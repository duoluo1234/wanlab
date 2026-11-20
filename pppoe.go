package main

// 线路拨号页签: 三条 PPPoE 线路的状态 (IP / 网关) 与重新拨号 (ROS 联动)。
// 状态: pppoe-client 给运行/禁用, /ip/address 给本端 IP (address) 与对端网关 (network)。
// 重拨 = 对 pppoe-client 先 PATCH disabled=true 再 false, 然后轮询地址出现为止 (单线最长 90 秒)。
// 重拨期间该线流量中断, 故整段任务过切线独占闸 (名「三线重拨」), 与体检/聚合等长任务互斥;
// 过程逐步记日志, 前端轮询 /api/pppoe/redial 看进度与每线的新旧 IP 对照。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type PppoeLine struct {
	Wan      string `json:"wan"`   // wan1 | wan2 | wan3
	Label    string `json:"label"` // 配置 lines 里的显示标签
	Iface    string `json:"iface"` // 配置 lines 里的 pppoe_iface
	Ether    string `json:"ether"` // ether1 ...
	ID       string `json:"id"`    // ROS .id
	Disabled bool   `json:"disabled"`
	Running  bool   `json:"running"`
	IP       string `json:"ip"`      // 本端地址, 未连接为空
	Gateway  string `json:"gateway"` // 对端地址 (network), 未连接为空
	Uptime   string `json:"uptime"`  // 当前会话连接时长 (ROS monitor), 如 7h57m43s
}

type pppoeDef struct{ Wan, Label, Iface string }

// pppoeDefs 由配置 lines 派生(无配置时为通用默认, 见 lineDefs)。
func pppoeDefs() []pppoeDef {
	defs := lineDefs()
	out := make([]pppoeDef, len(defs))
	for i, l := range defs {
		out[i] = pppoeDef{Wan: l.ID, Label: l.Label, Iface: l.PPPoEiface}
	}
	return out
}

type rosPppoeRaw struct {
	ID        string `json:".id"`
	Name      string `json:"name"`
	Interface string `json:"interface"`
	Disabled  string `json:"disabled"`
	Running   string `json:"running"`
}

type rosAddrRaw struct {
	Address   string `json:"address"`
	Network   string `json:"network"`
	Interface string `json:"interface"`
	Disabled  string `json:"disabled"`
	Invalid   string `json:"invalid"`
}

func pppoeStatus() ([]PppoeLine, error) {
	b, err := ros.Get("/rest/interface/pppoe-client")
	if err != nil {
		return nil, err
	}
	var clients []rosPppoeRaw
	if err := json.Unmarshal(b, &clients); err != nil {
		return nil, err
	}
	byName := map[string]rosPppoeRaw{}
	for _, c := range clients {
		byName[c.Name] = c
	}
	b, err = ros.Get("/rest/ip/address")
	if err != nil {
		return nil, err
	}
	var addrs []rosAddrRaw
	if err := json.Unmarshal(b, &addrs); err != nil {
		return nil, err
	}
	addrByIface := map[string]rosAddrRaw{}
	for _, a := range addrs {
		if a.Disabled == "true" || a.Invalid == "true" {
			continue
		}
		if !strings.Contains(a.Address, ".") { // 只要 IPv4
			continue
		}
		if _, ok := addrByIface[a.Interface]; !ok {
			addrByIface[a.Interface] = a
		}
	}
	out := []PppoeLine{}
	for _, d := range pppoeDefs() {
		l := PppoeLine{Wan: d.Wan, Label: d.Label, Iface: d.Iface}
		if c, ok := byName[d.Iface]; ok {
			l.ID = c.ID
			l.Ether = c.Interface
			l.Disabled = c.Disabled == "true"
			l.Running = c.Running == "true"
		}
		if a, ok := addrByIface[d.Iface]; ok {
			l.IP = strings.SplitN(a.Address, "/", 2)[0]
			l.Gateway = a.Network
		}
		out = append(out, l)
	}
	for i := range out {
		if out[i].ID == "" {
			continue
		}
		mb, _, err := ros.do("POST", "/rest/interface/pppoe-client/monitor",
			map[string]any{"numbers": out[i].ID, "once": "true"})
		if err != nil {
			continue
		}
		var mons []struct {
			Uptime string `json:"uptime"`
		}
		if json.Unmarshal(mb, &mons) == nil && len(mons) > 0 {
			out[i].Uptime = mons[0].Uptime
		}
	}
	return out, nil
}

func handlePppoe(w http.ResponseWriter, r *http.Request) {
	lines, err := pppoeStatus()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "读 ROS 线路状态失败: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"lines": lines})
}

// ---- 重拨任务 (异步, 单实例) ----

type PppoeRedialResult struct {
	Wan     string  `json:"wan"`
	Label   string  `json:"label"`
	OldIP   string  `json:"old_ip"`
	NewIP   string  `json:"new_ip"`
	Gateway string  `json:"gateway"`
	OK      bool    `json:"ok"`
	Err     string  `json:"err,omitempty"`
	Secs    float64 `json:"secs"`
}

type pppoeJob struct {
	Running   bool                `json:"running"`
	StartedAt string              `json:"started_at"`
	Log       []string            `json:"log"`
	Results   []PppoeRedialResult `json:"results"`
}

var pppoeMu sync.Mutex
var pppoeCur = pppoeJob{Log: []string{}, Results: []PppoeRedialResult{}}

func pppoeLogf(format string, args ...any) {
	pppoeMu.Lock()
	pppoeCur.Log = append(pppoeCur.Log, fmt.Sprintf(format, args...))
	pppoeMu.Unlock()
}

func pppoeSnapshot() pppoeJob {
	pppoeMu.Lock()
	defer pppoeMu.Unlock()
	cp := pppoeCur
	cp.Log = append([]string{}, pppoeCur.Log...)
	cp.Results = append([]PppoeRedialResult{}, pppoeCur.Results...)
	return cp
}

func handlePppoeRedial(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, pppoeSnapshot())
}

type pppoeRedialReq struct {
	Line string `json:"line"` // wan1 | wan2 | wan3 | all
}

func handlePppoeRedialStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var q pppoeRedialReq
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	defs := pppoeDefs()
	var targets []int
	if q.Line == "all" {
		for i := range defs {
			targets = append(targets, i)
		}
	} else {
		for i, d := range defs {
			if d.Wan == q.Line {
				targets = []int{i}
				break
			}
		}
	}
	if len(targets) == 0 {
		ids := make([]string, len(defs))
		for i, d := range defs {
			ids[i] = d.Wan
		}
		writeJSON(w, 400, map[string]string{"error": "line 必须是 " + strings.Join(ids, "/") + "/all"})
		return
	}
	if !tryExitGate("三线重拨") {
		holder, _ := exitGateBusy()
		writeJSON(w, 409, map[string]string{"error": holder + " 正在用线, 等它结束再重拨"})
		return
	}
	pppoeMu.Lock()
	if pppoeCur.Running {
		pppoeMu.Unlock()
		releaseExitGate()
		writeJSON(w, 409, map[string]string{"error": "重拨正在进行中"})
		return
	}
	pppoeCur = pppoeJob{Running: true, StartedAt: time.Now().Format("2006-01-02 15:04:05"),
		Log: []string{}, Results: []PppoeRedialResult{}}
	pppoeMu.Unlock()
	go runPppoeRedial(targets)
	writeJSON(w, 200, map[string]any{"started": true})
}

func runPppoeRedial(targets []int) {
	defer releaseExitGate()
	defer func() {
		pppoeMu.Lock()
		pppoeCur.Running = false
		pppoeMu.Unlock()
	}()
	for _, ti := range targets {
		d := pppoeDefs()[ti]
		res := PppoeRedialResult{Wan: d.Wan, Label: d.Label}
		t0 := time.Now()
		lines, err := pppoeStatus()
		if err != nil {
			res.Err = "读状态失败: " + err.Error()
			pppoeLogf("%s %s: %s", d.Wan, d.Label, res.Err)
			pppoeMu.Lock()
			pppoeCur.Results = append(pppoeCur.Results, res)
			pppoeMu.Unlock()
			continue
		}
		var cur *PppoeLine
		for i := range lines {
			if lines[i].Wan == d.Wan {
				cur = &lines[i]
			}
		}
		if cur == nil || cur.ID == "" {
			res.Err = "在 ROS 上找不到 " + d.Iface
			pppoeLogf("%s %s: %s", d.Wan, d.Label, res.Err)
			pppoeMu.Lock()
			pppoeCur.Results = append(pppoeCur.Results, res)
			pppoeMu.Unlock()
			continue
		}
		res.OldIP = cur.IP
		pppoeLogf("%s %s (%s): 现 IP %s / 网关 %s, 断开重拨…", d.Wan, d.Label, d.Iface, dash(cur.IP), dash(cur.Gateway))
		path := "/rest/interface/pppoe-client/" + cur.ID
		if _, _, err := ros.do("PATCH", path, map[string]any{"disabled": true}); err != nil {
			res.Err = "禁用失败: " + err.Error()
			pppoeLogf("%s %s: %s", d.Wan, d.Label, res.Err)
			pppoeMu.Lock()
			pppoeCur.Results = append(pppoeCur.Results, res)
			pppoeMu.Unlock()
			continue
		}
		time.Sleep(2 * time.Second)
		if _, _, err := ros.do("PATCH", path, map[string]any{"disabled": false}); err != nil {
			res.Err = "重新启用失败: " + err.Error()
			pppoeLogf("%s %s: %s", d.Wan, d.Label, res.Err)
			pppoeMu.Lock()
			pppoeCur.Results = append(pppoeCur.Results, res)
			pppoeMu.Unlock()
			continue
		}
		pppoeLogf("%s %s: 已重新启用, 等待拨号…", d.Wan, d.Label)
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(2 * time.Second)
			ls, err := pppoeStatus()
			if err != nil {
				continue
			}
			for _, l := range ls {
				if l.Wan == d.Wan && l.Running && l.IP != "" {
					res.NewIP = l.IP
					res.Gateway = l.Gateway
					res.OK = true
				}
			}
			if res.OK {
				break
			}
		}
		res.Secs = time.Since(t0).Seconds()
		if res.OK {
			pppoeLogf("%s %s: ✓ 已恢复, 新 IP %s / 网关 %s (用时 %.0f 秒)", d.Wan, d.Label, res.NewIP, res.Gateway, res.Secs)
		} else {
			res.Err = "90 秒内未恢复连接"
			pppoeLogf("%s %s: ✗ %s", d.Wan, d.Label, res.Err)
		}
		pppoeMu.Lock()
		pppoeCur.Results = append(pppoeCur.Results, res)
		pppoeMu.Unlock()
	}
	pppoeLogf("重拨任务结束")
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
