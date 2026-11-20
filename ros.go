package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Ros 是 RouterOS REST 的极简客户端(HTTPS + Basic Auth)。
type Ros struct {
	Base string
	User string
	Pass string
	HC   *http.Client
}

func NewRos(base, user, pass string) *Ros {
	return &Ros{
		Base: strings.TrimRight(base, "/"),
		User: user,
		Pass: pass,
		HC: &http.Client{
			Timeout: 12 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConnsPerHost: 4,
			},
		},
	}
}

func (r *Ros) do(method, path string, body any) ([]byte, int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, r.Base+path, rd)
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(r.User, r.Pass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.HC.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return out, resp.StatusCode, fmt.Errorf("ROS %s %s -> %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return out, resp.StatusCode, nil
}

func (r *Ros) Get(path string) ([]byte, error) {
	b, _, err := r.do("GET", path, nil)
	return b, err
}

// MangleRule 只取我们关心的字段。
type MangleRule struct {
	ID         string `json:".id"`
	Chain      string `json:"chain"`
	SrcAddress string `json:"src-address"`
	DstAddress string `json:"dst-address"`
	Action     string `json:"action"`
	Mark       string `json:"new-routing-mark"`
	Disabled   string `json:"disabled"`
	Comment    string `json:"comment"`
	Packets    string `json:"packets"`
}

// FindPinRule 按注释里的标记查找本机钉线规则。
func (r *Ros) FindPinRule(ip string) (*MangleRule, error) {
	b, err := r.Get("/rest/ip/firewall/mangle")
	if err != nil {
		return nil, err
	}
	var all []MangleRule
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	// ★ 只认「钉线」规则: 必须带 new-routing-mark。
	//   同一台机器上还有一条【分流】01 WANLAB 直连豁免(action=return, 无 routing-mark),
	//   以前这里只按 comment~WANLAB + src 匹配, 会先命中那条豁免规则,
	//   结果面板 enable/disable 的是豁免规则, 真正的钉线规则一直生效
	//   —— 表现为「面板显示 off / 实测出口却钉在某条线上」。
	var hit *MangleRule
	for i := range all {
		if !strings.Contains(all[i].Comment, "WANLAB") || all[i].SrcAddress != ip {
			continue
		}
		if strings.TrimSpace(all[i].Mark) == "" {
			continue // 豁免类规则, 跳过
		}
		if hit == nil {
			hit = &all[i]
		}
	}
	return hit, nil
}

func (r *Ros) CreatePinRule(ip, mark string, disabled bool) (*MangleRule, error) {
	body := map[string]any{
		"chain":            "prerouting",
		"action":           "mark-routing",
		"src-address":      ip,
		// 排除局域网目标: 访问 ROS/其它内网服务不能被改路由
		"dst-address":      "!" + lanCIDR(),
		"new-routing-mark": mark,
		"passthrough":      "no",
		"comment":          "WANLAB 出口钉线: 由测速面板(wanlab)自动维护, 勿手改",
	}
	if disabled {
		body["disabled"] = "yes"
	}
	b, _, err := r.do("PUT", "/rest/ip/firewall/mangle", body)
	if err != nil {
		return nil, err
	}
	var m MangleRule
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (r *Ros) PatchPinRule(id string, fields map[string]any) error {
	_, _, err := r.do("PATCH", "/rest/ip/firewall/mangle/"+id, fields)
	return err
}

// Lines 返回各条 PPPoE 线路的在线状态(线路定义来自配置 lines)。
type LineState struct {
	Name    string `json:"name"`
	Wan     string `json:"wan"` // 出口序号 "1"/"2"/"3"(按配置 lines 的顺序)
	Label   string `json:"label"`
	Running bool   `json:"running"`
	Address string `json:"address"`
}

func (r *Ros) Lines() ([]LineState, error) {
	b, err := r.Get("/rest/interface")
	if err != nil {
		return nil, err
	}
	var all []map[string]any
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	byIface := map[string]LineState{}
	for i, l := range lineDefs() {
		byIface[l.PPPoEiface] = LineState{Name: l.PPPoEiface, Wan: strconv.Itoa(i + 1), Label: l.Label + " " + l.ID}
	}
	var out []LineState
	for _, it := range all {
		name, _ := it["name"].(string)
		if st, ok := byIface[name]; ok {
			run, _ := it["running"].(string)
			st.Running = run == "true"
			out = append(out, st)
		}
	}
	// 取 PPPoE 上拿到的地址(部分线路是 CGNAT 100.x)
	b2, err2 := r.Get("/rest/ip/address")
	if err2 == nil {
		var adds []map[string]any
		if json.Unmarshal(b2, &adds) == nil {
			for i := range out {
				for _, a := range adds {
					if a["interface"] == out[i].Name {
						out[i].Address, _ = a["address"].(string)
					}
				}
			}
		}
	}
	return out, nil
}

// rosVerCache: ROS 版本号只随 ROS 升级变化, 缓存 10 分钟,
// 省掉状态轮询(每 30s/标签页)里一个无谓的 REST 往返。
var rosVerCache struct {
	sync.Mutex
	val string
	at  time.Time
}

// RosVersion 用于状态页展示。
func (r *Ros) RosVersion() string {
	rosVerCache.Lock()
	defer rosVerCache.Unlock()
	if rosVerCache.val != "" && time.Since(rosVerCache.at) < 10*time.Minute {
		return rosVerCache.val
	}
	b, err := r.Get("/rest/system/resource")
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	v, _ := m["version"].(string)
	if v != "" {
		rosVerCache.val, rosVerCache.at = v, time.Now()
	}
	return v
}

// LocalIP 返回本机在 eth0 上的 IPv4(钉线规则要用它做 src-address)。
func LocalIP() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifs {
		if ifc.Name != "eth0" {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				return ipn.IP.String()
			}
		}
	}
	return ""
}
