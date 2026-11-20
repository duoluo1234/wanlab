package main

// 机队体检(三线矩阵版): 按出口分组逐台测 fleet 节点网络质量 ——
// v4 节点 × 三线(wan1/wan2/wan3), v6 节点 × 双线(第一/第二线 IPv6 直连)。
// 每组先 setExit 钉线再逐台测: ping 延迟/抖动/丢包、iperf3 TCP 上下行、UDP 丢包/抖动;
// 全部测完恢复体检前的出口。复用 exec.go 的 Ping / IperfPrepare / IperfRun / IperfStop。
// 结果持久化到 /etc/wanlab/fleetcheck-last.json。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FleetCheckResult struct {
	Key         string  `json:"key"`
	Label       string  `json:"label"`
	IP          string  `json:"ip"`
	Line        string  `json:"line"`       // 1|2|3|v6|v6u
	LineLabel   string  `json:"line_label"` // 线路显示名(由后端 exitLabel 按配置标签生成)
	Status      string  `json:"status"`     // ok | down
	PingAvgMs   float64 `json:"ping_avg_ms"`
	PingJitter  float64 `json:"ping_jitter_ms"`
	PingLossPct float64 `json:"ping_loss_pct"`
	DownMbps    float64 `json:"down_mbps"`
	DownRetrans int     `json:"down_retrans"`
	UpMbps      float64 `json:"up_mbps"`
	UpRetrans   int     `json:"up_retrans"`
	UDPUpLoss   float64 `json:"udp_up_loss_pct"`
	UDPUpJitter float64 `json:"udp_up_jitter_ms"`
	UDPDownLoss float64 `json:"udp_down_loss_pct"`
	UDPDownJit  float64 `json:"udp_down_jitter_ms"`
	Error       string  `json:"error,omitempty"`
}

type fleetJob struct {
	Running    bool               `json:"running"`
	StartedAt  string             `json:"started_at,omitempty"`
	FinishedAt string             `json:"finished_at,omitempty"`
	Log        []string           `json:"log"`
	Results    []FleetCheckResult `json:"results"`
}

const fleetCheckFile = "/etc/wanlab/fleetcheck-last.json"

var (
	fleetMu     sync.Mutex
	fleetCur    = fleetJob{Log: []string{}, Results: []FleetCheckResult{}}
	fleetCancel context.CancelFunc
	fleetLoaded bool
)

func fleetLogf(format string, a ...any) {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	fleetCur.Log = append(fleetCur.Log, time.Now().Format("15:04:05")+" "+fmt.Sprintf(format, a...))
}

func fleetSnapshot() fleetJob {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	out := fleetCur
	out.Log = append([]string{}, fleetCur.Log...)
	out.Results = append([]FleetCheckResult{}, fleetCur.Results...)
	return out
}

func loadFleetLast() {
	fleetMu.Lock()
	defer fleetMu.Unlock()
	// 只在全新进程、还没跑过任何一轮时加载上次结果;已开跑/已有结果绝不覆盖,
	// 否则上一轮的结果会混进正在跑的这一轮(实测踩过)。
	if fleetLoaded || fleetCur.Running || len(fleetCur.Results) > 0 {
		fleetLoaded = true
		return
	}
	fleetLoaded = true
	b, err := os.ReadFile(fleetCheckFile)
	if err != nil {
		return
	}
	var saved fleetJob
	if json.Unmarshal(b, &saved) == nil && len(saved.Results) > 0 {
		fleetCur.Results = saved.Results
		fleetCur.FinishedAt = saved.FinishedAt
	}
}

func saveFleetLast(job fleetJob) {
	b, err := json.Marshal(job)
	if err == nil {
		os.WriteFile(fleetCheckFile, b, 0644)
	}
}

// reprepare 重启节点上的 iperf3 服务端: iperf3 单实例服务端跑完一测有残留状态,
// 紧接着的下一测会报 "server is busy" 或被 RST;每段开测前重拉一个干净实例。
func reprepare(ctx context.Context, node Node) {
	IperfPrepare(ctx, node)
	time.Sleep(300 * time.Millisecond)
}

// udpIperf 跑一次 UDP iperf3(dir=up: 本机->节点; down: 节点->本机), 回丢包% 与抖动 ms。
func udpIperf(ctx context.Context, node Node, dir string) (float64, float64, error) {
	const secs = 3
	args := []string{"-c", node.IP, "-p", "5201", ipFamFlag(node.IP), "-u", "-b", "50M",
		"-t", strconv.Itoa(secs), "-J", "--connect-timeout", "5000", "-i", "0"}
	if dir == "down" {
		args = append(args, "-R")
	}
	cctx, cancel := context.WithTimeout(ctx, (secs+12)*time.Second)
	defer cancel()
	out, err := runCmd(cctx, "iperf3", args...)
	if err != nil && out == "" {
		return 0, 0, err
	}
	var j struct {
		Error string `json:"error"`
		End   struct {
			Sum struct {
				JitterMs    float64 `json:"jitter_ms"`
				LostPackets int     `json:"lost_packets"`
				Packets     int     `json:"packets"`
				LostPercent float64 `json:"lost_percent"`
			} `json:"sum"`
			SumReceived struct {
				JitterMs    float64 `json:"jitter_ms"`
				LostPackets int     `json:"lost_packets"`
				Packets     int     `json:"packets"`
				LostPercent float64 `json:"lost_percent"`
			} `json:"sum_received"`
		} `json:"end"`
	}
	if e := json.Unmarshal([]byte(out), &j); e != nil {
		return 0, 0, fmt.Errorf("UDP 输出解析失败")
	}
	if j.Error != "" {
		return 0, 0, fmt.Errorf("%s", j.Error)
	}
	if j.End.Sum.Packets > 0 {
		return j.End.Sum.LostPercent, j.End.Sum.JitterMs, nil
	}
	if j.End.SumReceived.Packets > 0 {
		return j.End.SumReceived.LostPercent, j.End.SumReceived.JitterMs, nil
	}
	return 0, 0, fmt.Errorf("UDP 无统计数据")
}

// checkOneNode 在当前已钉好的出口下测一台节点。
func checkOneNode(ctx context.Context, node Node, line, lineLabel string) FleetCheckResult {
	res := FleetCheckResult{Key: node.Key, Label: node.Label, IP: node.IP,
		Line: line, LineLabel: lineLabel, Status: "down"}
	fleetLogf("== [%s] %s (%s)", lineLabel, node.Label, node.IP)

	fam := 4
	if strings.Contains(node.IP, ":") {
		fam = 6
	}
	if sm, _, err := Ping(ctx, node.IP, 10, 200, fam); err == nil {
		res.PingAvgMs = sm.Avg
		res.PingJitter = sm.Jitter
		res.PingLossPct = sm.LossPct
		fleetLogf("  ping: 平均 %.1fms 抖动 %.1fms 丢包 %.0f%% (%d/%d)", sm.Avg, sm.Jitter, sm.LossPct, sm.Recv, sm.Sent)
	} else {
		fleetLogf("  ping 失败: %v", err)
	}

	prep, perr := IperfPrepare(ctx, node)
	if perr != nil || !strings.Contains(prep, "IPERF_UP") {
		res.Error = "iperf3 服务端未就绪"
		fleetLogf("  iperf3 服务端未就绪, 跳过速率测试")
		return res
	}
	res.Status = "ok"

	down := IperfRun(ctx, node, "down", 5, 4)
	res.DownMbps, res.DownRetrans = down.Mbps, down.Retrans
	if down.RawError != "" {
		fleetLogf("  下行失败: %s", down.RawError)
	} else {
		fleetLogf("  下行 %.0f Mbps (重传 %d)", down.Mbps, down.Retrans)
	}
	reprepare(ctx, node)
	up := IperfRun(ctx, node, "up", 5, 4)
	res.UpMbps, res.UpRetrans = up.Mbps, up.Retrans
	if up.RawError != "" {
		fleetLogf("  上行失败: %s", up.RawError)
	} else {
		fleetLogf("  上行 %.0f Mbps (重传 %d)", up.Mbps, up.Retrans)
	}

	reprepare(ctx, node)
	if loss, jit, err := udpIperf(ctx, node, "up"); err == nil {
		res.UDPUpLoss, res.UDPUpJitter = loss, jit
		fleetLogf("  UDP 上行: 丢包 %.2f%% 抖动 %.2fms", loss, jit)
	} else {
		fleetLogf("  UDP 上行失败: %v", err)
	}
	reprepare(ctx, node)
	if loss, jit, err := udpIperf(ctx, node, "down"); err == nil {
		res.UDPDownLoss, res.UDPDownJit = loss, jit
		fleetLogf("  UDP 下行: 丢包 %.2f%% 抖动 %.2fms", loss, jit)
	} else {
		fleetLogf("  UDP 下行失败: %v", err)
	}

	IperfStop(ctx, node)
	return res
}

func runFleetCheck(ctx context.Context) {
	defer releaseExitGate()
	prev := getExit()
	fleetLogf("机队体检开始(三线矩阵): 体检前出口=%s, 测完恢复", exitLabel(prev))
	defer func() {
		if err := setExit(prev); err != nil {
			fleetLogf("恢复出口失败: %v (当前可在面板手动切回 %s)", err, exitLabel(prev))
		} else {
			fleetLogf("出口已恢复: %s", exitLabel(prev))
		}
	}()

	var v4Nodes, v6Nodes []Node
	for _, n := range cfg.Nodes {
		if strings.Contains(n.IP, ":") {
			v6Nodes = append(v6Nodes, n)
		} else {
			v4Nodes = append(v4Nodes, n)
		}
	}
	groups := []struct {
		line  string
		nodes []Node
	}{
		{"1", v4Nodes},
		{"2", v4Nodes},
		{"3", v4Nodes},
		{"v6", v6Nodes},
		{"v6u", v6Nodes},
	}
	for _, g := range groups {
		if ctx.Err() != nil {
			fleetLogf("机队体检已被手动停止")
			goto finish
		}
		label := exitLabel(g.line)
		if len(g.nodes) == 0 {
			continue
		}
		if err := setExit(g.line); err != nil {
			fleetLogf("钉线到 %s 失败: %v, 跳过该线", label, err)
			continue
		}
		fleetLogf("---- 出口切换: %s (%d 台) ----", label, len(g.nodes))
		time.Sleep(1200 * time.Millisecond) // 等路由/conntrack 生效(与自定义 iperf 同)
		for _, node := range g.nodes {
			if ctx.Err() != nil {
				fleetLogf("机队体检已被手动停止")
				goto finish
			}
			res := checkOneNode(ctx, node, g.line, label)
			fleetMu.Lock()
			fleetCur.Results = append(fleetCur.Results, res)
			fleetMu.Unlock()
		}
	}

finish:
	fleetMu.Lock()
	fleetCur.Running = false
	fleetCur.FinishedAt = time.Now().Format("2006-01-02 15:04:05")
	done := fleetCur
	fleetMu.Unlock()
	saveFleetLast(done)
	fleetLogf("机队体检完成")
}

func handleFleetCheckStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	if !tryExitGate("机队体检") {
		holder, _ := exitGateBusy()
		writeJSON(w, 409, map[string]string{"error": holder + " 正在用线, 等它结束再体检"})
		return
	}
	fleetMu.Lock()
	if fleetCur.Running {
		fleetMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "体检正在进行中"})
		return
	}
	fleetLoaded = true
	fleetCur = fleetJob{Running: true, StartedAt: time.Now().Format("2006-01-02 15:04:05"),
		Log: []string{}, Results: []FleetCheckResult{}}
	ctx, cancel := context.WithCancel(context.Background())
	fleetCancel = cancel
	fleetMu.Unlock()
	go runFleetCheck(ctx)
	writeJSON(w, 200, map[string]any{"started": true})
}

func handleFleetCheckStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	fleetMu.Lock()
	cancel := fleetCancel
	running := fleetCur.Running
	fleetMu.Unlock()
	if !running || cancel == nil {
		writeJSON(w, 409, map[string]string{"error": "体检未在运行"})
		return
	}
	cancel()
	fleetLogf("已收到停止请求, 正在收尾(恢复出口)…")
	writeJSON(w, 200, map[string]any{"stopping": true})
}

func handleFleetCheck(w http.ResponseWriter, r *http.Request) {
	loadFleetLast()
	writeJSON(w, 200, fleetSnapshot())
}
