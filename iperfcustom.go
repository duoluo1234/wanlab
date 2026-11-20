package main

// 自定义 iperf3 —— 目标地址/端口/钉线都由用户现填, 不依赖 config.json 里的机队,
// 也不需要 SSH 到对端拉服务端(对端自己跑好 iperf3 -s 即可)。
//
// 钉线的语义: **本次测试期间**把面板切到指定线路, 测完自动恢复原出口。
// 这样既能测任意一条线的真实线速, 又不会把面板留在被改过的状态上。
// 结果里带 exit_ip(Cloudflare trace 实测出口), 用来证明钉线真的生效, 而不是只信规则。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	customMu   sync.Mutex // 钉线是全局状态, 同一时刻只允许一个自定义 iperf3
	customBusy bool
)

type IperfCustomResult struct {
	Host     string  `json:"host"`
	TargetIP string  `json:"target_ip,omitempty"`
	Port     int     `json:"port"`
	Dir      string  `json:"dir"`
	Mbps     float64 `json:"mbps"`
	Retrans  int     `json:"retrans"`
	Seconds  float64 `json:"seconds"`
	Streams  int     `json:"streams"`
	Family   int     `json:"family"`
	Wan      string  `json:"wan"`
	WanLabel string  `json:"wan_label"`
	ExitIP   string  `json:"exit_ip,omitempty"`
	ExitLoc  string  `json:"exit_loc,omitempty"`
	PrevExit string  `json:"prev_exit"`
	Restored bool    `json:"restored"`
	RawError string  `json:"raw_error,omitempty"`
}

// cleanHost 去掉方括号/空白, 并挡掉会被 iperf3 当成选项或破坏参数的形式。
func cleanHost(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	if s == "" {
		return "", fmt.Errorf("目标地址不能为空")
	}
	if strings.HasPrefix(s, "-") {
		return "", fmt.Errorf("目标地址不能以 - 开头")
	}
	if len(s) > 253 {
		return "", fmt.Errorf("目标地址过长")
	}
	for _, r := range s {
		ok := r == '.' || r == ':' || r == '-' || r == '_' ||
			(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !ok {
			return "", fmt.Errorf("目标地址含非法字符 %q", r)
		}
	}
	return s, nil
}

// hostFam 判断地址族: 字面量看冒号, 域名按默认 v4 处理(解析后再校正)。
func hostFam(host string) int {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return 4
		}
		return 6
	}
	if strings.Contains(host, ":") {
		return 6
	}
	return 4
}

// pppIface 线路号 → ROS 上的 PPPoE 接口名(取配置 lines 的 pppoe_iface)。
func pppIface(wan string) string {
	idx := -1
	switch wan {
	case "1", "v6":
		idx = 0
	case "2", "v6u":
		idx = 1
	case "3":
		idx = 2
	}
	if l, ok := lineByIdx(idx); ok {
		return l.PPPoEiface
	}
	return ""
}

// pppV4Exit 读 ROS 上该线路 PPPoE 的 IPv4 地址, 作为出口的兜底
// (Cloudflare trace 偶尔超时, 有它就不会出现「出口 --」)。
func pppV4Exit(wan string) string {
	iface := pppIface(wan)
	if iface == "" {
		return ""
	}
	b, err := ros.Get("/rest/ip/address")
	if err != nil {
		return ""
	}
	var all []struct {
		Address   string `json:"address"`
		Interface string `json:"interface"`
		Disabled  string `json:"disabled"`
	}
	if json.Unmarshal(b, &all) != nil {
		return ""
	}
	for _, a := range all {
		if a.Interface == iface && a.Disabled != "true" && !strings.HasPrefix(a.Address, "192.168.") {
			return strings.SplitN(a.Address, "/", 2)[0]
		}
	}
	return ""
}

// pppV6Exit 读 ROS 上该线路 PPPoE 接口的 IPv6 地址。
// 内网设备出 v6 走 NAT66(ULA→PPP 地址), 所以这个地址就是**真正对外的源**,
// 拿它验证 v6 钉线比查本机 ULA 有意义得多(ULA 两条线都一样)。
func pppV6Exit(line string) string {
	iface := "pppoe-mobile"
	if line == "v6u" {
		iface = "pppoe-unicom"
	}
	b, err := ros.Get("/rest/ipv6/address")
	if err != nil {
		return ""
	}
	var all []struct {
		Address   string `json:"address"`
		Interface string `json:"interface"`
		Disabled  string `json:"disabled"`
	}
	if json.Unmarshal(b, &all) != nil {
		return ""
	}
	for _, a := range all {
		if a.Interface != iface || a.Disabled == "true" {
			continue
		}
		ip := strings.SplitN(a.Address, "/", 2)[0]
		if ip != "" && !strings.HasPrefix(strings.ToLower(ip), "fe80") {
			return ip
		}
	}
	return ""
}

func handleIperfCustom(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Dir     string `json:"dir"`
		Secs    int    `json:"secs"`
		Streams int    `json:"streams"`
		Wan     string `json:"wan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求体不是合法 JSON"})
		return
	}
	host, err := cleanHost(body.Host)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if body.Port == 0 {
		body.Port = 5201
	}
	if body.Port < 1 || body.Port > 65535 {
		writeJSON(w, 400, map[string]string{"error": "端口必须在 1-65535"})
		return
	}
	if body.Secs <= 0 {
		body.Secs = 10
	}
	if body.Secs > 120 {
		body.Secs = 120
	}
	if body.Streams <= 0 {
		body.Streams = 4
	}
	if body.Streams > 32 {
		body.Streams = 32
	}
	if body.Dir != "up" {
		body.Dir = "down"
	}
	switch body.Wan {
	case "", "off", "1", "2", "3", "v6", "v6u":
	default:
		writeJSON(w, 400, map[string]string{"error": "钉线取值非法: " + body.Wan})
		return
	}
	if body.Wan == "" {
		body.Wan = "off"
	}

	customMu.Lock()
	if customBusy {
		customMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "已有自定义 iperf3 在跑, 等它结束"})
		return
	}
	customBusy = true
	customMu.Unlock()
	defer func() {
		customMu.Lock()
		customBusy = false
		customMu.Unlock()
	}()
	if !tryExitGate("自定义 iperf") {
		holder, _ := exitGateBusy()
		writeJSON(w, 409, map[string]string{"error": holder + " 正在用线, 等它结束"})
		return
	}
	defer releaseExitGate()

	ctx := r.Context()
	res := IperfCustomResult{
		Host: host, Port: body.Port, Dir: body.Dir,
		Seconds: float64(body.Secs), Streams: body.Streams,
		Wan: body.Wan, WanLabel: exitLabel(body.Wan), PrevExit: getExit(),
	}

	// 解析目标: 字面量直接用; 域名先 DoH 拿真 IP(顺带定地址族), 失败就交给 iperf3 自己解析
	fam := hostFam(host)
	target := host
	if net.ParseIP(host) == nil {
		if ip, _ := resolveTarget(ctx, host, "doh.pub", fam); ip != "" {
			target = ip
			res.TargetIP = ip
			fam = hostFam(ip)
		}
	} else {
		res.TargetIP = host
	}
	res.Family = fam

	// v6 钉线只对 v6 目标有意义; 反过来 v4 目标也吃不到 v6 钉线
	if (body.Wan == "v6" || body.Wan == "v6u") && fam == 4 {
		writeJSON(w, 400, map[string]string{"error": "目标是 IPv4, 钉 v6 线不生效; 请换成 v6 地址或改用 1/2/3"})
		return
	}
	if fam == 6 && (body.Wan == "1" || body.Wan == "2" || body.Wan == "3") {
		writeJSON(w, 400, map[string]string{"error": "目标是 IPv6, v4 钉线规则不生效; 请改用 v6 / v6u"})
		return
	}

	// 钉线: 切到目标线路, 测完恢复
	prev := res.PrevExit
	pinned := body.Wan != prev
	if pinned {
		if err := setExit(body.Wan); err != nil {
			res.RawError = "钉线失败: " + err.Error()
			writeJSON(w, 200, res)
			return
		}
		// 等路由/conntrack 生效再起流, 否则前几百毫秒还走旧线
		time.Sleep(1200 * time.Millisecond)
	}

	// runOnce: 实测出口 + 压测 + 解析结果, 全部写进 res
	runOnce := func() {
		// 实测出口, 用来证明钉线生效(而不是只看规则)
		if fam == 6 {
			// v6 走 NAT66: 对外源是 PPP 地址, 本机 ULA 两条线一样, 拿它验证没意义。
			// (直接的 v6 trace 会被 ROS 送去旁路由代答, 测出来是代理节点地址)
			if ip := pppV6Exit(body.Wan); ip != "" {
				res.ExitIP = ip
				res.ExitLoc = "NAT66 " + res.WanLabel
			} else if info := ExitInfoOf(ctx, 6); info.IP != "" {
				res.ExitIP = info.IP
				res.ExitLoc = "本机 ULA"
			}
		} else {
			// trace 偶发超时, 给一次重试; 仍失败就用 ROS 上该线路的 PPP 地址兜底
			for i := 0; i < 2 && res.ExitIP == ""; i++ {
				if info := ExitInfoOf(ctx, fam); info.IP != "" {
					res.ExitIP = info.IP
					res.ExitLoc = strings.TrimSpace(info.Colo + " " + info.Loc)
				}
			}
			if res.ExitIP == "" {
				if ip := pppV4Exit(body.Wan); ip != "" {
					res.ExitIP = ip
					res.ExitLoc = "ROS " + strings.TrimSpace(res.WanLabel) + " PPP"
				}
			}
		}

		args := []string{
			"-c", target, "-p", strconv.Itoa(body.Port),
			"-t", strconv.Itoa(body.Secs), "-P", strconv.Itoa(body.Streams),
			"-J", "--connect-timeout", "5000", "-i", "0",
		}
		if fam == 6 {
			args = append(args, "-6")
		} else {
			args = append(args, "-4")
		}
		if body.Dir == "down" {
			args = append(args, "-R")
		}

		cctx, cancel := context.WithTimeout(ctx, time.Duration(body.Secs+30)*time.Second)
		defer cancel()
		out, err := runCmd(cctx, "iperf3", args...)
		if err != nil && strings.TrimSpace(out) == "" {
			res.RawError = err.Error()
			return
		}

		var j struct {
			Error string `json:"error"`
			End   struct {
				SumSent struct {
					BitsPerSecond float64 `json:"bits_per_second"`
					Retransmits   int     `json:"retransmits"`
				} `json:"sum_sent"`
				SumReceived struct {
					BitsPerSecond float64 `json:"bits_per_second"`
					Retransmits   int     `json:"retransmits"`
				} `json:"sum_received"`
			} `json:"end"`
		}
		if e := json.Unmarshal([]byte(out), &j); e != nil {
			res.RawError = strings.TrimSpace(out)
			if len(res.RawError) > 400 {
				res.RawError = res.RawError[:400]
			}
			return
		}
		if j.Error != "" {
			res.RawError = j.Error
			return
		}
		if body.Dir == "down" {
			res.Mbps = j.End.SumReceived.BitsPerSecond / 1e6
			res.Retrans = j.End.SumReceived.Retransmits
		} else {
			res.Mbps = j.End.SumSent.BitsPerSecond / 1e6
			res.Retrans = j.End.SumSent.Retransmits
		}
	}
	runOnce()

	// 还原必须在 writeJSON 之前 —— defer 里改 res 不会进已序列化的响应体
	if pinned {
		if err := setExit(prev); err == nil {
			res.Restored = true
		} else {
			res.RawError = strings.TrimSpace(res.RawError + " | 还原出口失败: " + err.Error())
		}
	}
	writeJSON(w, 200, res)
}
