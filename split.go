package main

// 分流归属矩阵（参考 ip.skk.moe/split-tunnel 的思路，但按本网拓扑定制）：
// 并发访问一组「归属已知」的回显探测点，看每个探测点看到的来源 IP 属于哪条线/是否走了代理，
// 从而一眼看出「国内 → 直连某条线；国外 → 代理/某 VPS」的分流方向。
//
// 与 split-tunnel 的差别：它测的是浏览器里的流量（PAC/规则命中），我们测的是【整机出口】
// —— 也就是容器当前钉线 + ROS 分流规则共同作用后的真实结果，正好用来验证分流策略。

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// probeDef 一个探测点。Group 决定展示分组，Kind 决定解析方式。
type probeDef struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	URL   string `json:"url"`
	Kind  string `json:"kind"` // json | text | cipcc | ipip
}

// 探测点清单：按「目标归属」分组，正好覆盖本网三条线可区分的运营商。
// ★ 同一 URL 别在多个组重复（会得到相同结果，纯噪声）；IPv6 组必须用 v6-only 服务。
var splitProbes = []probeDef{
	{"国内 · 移动", "ipip.net", "https://myip.ipip.net", "ipip"},
	{"国内 · 移动", "3322.org", "http://ip.3322.net", "text"},
	{"国内 · 联通", "cip.cc", "https://www.cip.cc", "cipcc"},
	{"国内 · 联通", "myip.ipip.net#2", "https://myip.ipip.net/s", "ipip"},
	{"国外 · 通用", "ip.sb", "https://api.ip.sb/geoip", "json"},
	{"国外 · 通用", "ip-api", "http://ip-api.com/json/?fields=query,country,isp", "json"},
	{"国外 · 通用", "ipinfo.io", "https://ipinfo.io/json", "json"},
	{"国外 · 通用", "ifconfig.me", "https://ifconfig.me/ip", "text"},
	{"IPv6 直连", "ipv6.ip.sb", "https://api-ipv6.ip.sb/ip", "text"},
	{"IPv6 直连", "ipv6.icanhazip", "https://ipv6.icanhazip.com", "text"},
}

// SplitRow 一行结果。
type SplitRow struct {
	Group    string `json:"group"`
	Name     string `json:"name"`
	IP       string `json:"ip"`
	Family   string `json:"family"`   // v4 / v6
	ISP      string `json:"isp"`      // 归属运营商（ipip/cip.cc 给的，或 ip-api 查的）
	Region   string `json:"region"`   // 地区
	Line     string `json:"line"`     // 判定：移动/联通/9929/代理(节点名)/未知
	Kind     string `json:"kind"`     // direct / proxy
	Ms       int64  `json:"ms"`
	Error    string `json:"error,omitempty"`
	Raw      string `json:"raw,omitempty"` // 原始回显（截断）
}

var (
	reIPV4 = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)
	reIPV6 = regexp.MustCompile(`(?i)\b((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4})\b`)
)

// pickIP 从任意回显里抠出第一个像样的公网 IP（优先 v4）。
func pickIP(s string) (string, string) {
	for _, m := range reIPV4.FindAllString(s, -1) {
		parts := strings.Split(m, ".")
		bad := false
		for _, p := range parts {
			if len(p) > 3 || (len(p) > 1 && p[0] == '0') {
				bad = true
			}
		}
		if !bad && !strings.HasPrefix(m, "127.") && !strings.HasPrefix(m, "0.") {
			return m, "v4"
		}
	}
	for _, m := range reIPV6.FindAllString(s, -1) {
		if strings.Count(m, ":") >= 2 && !strings.HasPrefix(m, "::") {
			return m, "v6"
		}
	}
	return "", ""
}

// runProbe 跑单个探测点。
func runProbe(ctx context.Context, p probeDef) SplitRow {
	row := SplitRow{Group: p.Group, Name: p.Name}
	st := time.Now()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := runCmd(cctx, "curl", "-sL", "-m", "9", "--max-time", "9", "-A",
		"Mozilla/5.0 (compatible; wanlab-split/1.0)", p.URL)
	row.Ms = time.Since(st).Milliseconds()
	if err != nil && out == "" {
		row.Error = "请求失败"
		return row
	}
	row.Raw = truncate(strings.ReplaceAll(out, "\n", " "), 120)

	switch p.Kind {
	case "json":
		var m map[string]any
		if json.Unmarshal([]byte(out), &m) == nil {
			if v, ok := m["ip"].(string); ok {
				row.IP = v
			}
			if v, ok := m["query"].(string); ok && row.IP == "" {
				row.IP = v
			}
			// ip.cn: {"data":{"ip":"..","location":".."}}
			if d, ok := m["data"].(map[string]any); ok {
				if v, ok := d["ip"].(string); ok && row.IP == "" {
					row.IP = v
				}
				if v, ok := d["location"].(string); ok {
					row.ISP = v
				}
			}
			if v, ok := m["city"].(string); ok {
				row.Region = v
			}
			if v, ok := m["country"].(string); ok && row.Region == "" {
				row.Region = v
			}
			if v, ok := m["org"].(string); ok {
				row.ISP = v
			}
		}
	case "ipip":
		// 当前 IP：1.2.3.4  来自于：中国 上海 上海 移动
		if i := strings.Index(out, "来自于"); i > 0 {
			row.ISP = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out[i:]), "来自于："))
			row.Region = row.ISP
		}
	case "cipcc":
		for _, ln := range strings.Split(out, "\n") {
			ln = strings.ReplaceAll(ln, "\t", " ")
			if strings.HasPrefix(strings.TrimSpace(ln), "地址") || strings.Contains(ln, "地址 :") {
				row.Region = strings.TrimSpace(strings.SplitN(ln, ":", 2)[len(strings.SplitN(ln, ":", 2))-1])
			}
			if strings.Contains(ln, "运营商") && strings.Contains(ln, ":") {
				row.ISP = strings.TrimSpace(strings.SplitN(ln, ":", 2)[1])
			}
		}
	}

	if row.IP == "" {
		ip, fam := pickIP(out)
		row.IP, row.Family = ip, fam
	} else {
		if strings.Contains(row.IP, ":") {
			row.Family = "v6"
		} else {
			row.Family = "v4"
		}
	}
	if row.IP == "" {
		row.Error = "没解析到 IP"
	}
	return row
}

// classify 依据 IP 归属判定它走了哪条线（本网拓扑：移动/联通 v4 出口 + 9929 + 代理节点）。
// 优先级：已知出口 IP 精确匹配 > 机队节点 IP（=被代理）> ISP 关键词 > 兜底。
func classify(row *SplitRow, exits map[string]string, nodeIPs map[string]string) {
	if row.IP == "" {
		return
	}
	// 1) 是否等于某条线的出口 IP（最硬的判据）
	for line, ip := range exits {
		if ip != "" && ip == row.IP {
			row.Line, row.Kind = line, "direct"
			return
		}
	}
	// 2) 是否是机队节点的 IP（= 流量被代理到该节点）
	for name, ip := range nodeIPs {
		if ip == "" {
			continue
		}
		if ip == row.IP {
			row.Line, row.Kind = "代理 → "+name, "proxy"
			return
		}
		// ★ v6 回显常被截断/简写（如 2a12:a304:4:63b vs 2a12:a304:4:63b::a）⇒ 前缀匹配
		if strings.Contains(ip, ":") && strings.HasPrefix(ip, row.IP) {
			row.Line, row.Kind = "代理 → "+name, "proxy"
			return
		}
	}
	// 3) ISP 关键词
	isp := strings.ToLower(row.ISP + " " + row.Region)
	switch {
	case strings.Contains(isp, "移动") || strings.Contains(isp, "mobile") || strings.Contains(isp, "cmcc"):
		row.Line, row.Kind = "移动", "direct"
	case strings.Contains(isp, "联通") || strings.Contains(isp, "unicom"):
		row.Line, row.Kind = "联通", "direct"
	case strings.Contains(isp, "电信") || strings.Contains(isp, "telecom"):
		row.Line, row.Kind = "电信", "direct"
	case strings.Contains(isp, "9929") || strings.Contains(isp, "industrial"):
		row.Line, row.Kind = "9929", "direct"
	default:
		// 4) 都判不出：用 ip-api 反查一次（有缓存，便宜）
		if !isPrivateIPV6(row.IP) {
			if as := LookupASN(context.Background(), []string{row.IP}); len(as) > 0 {
				if row.ISP == "" {
					row.ISP = as[0].Display
				}
				d := strings.ToLower(as[0].Display)
				switch {
				case strings.Contains(d, "移动") || strings.Contains(d, "mobile"):
					row.Line, row.Kind = "移动", "direct"
				case strings.Contains(d, "联通") || strings.Contains(d, "unicom"):
					row.Line, row.Kind = "联通", "direct"
				case strings.Contains(d, "电信") || strings.Contains(d, "telecom"):
					row.Line, row.Kind = "电信", "direct"
				}
			}
		}
		if row.Line == "" {
			row.Line = "未知"
		}
	}
}

func isPrivateIPV6(ip string) bool {
	return strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.16.") || strings.HasPrefix(ip, "100.64.") ||
		strings.HasPrefix(ip, "198.18.")
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// SplitTunnel 并发跑全部探测点并给出归属判定。
// exits: 线路名 -> 出口IP（由当前钉线状态 + 各线实测得到）；nodeIPs: 机队节点 -> IP。
func SplitTunnel(ctx context.Context, exits, nodeIPs map[string]string) []SplitRow {
	var wg sync.WaitGroup
	rows := make([]SplitRow, len(splitProbes))
	sem := make(chan struct{}, 3) // 并发压到 3：探测点多在境外，并发高了互相抢带宽全超时
	for i, p := range splitProbes {
		wg.Add(1)
		go func(i int, p probeDef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rows[i] = runProbe(ctx, p)
		}(i, p)
	}
	wg.Wait()
	for i := range rows {
		classify(&rows[i], exits, nodeIPs)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Group != rows[j].Group {
			return rows[i].Group < rows[j].Group
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

// lineOfIP 反查某 IP 属于已知出口还是节点（给外部复用）。
func lineOfIP(ip string, exits, nodeIPs map[string]string) string {
	for l, v := range exits {
		if v == ip {
			return l
		}
	}
	for n, v := range nodeIPs {
		if v == ip {
			return "代理 → " + n
		}
	}
	return fmt.Sprintf("未知(%s)", ip)
}
