package main

// 主流站点走向探测：不只看「出口 IP」，而是实测「访问这些站点时实际连到哪个 IP、是否通、多快」，
// 从而一眼看出分流对真实业务的走向（YouTube 走哪条线、Netflix 有没有走代理、GitHub 直连还是绕路）。
//
// ★ 为什么必须先 DoH 解析再 --resolve：
//   面板容器 resolv.conf 指向 223.5.5.5（明文），境外域名普遍被污染——
//   实测 www.youtube.com 解析成 31.13.92.37（Facebook 的 IP）、www.google.com 解析成 31.13.92.37，
//   doh.pub / alidns 对 youtube 也返回假 IP（104.244.42.197 / 142.251.151.4 中只有 CF 的真）。
//   所以统一走 Cloudflare DoH 取真 IP，再用 curl --resolve 强制连该 IP + 原域名 SNI。

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// siteDef 一个主流站点探测目标。
type siteDef struct {
	Group string `json:"group"` // 归类：视频/社交/开发/AI
	Name  string `json:"name"`  // 展示名
	Host  string `json:"host"`  // 域名（也是 SNI）
	URL   string `json:"url"`   // 实际访问 URL（可用不同路径）
}

var splitSites = []siteDef{
	{"视频", "YouTube", "www.youtube.com", "https://www.youtube.com/"},
	{"视频", "Netflix", "www.netflix.com", "https://www.netflix.com/"},
	{"视频", "Disney+", "www.disneyplus.com", "https://www.disneyplus.com/"},
	{"视频", "TikTok", "www.tiktok.com", "https://www.tiktok.com/"},
	{"社交", "Instagram", "www.instagram.com", "https://www.instagram.com/"},
	{"社交", "X (Twitter)", "x.com", "https://x.com/"},
	{"开发", "GitHub", "github.com", "https://github.com/"},
	{"开发", "Cloudflare", "www.cloudflare.com", "https://www.cloudflare.com/"},
	{"AI", "OpenAI", "chat.openai.com", "https://chat.openai.com/"},
	{"AI", "Claude", "claude.ai", "https://claude.ai/"},
}


// currentExitIP 查"此刻整机出口 IP"（Cloudflare trace，最稳、国内国外都通）。
// ★ 用途：站点探测没法直接知道"站点看到我是谁"，但同一次请求内整机出口是一致的，
//   所以测站点时顺带查一次出口，就能判定这些站点的流量走了哪条线/是否走了代理。
func currentExitIP(ctx context.Context) string {
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, _ := runCmd(cctx, "curl", "-s", "-m", "6", "--max-time", "6",
		"https://www.cloudflare.com/cdn-cgi/trace")
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(ln, "ip=") {
			return strings.TrimPrefix(ln, "ip=")
		}
	}
	return ""
}

// SiteRow 一个站点的探测结果。
type SiteRow struct {
	Group   string `json:"group"`
	Name    string `json:"name"`
	Host    string `json:"host"`
	IP      string `json:"ip"`      // DoH 解析出的真 IP
	Code    int    `json:"code"`    // HTTP 状态码
	Ms      int64  `json:"ms"`      // 总耗时
	OK      bool   `json:"ok"`      // 是否可达（code>0）
	Line    string `json:"line"`    // 该 IP 归属哪条线/代理
	Kind    string `json:"kind"`    // direct / proxy
	ASN     string `json:"asn"`     // IP 归属（服务商名）
	// OpenClash/mihomo 真实分流结果（比"整机出口"精确得多）
	MihomoNode  string   `json:"mihomoNode,omitempty"`  // 实际出口节点, 如 node1/node2
	MihomoGroup string   `json:"mihomoGroup,omitempty"` // 命中的策略组, 如 📹 YouTube
	Chains      []string `json:"chains,omitempty"`      // 完整链路
	Error       string   `json:"error,omitempty"`

	mihomoHit bool // 内部：已由 mihomo 实际链路判定（后续不再被出口判定覆盖）
}

// dohResolveA 用 Cloudflare DoH 解析 A 记录（取第一个）。
// 不用 doh.pub：实测它对 youtube/google 返回被污染的假 IP。
func dohResolveA(ctx context.Context, host string) string {
	// 多个 DoH 源依次尝试：CF 最准但可能不可达（本网某些钉线直连境外时被墙）
	for _, src := range []string{
		"https://cloudflare-dns.com/dns-query?name=" + host + "&type=A",
		"https://dns.alidns.com/resolve?name=" + host + "&type=A",
		"https://doh.pub/dns-query?name=" + host + "&type=A",
	} {
		if ip := dohOnce(ctx, src); ip != "" {
			return ip
		}
	}
	return ""
}

func dohOnce(ctx context.Context, url string) string {
	cctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	out, _ := runCmd(cctx, "curl", "-s", "-m", "5", "--max-time", "5",
		"-H", "accept: application/dns-json", url)
	// 轻量解析: 取第一个 "data":"x.x.x.x"
	const key = `"data":"`
	for {
		i := strings.Index(out, key)
		if i < 0 {
			return ""
		}
		out = out[i+len(key):]
		j := strings.IndexByte(out, '"')
		if j < 0 {
			return ""
		}
		v := out[:j]
		// 只接受 A 记录的 IPv4；CNAME 的 data 是域名（如 ftl-www.netflix.com.），跳过
		if strings.Count(v, ".") == 3 && !strings.Contains(v, ":") {
			allDigits := true
			for _, part := range strings.Split(strings.TrimSuffix(v, "."), ".") {
				if part == "" {
					allDigits = false
					break
				}
				for _, c := range part {
					if c < '0' || c > '9' {
						allDigits = false
						break
					}
				}
			}
			if allDigits {
				return v
			}
		}
	}
}

// runSite 跑单个站点。
// ★ 连接存活期很短：curl 一结束 mihomo 里的连接可能就回收了，
//   所以必须【探完立刻】抓一次 connections，而不是等所有站点都跑完再抓。
func runSite(ctx context.Context, s siteDef) SiteRow {
	row := SiteRow{Group: s.Group, Name: s.Name, Host: s.Host}
	ip := dohResolveA(ctx, s.Host)
	if ip == "" {
		row.Error = "DoH 解析失败"
		return row
	}
	row.IP = ip
	st := time.Now()
	cctx, cancel := context.WithTimeout(ctx, 14*time.Second)
	defer cancel()
	// -L 跟随跳转；--resolve 钉住真 IP 但保留 SNI/Host 为原域名
	out, _ := runCmd(cctx, "curl", "-sL", "-o", "/dev/null", "-m", "10", "--max-time", "10",
		"-A", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/152.0",
		"-w", "%{http_code}",
		"--resolve", s.Host+":443:"+ip, s.URL)
	row.Ms = time.Since(st).Milliseconds()
	row.Code = atoiSafe(strings.TrimSpace(out))
	row.OK = row.Code > 0
	if !row.OK {
		if row.Ms < 80 {
			row.Error = "连接被拒/解析异常"
		} else {
			row.Error = "不可达/超时"
		}
	}
	// 没立刻命中时，用"保持连接"再抓一次：
	// 起一个限速的 curl 挂着（连接不结束），给 mihomo 0.8s 抓包窗口，再杀掉。
	if conns := fetchMihomoConns(ctx); matchMihomoPath(conns, s.Host, ip) == nil {
		holdAndGrab(ctx, s, ip, &row)
	} else if conns := fetchMihomoConns(ctx); len(conns) > 0 {
		if mp := matchMihomoPath(conns, s.Host, ip); mp != nil {
			row.MihomoNode = mp.Node
			row.MihomoGroup = mp.Group
			row.Chains = mp.All
			if mp.IsDirect() {
				row.Line, row.Kind = "直连（"+mp.Group+"）", "direct"
			} else {
				row.Line, row.Kind = "代理 → "+mp.Node, "proxy"
			}
			row.mihomoHit = true
		}
	}
	return row
}

// holdAndGrab 起一个限速挂起的 curl（连接保持打开），等 mihomo 记录后抓链路，然后杀掉。
// 有些站点响应太快（或探测本身走 HEAD 已结束），连接在 mihomo 里存活不到我们去查的那一刻。
func holdAndGrab(ctx context.Context, s siteDef, ip string, row *SiteRow) {
	if ip == "" {
		return
	}
	hctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		c, cc := context.WithTimeout(hctx, 6*time.Second)
		defer cc()
		// --limit-rate 1k 让连接挂住；-m 5 兜底
		runCmd(c, "curl", "-sL", "-o", "/dev/null", "-m", "5", "--max-time", "5",
			"--limit-rate", "1k", "-A", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
			"--resolve", s.Host+":443:"+ip, s.URL)
	}()
	time.Sleep(800 * time.Millisecond)
	conns := fetchMihomoConns(ctx)
	if mp := matchMihomoPath(conns, s.Host, ip); mp != nil {
		row.MihomoNode = mp.Node
		row.MihomoGroup = mp.Group
		row.Chains = mp.All
		row.mihomoHit = true
		if mp.IsDirect() {
			row.Line, row.Kind = "直连（"+mp.Group+"）", "direct"
		} else {
			row.Line, row.Kind = "代理 → "+mp.Node, "proxy"
		}
	}
}

func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// SplitSites 并发跑全部站点（并发 3，与 IP 探测一致，避免抢带宽）。
func SplitSites(ctx context.Context, exits, nodeIPs map[string]string) []SiteRow {
	var wg sync.WaitGroup
	rows := make([]SiteRow, len(splitSites))
	sem := make(chan struct{}, 3)
	for i, s := range splitSites {
		wg.Add(1)
		go func(i int, s siteDef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			rows[i] = runSite(ctx, s)
		}(i, s)
	}
	wg.Wait()

	// 用"整机出口"判定这些站点的走向（站点 IP 本身不代表出口）
	exitIP := currentExitIP(ctx)
	if exitIP != "" {
		er := SplitRow{IP: exitIP}
		classify(&er, exits, nodeIPs)
		for i := range rows {
			if rows[i].mihomoHit {
				continue // 已由 OpenClash 实际链路判定，优先保留
			}
			if rows[i].IP == "" {
				// 解析都没成，别硬套"直连某线"的结论；只标出口，结论留给"未测通"
				rows[i].Line = er.Line + "（未测通）"
				rows[i].Kind = ""
				continue
			}
			rows[i].Line, rows[i].Kind = er.Line, er.Kind
			rows[i].ASN = er.ISP
		}
	}
	return rows
}

// siteSummary 给前端一句人话结论。
func siteSummary(rows []SiteRow) string {
	if len(rows) == 0 {
		return ""
	}
	okN, proxyN, directN := 0, 0, 0
	for _, r := range rows {
		if r.OK {
			okN++
		}
		switch r.Kind {
		case "proxy":
			proxyN++
		case "direct":
			directN++
		}
	}
	return fmt.Sprintf("可达 %d/%d · 走代理 %d · 直连 %d", okN, len(rows), proxyN, directN)
}
