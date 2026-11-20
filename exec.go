package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---------- 通用命令执行 ----------

// runCmd 跑一条命令并返回 stdout+stderr(超时由 ctx 控制)。
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// streamCmd 逐行回调(stdout+stderr 合并), 用于 ping / traceroute 实时输出。
func streamCmd(ctx context.Context, name string, args []string, onLine func(string)) error {
	cmd := exec.CommandContext(ctx, name, args...)
	pr, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		onLine(sc.Text())
	}
	return cmd.Wait()
}

// ---------- DNS 真实解析(绕过 ADG fake-ip) ----------

type DNSRecord struct {
	Name  string `json:"name"`
	TTL   int    `json:"ttl"`
	Type  string `json:"type"`
	Value string `json:"value"`
	Fake  bool   `json:"fake"`
}

type DNSResult struct {
	Name     string      `json:"name"`
	Resolver string      `json:"resolver"`
	Ms       int         `json:"ms"`
	Records  []DNSRecord `json:"records"`
	Raw      string      `json:"raw"`
	FakeIP   bool        `json:"fake_ip"`
	Error    string      `json:"error,omitempty"`
}

var fakeNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("198.18.0.0/15")
	return n
}()

// dohEndpoints: 常用 DoH 端点(用 JSON 接口, 无需额外依赖)。
// ★ 国内明文 53 对境外域名普遍被污染(实测 1.1.1.1/8.8.8.8/223.5.5.5 都返回假 IP),
// 只有 doh.pub(腾讯)稳定返回真 IP, 所以默认走它。
var dohEndpoints = map[string]string{
	"doh.pub":    "https://doh.pub/dns-query",
	"alidns":     "https://dns.alidns.com/resolve",
	"cloudflare": "https://1.1.1.1/dns-query",
	"google":     "https://dns.google/resolve",
}

func isDoH(resolver string) (string, bool) {
	if u, ok := dohEndpoints[resolver]; ok {
		return u, true
	}
	if strings.HasPrefix(resolver, "https://") {
		return resolver, true
	}
	return "", false
}

// dohTransport 全局共享: 原来每次 DoH 查询都新建 Transport, 连接无法复用,
// 批量解析时每个域名都重新 TCP+TLS 握手。Transport 本身并发安全, 适合共享。
var dohTransport = &http.Transport{
	// 强制 IPv4: 否则 DoH 可能走 IPv6( v6 线路), 与当前钉线不一致
	DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 6 * time.Second}
		return d.DialContext(c, "tcp4", addr)
	},
	TLSHandshakeTimeout: 6 * time.Second,
	MaxIdleConnsPerHost: 4,
}

// resolveDoH 用 DoH(JSON) 查询, 返回真实记录。
func resolveDoH(ctx context.Context, name, typ, endpoint string) DNSResult {
	res := DNSResult{Name: name, Resolver: endpoint, Records: []DNSRecord{}}
	start := time.Now()
	url := endpoint + "?name=" + urlQueryEscape(name) + "&type=" + urlQueryEscape(typ)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("accept", "application/dns-json")
	hc := &http.Client{Timeout: 8 * time.Second, Transport: dohTransport}
	resp, err := hc.Do(req)
	if err != nil {
		res.Error = "DoH 请求失败: " + err.Error()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	res.Ms = int(time.Since(start).Milliseconds())
	res.Raw = string(body)
	var j struct {
		Status int `json:"Status"`
		Answer []struct {
			Name string `json:"name"`
			TTL  int    `json:"TTL"`
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &j); err != nil {
		res.Error = "DoH 响应解析失败: " + err.Error()
		return res
	}
	if j.Status != 0 {
		res.Error = fmt.Sprintf("DNS 返回状态 %d(3=NXDOMAIN)", j.Status)
	}
	tnames := map[int]string{1: "A", 5: "CNAME", 28: "AAAA", 15: "MX", 16: "TXT", 2: "NS", 6: "SOA"}
	for _, a := range j.Answer {
		t := tnames[a.Type]
		if t == "" {
			t = strconv.Itoa(a.Type)
		}
		rec := DNSRecord{Name: strings.TrimSuffix(a.Name, "."), TTL: a.TTL, Type: t, Value: a.Data}
		if t == "A" {
			if ip := net.ParseIP(a.Data); ip != nil && fakeNet.Contains(ip) {
				rec.Fake = true
				res.FakeIP = true
			}
		}
		res.Records = append(res.Records, rec)
	}
	if len(res.Records) == 0 && res.Error == "" {
		res.Error = "无记录"
	}
	return res
}

// Resolve 用指定公共 DNS(dig) 解析, 返回真 IP。ADG/旁路由的 198.18/15 会标 fake。
func Resolve(ctx context.Context, name, typ, resolver string) DNSResult {
	if resolver == "" {
		resolver = "doh.pub"
	}
	if typ == "" {
		typ = "A"
	}
	if ep, ok := isDoH(resolver); ok {
		r := resolveDoH(ctx, name, typ, ep)
		r.Resolver = resolver
		return r
	}
	res := DNSResult{Name: name, Resolver: resolver, Records: []DNSRecord{}}
	cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	out, err := runCmd(cctx, "dig", "+time=3", "+tries=1", "+noall", "+answer", "+stats", "@"+resolver, name, typ)
	res.Raw = strings.TrimSpace(out)
	if err != nil {
		res.Error = strings.TrimSpace(out)
		if res.Error == "" {
			res.Error = err.Error()
		}
		return res
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, ";") {
			if strings.Contains(line, "Query time:") {
				f := strings.Fields(line)
				for i, t := range f {
					if t == "time:" && i+1 < len(f) {
						if v, e := strconv.Atoi(strings.TrimSuffix(f[i+1], " msec")); e == nil {
							res.Ms = v
						}
					}
				}
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		ttl, _ := strconv.Atoi(f[1])
		rec := DNSRecord{Name: strings.TrimSuffix(f[0], "."), TTL: ttl, Type: f[3], Value: f[4]}
		if rec.Type == "A" {
			if ip := net.ParseIP(rec.Value); ip != nil && fakeNet.Contains(ip) {
				rec.Fake = true
				res.FakeIP = true
			}
		}
		res.Records = append(res.Records, rec)
	}
	if len(res.Records) == 0 && res.Error == "" {
		res.Error = "无记录(可能不存在或被过滤)"
	}
	return res
}

// ---------- ping ----------

var (
	rePingTime = regexp.MustCompile(`time[=<]([\d.]+)\s*ms`)
	rePingTTL  = regexp.MustCompile(`ttl=(\d+)`)
	rePingSeq  = regexp.MustCompile(`icmp_seq=(\d+)`)
)

type PingSample struct {
	Seq   int     `json:"seq"`
	RTT   float64 `json:"rtt"`
	TTL   int     `json:"ttl"`
	Loss  bool    `json:"loss"`
	Line  string  `json:"line"`
}

type PingSummary struct {
	Target   string  `json:"target"`
	Sent     int     `json:"sent"`
	Recv     int     `json:"recv"`
	LossPct  float64 `json:"loss_pct"`
	Min      float64 `json:"min"`
	Avg      float64 `json:"avg"`
	Max      float64 `json:"max"`
	Jitter   float64 `json:"jitter"`
	IP       string  `json:"ip"`
	Resolved []string `json:"resolved"`
	FakeIP   bool    `json:"fake_ip"`
	Resolve  int     `json:"resolve_ms"`
}

// Ping 走当前钉线出口, 逐包回调, 最后给统计。
func Ping(ctx context.Context, ip string, count, intervalMs, fam int) (PingSummary, []PingSample, error) {
	s := PingSummary{Target: ip}
	if count <= 0 {
		count = 5
	}
	if intervalMs <= 0 {
		intervalMs = 300
	}
	flag := "-4"
	if fam == 6 {
		flag = "-6"
	}
	args := []string{flag, "-n", "-c", strconv.Itoa(count), "-i", fmt.Sprintf("%.2f", float64(intervalMs)/1000.0), "-W", "2", ip}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(count)*time.Duration(intervalMs)*time.Millisecond+15*time.Second)
	defer cancel()
	var samples []PingSample
	var rtts []float64
	err := streamCmd(cctx, "ping", args, func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		if m := rePingTime.FindStringSubmatch(line); m != nil {
			v, _ := strconv.ParseFloat(m[1], 64)
			sm := PingSample{RTT: v, Line: line}
			if q := rePingSeq.FindStringSubmatch(line); q != nil {
				sm.Seq, _ = strconv.Atoi(q[1])
			}
			if t := rePingTTL.FindStringSubmatch(line); t != nil {
				sm.TTL, _ = strconv.Atoi(t[1])
			}
			samples = append(samples, sm)
			rtts = append(rtts, v)
			return
		}
		if strings.Contains(line, "no answer yet") || strings.Contains(line, "Destination Host Unreachable") || strings.Contains(line, "Destination Port Unreachable") {
			sm := PingSample{Loss: true, Line: line}
			if q := rePingSeq.FindStringSubmatch(line); q != nil {
				sm.Seq, _ = strconv.Atoi(q[1])
			}
			samples = append(samples, sm)
		}
	})
	s.Sent = count
	s.Recv = len(rtts)
	if s.Sent > 0 {
		s.LossPct = float64(s.Sent-s.Recv) / float64(s.Sent) * 100
	}
	if len(rtts) > 0 {
		s.Min, s.Max = rtts[0], rtts[0]
		sum := 0.0
		for _, v := range rtts {
			if v < s.Min {
				s.Min = v
			}
			if v > s.Max {
				s.Max = v
			}
			sum += v
		}
		s.Avg = sum / float64(len(rtts))
		// jitter = 相邻差值绝对值均值(与 ping 的 mdev 口径接近)
		if len(rtts) > 1 {
			j := 0.0
			for i := 1; i < len(rtts); i++ {
				j += math.Abs(rtts[i] - rtts[i-1])
			}
			s.Jitter = j / float64(len(rtts)-1)
		}
	}
	return s, samples, err
}

// ---------- traceroute ----------

var (
	reHop    = regexp.MustCompile(`^\s*(\d+)\s+(.*)$`)
	reHopRTT = regexp.MustCompile(`([\d.]+)\s*ms`)
)

type Hop struct {
	Hop  int      `json:"hop"`
	Raw  string   `json:"raw"`
	Addr []string `json:"addr"`
	RTT  []string `json:"rtt"`
}

func parseHop(line string) *Hop {
	m := reHop.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	h := &Hop{Hop: 0, Raw: strings.TrimSpace(line)}
	h.Hop, _ = strconv.Atoi(m[1])
	for _, f := range strings.Fields(m[2]) {
		if f == "*" {
			continue
		}
		if net.ParseIP(f) != nil {
			h.Addr = append(h.Addr, f)
		}
	}
	for _, mm := range reHopRTT.FindAllStringSubmatch(m[2], -1) {
		h.RTT = append(h.RTT, mm[1]+" ms")
	}
	return h
}

// Traceroute 逐跳回调。proto: udp(默认) / icmp / tcp(443)。
// 实测同一目标三种探测能挖出的跳数差别很大(骨干/对端常只回某一种), 所以必须可切。
func Traceroute(ctx context.Context, ip string, maxHops, q int, proto string, fam int, onLine func(string)) error {
	if maxHops <= 0 {
		maxHops = 20
	}
	if q <= 0 {
		q = 1
	}
	flag := "-4"
	if fam == 6 {
		flag = "-6"
	}
	args := []string{flag, "-n", "-q", strconv.Itoa(q), "-w", "1.5", "-m", strconv.Itoa(maxHops)}
	switch proto {
	case "icmp":
		args = append(args, "-I")
	case "tcp":
		args = append(args, "-T", "-p", "443")
	}
	args = append(args, ip)
	return streamCmd(ctx, "traceroute", args, onLine)
}

// ---------- 出口信息 ----------

type ExitInfo struct {
	IP    string `json:"ip"`
	Loc   string `json:"loc"`
	Colo  string `json:"colo"`
	Org   string `json:"org"`
	City  string `json:"city"`
	Error string `json:"error,omitempty"`
}

// ExitInfoOf 通过当前钉线访问 cloudflare trace 拿真实出口 IP, 再查 ipinfo 的 AS/归属。
func ExitInfoOf(ctx context.Context, fam int) ExitInfo {
	if fam == 6 {
		addr := localV6Addr()
		if addr == "" {
			return ExitInfo{Error: "容器没有全局 IPv6 地址"}
		}
		e := ExitInfo{IP: addr, Loc: "CN"}
		if info := LookupASN(ctx, []string{addr}); len(info) > 0 {
			e.Org = info[0].Display
			if info[0].CountryCN != "" {
				e.Loc = info[0].CountryCN
			}
		}
		return e
	}
	var e ExitInfo
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	// 先用公共 DNS 显式解析, 保证不会拿到 fake-ip
	r := Resolve(cctx, "www.cloudflare.com", "A", "doh.pub")
	ip := ""
	if len(r.Records) > 0 {
		ip = r.Records[0].Value
	}
	args := []string{"-4", "-s", "-m", "10"}
	if ip != "" {
		args = append(args, "--resolve", "www.cloudflare.com:443:"+ip)
	}
	args = append(args, "https://www.cloudflare.com/cdn-cgi/trace")
	out, err := runCmd(cctx, "curl", args...)
	if err != nil && out == "" {
		e.Error = err.Error()
		return e
	}
	for _, line := range strings.Split(out, "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "ip":
			e.IP = kv[1]
		case "loc":
			e.Loc = kv[1]
		case "colo":
			e.Colo = kv[1]
		}
	}
	if e.IP != "" {
		if b, err := runCmd(cctx, "curl", "-4", "-s", "-m", "6", "https://ipinfo.io/"+e.IP+"/json"); err == nil {
			var m map[string]any
			if json.Unmarshal([]byte(b), &m) == nil {
				e.Org, _ = m["org"].(string)
				e.City, _ = m["city"].(string)
			}
		}
	}
	return e
}

// ---------- 机队(iperf3 / HTTP 2G 文件) ----------

type Node struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	IP    string `json:"ip"`
	// Group 可选: 出口组。同组节点共享同一出口上限(如同机房两台),
	// 聚合自动分配时同组只算一个源; 空 = 各自成组。
	Group string `json:"group,omitempty"`
}

func sshArgs(node Node, remote string) []string {
	return []string{
		"-i", cfg.FleetKey,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=6",
		"-o", "BatchMode=yes",
		"-o", "LogLevel=ERROR",
		"root@" + node.IP,
		remote,
	}
}

// IperfPrepare 在节点上放行 5201 并拉起 iperf3 服务端。
func IperfPrepare(ctx context.Context, node Node) (string, error) {
	remote := `fw-iperf on >/dev/null 2>&1 || true; pkill -x iperf3 2>/dev/null; sleep 0.3; nohup iperf3 -s -p 5201 >/tmp/iperf3srv.log 2>&1 & sleep 0.6; (ss -lnt 2>/dev/null | grep -q ':5201') && echo IPERF_UP || echo IPERF_DOWN`
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	return runCmd(cctx, "ssh", sshArgs(node, remote)...)
}

// IperfStop 关闭节点上的 iperf3 服务端并收回端口放行。
func IperfStop(ctx context.Context, node Node) string {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, _ := runCmd(cctx, "ssh", sshArgs(node, `pkill -x iperf3; fw-iperf off >/dev/null 2>&1 || true; echo stopped`)...)
	return out
}

type IperfResult struct {
	Node      string  `json:"node"`
	Dir       string  `json:"dir"`
	Mbps      float64 `json:"mbps"`
	Retrans   int     `json:"retrans"`
	Seconds   float64 `json:"seconds"`
	Streams   int     `json:"streams"`
	RawError  string  `json:"raw_error,omitempty"`
}

// IperfRun 跑一次 iperf3(-R = 下行/节点发给家)。
func IperfRun(ctx context.Context, node Node, dir string, secs, streams int) IperfResult {
	if secs < 3 {
		secs = 8
	}
	if streams < 1 {
		streams = 1
	}
	r := IperfResult{Node: node.Label, Dir: dir, Seconds: float64(secs), Streams: streams}
	args := []string{"-c", node.IP, "-p", "5201", ipFamFlag(node.IP), "-t", strconv.Itoa(secs), "-P", strconv.Itoa(streams),
		"-J", "--connect-timeout", "5000", "-i", "0"}
	if dir == "down" {
		args = append(args, "-R")
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(secs+25)*time.Second)
	defer cancel()
	out, err := runCmd(cctx, "iperf3", args...)
	if err != nil && out == "" {
		r.RawError = err.Error()
		return r
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
		r.RawError = strings.TrimSpace(out)
		if len(r.RawError) > 400 {
			r.RawError = r.RawError[:400]
		}
		return r
	}
	if j.Error != "" {
		r.RawError = j.Error
		return r
	}
	// 下行: 客户端收 => sum_received; 上行: 客户端发 => sum_sent
	if dir == "down" {
		r.Mbps = j.End.SumReceived.BitsPerSecond / 1e6
		r.Retrans = j.End.SumReceived.Retransmits
	} else {
		r.Mbps = j.End.SumSent.BitsPerSecond / 1e6
		r.Retrans = j.End.SumSent.Retransmits
	}
	return r
}

// HTTPPrepare 在节点上放行 nginx 8899(2GB 测速文件)。
func HTTPPrepare(ctx context.Context, node Node) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return runCmd(cctx, "ssh", sshArgs(node, `fw-http on 2>/dev/null || true; ls -l /srv/2gtest/2g.bin 2>/dev/null | awk '{print "FILE=" $5}'`)...)
}

// HTTPCleanup 测完收回 8899 放行(不长期对外开端口)。
func HTTPCleanup(ctx context.Context, node Node) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	runCmd(cctx, "ssh", sshArgs(node, `fw-http off >/dev/null 2>&1 || true; echo closed`)...)
}

type HTTPResult struct {
	Node     string  `json:"node"`
	Threads  int     `json:"threads"`
	Seconds  float64 `json:"seconds"`
	Mbps     float64 `json:"mbps"`
	Bytes    int64   `json:"bytes"`
	Mode     string  `json:"mode"`
	Error    string  `json:"error,omitempty"`
}

// HTTPRun 多线程拉机队 nginx 上的 2GB 文件, 算合计吞吐。
func HTTPRun(ctx context.Context, node Node, threads, secs int) HTTPResult {
	return HTTPRunMode(ctx, node, threads, secs, "fleet")
}

// HTTPRunMode: fleet = 机队 2G 文件; cf = Cloudflare 官方测速接口(任意出口都可用)。
func HTTPRunMode(ctx context.Context, node Node, threads, secs int, mode string) HTTPResult {
	if threads < 1 {
		threads = 1
	}
	if secs < 3 {
		secs = 10
	}
	r := HTTPResult{Node: node.Label, Threads: threads, Seconds: float64(secs), Mode: mode}
	type res struct {
		bytes int64
		code  int
		err   error
	}
	ch := make(chan res, threads)
	cctx, cancel := context.WithTimeout(ctx, time.Duration(secs+15)*time.Second)
	defer cancel()
	start := time.Now()
	for i := 0; i < threads; i++ {
		go func() {
			// Cloudflare 单次上限 50MB(实测 bytes>=1e8 直接 403), 故用 50MB + 唯一参数防缓存
			var url string
			if mode == "cf" {
				url = fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=50000000&x=%d", time.Now().UnixNano())
			} else {
				url = fmt.Sprintf("http://%s/2g.bin?x=%d", hostPort(node.IP, 8899), time.Now().UnixNano())
			}
			out, err := runCmd(cctx, "curl", ipFamFlag(node.IP), "-s", "-o", "/dev/null", "-m", strconv.Itoa(secs),
				"--max-time", strconv.Itoa(secs), "-w", "%{http_code} %{size_download}", url)
			fields := strings.Fields(out)
			var code int
			var n int64
			if len(fields) == 2 {
				code, _ = strconv.Atoi(fields[0])
				n, _ = strconv.ParseInt(fields[1], 10, 64)
			}
			ch <- res{bytes: n, code: code, err: err}
		}()
	}
	var total int64
	var lastErr string
	for i := 0; i < threads; i++ {
		rr := <-ch
		total += rr.bytes
		if rr.code != 0 && rr.code != 200 && lastErr == "" {
			lastErr = fmt.Sprintf("HTTP %d", rr.code)
		}
		if rr.err != nil && lastErr == "" {
			lastErr = rr.err.Error()
		}
	}
	el := time.Since(start).Seconds()
	if el < 0.2 {
		el = 0.2
	}
	r.Bytes = total
	r.Mbps = float64(total) * 8 / el / 1e6
	// 有效时长按 min(el, secs) 算更贴近"稳定期吞吐", 但用实际墙钟更保守
	if total == 0 {
		r.Error = "没有收到数据"
		if lastErr != "" {
			r.Error += ": " + lastErr
		}
	}
	return r
}

// ---------- 小工具: 把 []byte 转成单行 ----------

func oneline(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

var _ = oneline

func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// ---------- TCP 握手探测(ICMP 被墙时用) ----------

type TCPProbe struct {
	Seq  int     `json:"seq"`
	Ms   float64 `json:"rtt"`
	Loss bool    `json:"loss"`
	Err  string  `json:"err,omitempty"`
}

// TCPing 对 ip:port 做 N 次 TCP 握手, 返回每次耗时与汇总。
func TCPing(ctx context.Context, ip string, port, count, intervalMs, fam int) (PingSummary, []TCPProbe) {
	if port <= 0 || port > 65535 {
		port = 443
	}
	if count <= 0 {
		count = 5
	}
	if intervalMs <= 0 {
		intervalMs = 300
	}
	s := PingSummary{Target: fmt.Sprintf("%s:%d", ip, port)}
	var probes []TCPProbe
	var rtts []float64
	d := net.Dialer{Timeout: 4 * time.Second}
	for i := 1; i <= count; i++ {
		select {
		case <-ctx.Done():
			return s, probes
		default:
		}
		start := time.Now()
		network := "tcp4"
		if fam == 6 {
			network = "tcp6"
		}
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip, strconv.Itoa(port)))
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		if err != nil {
			probes = append(probes, TCPProbe{Seq: i, Loss: true, Err: oneline(err.Error())})
		} else {
			conn.Close()
			probes = append(probes, TCPProbe{Seq: i, Ms: ms})
			rtts = append(rtts, ms)
		}
		time.Sleep(time.Duration(intervalMs) * time.Millisecond)
	}
	s.Sent = count
	s.Recv = len(rtts)
	if s.Sent > 0 {
		s.LossPct = float64(s.Sent-s.Recv) / float64(s.Sent) * 100
	}
	if len(rtts) > 0 {
		s.Min, s.Max = rtts[0], rtts[0]
		sum := 0.0
		for _, v := range rtts {
			if v < s.Min {
				s.Min = v
			}
			if v > s.Max {
				s.Max = v
			}
			sum += v
		}
		s.Avg = sum / float64(len(rtts))
		if len(rtts) > 1 {
			j := 0.0
			for i := 1; i < len(rtts); i++ {
				j += math.Abs(rtts[i] - rtts[i-1])
			}
			s.Jitter = j / float64(len(rtts)-1)
		}
	}
	return s, probes
}

// ipFamFlag 按目标地址自动选 ping/iperf3/curl 的协议族开关。
// ★ v6 节点（如带 v6 后缀的节点）必须走 -6，否则硬编码 -4 会连不上。
func ipFamFlag(host string) string {
	if strings.Contains(host, ":") {
		return "-6"
	}
	return "-4"
}

// hostPort 拼 host:port，IPv6 字面量要加方括号（http://[2400::a]:8899/...），否则 URL 非法。
func hostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}
