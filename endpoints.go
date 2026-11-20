package main

// endpoints.go —— 多云端点延迟矩阵（目录对齐 https://m2c.1ms.dog/zh-cn/）
//
// 设计要点：
//   1. 端点目录来自 m2c.1ms.dog 的官方清单（17 家厂商 / 361 个区域端点），
//      外加 8 个站外连通性检查点（CF / ipify / ident.me），共 369 个。
//      每个端点同时有 v4 主机(host) 与可选 v6 主机(host6，如 AWS 的 .api.aws)。
//   2. 一律用 DoH(doh.pub) 解析 —— 绝不能走本机 DNS，否则拿到 198.18 的 fake-ip。
//   3. 解析只做一次（并发 24），之后所有线路复用同一批真 IP，保证三线比的是「线路」不是「DNS」。
//   4. 每条线通过 ROS 钉线规则切换（复用 main.go 的 setExit），切完等 1.5s 让 conntrack/路由生效，
//      测完恢复原来的出口。
//   5. 每个端点同时测 ICMP 与 TCP:443 握手：对象存储接口普遍不回 ICMP（实测只有 40~58% 响应），
//      但 TCP 握手几乎全部可达，两者都给，前端可切换以哪个排序。

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed static/endpoints.json
var epFS embed.FS

type EpEndpoint struct {
	ID         string `json:"id"`
	Vendor     string `json:"vendor"`
	VendorName string `json:"vendor_name"`
	Region     string `json:"region"`
	City       string `json:"city"`
	Country    string `json:"country"`
	Continent  string `json:"continent"`
	Tier       string `json:"tier"`
	Method     string `json:"method"`
	Host       string `json:"host"`
	Path       string `json:"path"`
	Host6      string `json:"host6"`
	Fam        string `json:"fam,omitempty"`
	Port       int    `json:"port,omitempty"` // 自定义端点可指定端口（默认 443）
}

type EpCatalog struct {
	Verified  string                     `json:"verified"`
	Source    string                     `json:"source"`
	Vendors   map[string]json.RawMessage `json:"vendors"`
	Endpoints []EpEndpoint               `json:"endpoints"`
}

var (
	epOnce sync.Once
	epCat  EpCatalog
	epRaw  []byte
)

func loadEpCatalog() (*EpCatalog, []byte) {
	epOnce.Do(func() {
		b, err := epFS.ReadFile("static/endpoints.json")
		if err != nil {
			return
		}
		epRaw = b
		json.Unmarshal(b, &epCat) // 解析失败时 epCat 为空，handler 会返回错误
	})
	return &epCat, epRaw
}

// handleEndpoints 返回目录（原样透传，前端自己分组/过滤）。
func handleEndpoints(w http.ResponseWriter, r *http.Request) {
	cat, raw := loadEpCatalog()
	if len(raw) == 0 {
		writeJSON(w, 500, map[string]string{"error": "端点目录未内嵌"})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(raw)
	_ = cat
}

// ---- DoH 解析缓存 + 重试 + 多上游兜底 ----
// 背景：一次性怼 369 个域名到 doh.pub，会触发它的限流（返回 HTML ⇒ "invalid character '<'"），
// 实测同一批端点第一次跑失败 19 个、第二次 119 个，越跑越差。对策：
//   ① 结果缓存（成功 30min，失败 90s），重复点「开始」不再重解析；
//   ② 每个域名 3 个上游依次试（doh.pub → 阿里 → Cloudflare），每个上游最多 2 次；
//   ③ 解析并发从 24 降到 6 并加抖动。
type epDNSEntry struct {
	ip  string
	err string
	at  time.Time
}

var (
	epDNSMu sync.Mutex
	epDNS   = map[string]epDNSEntry{}
)

const (
	epDNSOKTTL  = 30 * time.Minute
	epDNSBadTTL = 90 * time.Second
)

func epDNSGet(host string, fam int) (string, string, bool) {
	key := fmt.Sprintf("%s/%d", host, fam)
	epDNSMu.Lock()
	defer epDNSMu.Unlock()
	e, ok := epDNS[key]
	if !ok {
		return "", "", false
	}
	ttl := epDNSOKTTL
	if e.ip == "" {
		ttl = epDNSBadTTL
	}
	if time.Since(e.at) > ttl {
		return "", "", false
	}
	return e.ip, e.err, true
}

func epDNSPut(host string, fam int, ip, errMsg string) {
	key := fmt.Sprintf("%s/%d", host, fam)
	epDNSMu.Lock()
	epDNS[key] = epDNSEntry{ip: ip, err: errMsg, at: time.Now()}
	epDNSMu.Unlock()
}

// epResolve 解析一个主机名（三线共用），带缓存/重试/多 DoH 兜底。
func epResolve(ctx context.Context, host string, fam int) (string, string) {
	if ip, errMsg, ok := epDNSGet(host, fam); ok {
		return ip, errMsg
	}
	var lastErr string
	for _, r := range []string{"doh.pub", "alidns", "cloudflare"} {
		for attempt := 0; attempt < 2; attempt++ {
			if ctx.Err() != nil {
				return "", "已取消"
			}
			cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			ip, dr := resolveTarget(cctx, host, r, fam)
			cancel()
			if ip != "" {
				epDNSPut(host, fam, ip, "")
				return ip, ""
			}
			lastErr = dr.Error
			if lastErr == "" {
				lastErr = "无记录"
			}
			time.Sleep(time.Duration(150*(attempt+1)) * time.Millisecond)
		}
	}
	epDNSPut(host, fam, "", lastErr)
	return "", lastErr
}

// epStats 是一组探测样本的统计量（ms）。对齐 m2c.1ms.dog 的口径：
// 中位数 / P90 / 抖动 / 丢包 才是选区域真正该看的，只看 avg 会被单次抖动带偏。
type epStats struct {
	Sent   int     `json:"sent"`
	Recv   int     `json:"recv"`
	Loss   float64 `json:"loss"`   // %
	Min    float64 `json:"min"`
	Median float64 `json:"median"`
	P90    float64 `json:"p90"`
	Avg    float64 `json:"avg"`
	Max    float64 `json:"max"`
	Jitter float64 `json:"jitter"`
}

// epResult 是单个端点在单条线上的测量结果。
type epResult struct {
	ID   string   `json:"id"`
	Wan  string   `json:"wan"`
	IP   string   `json:"ip"`
	Port int      `json:"port,omitempty"`
	Icmp *epStats `json:"icmp,omitempty"`
	Tcp  *epStats `json:"tcp,omitempty"`
	Err  string   `json:"err,omitempty"`
}

// statsFromSamples 把逐次 RTT 采样算成统计量。idxs 里 <=0 表示该样本丢失。
func statsFromSamples(sent int, rtts []float64, sum PingSummary) *epStats {
	var ok []float64
	for _, v := range rtts {
		if v > 0 {
			ok = append(ok, v)
		}
	}
	st := &epStats{Sent: sent, Recv: len(ok), Loss: sum.LossPct,
		Min: sum.Min, Avg: sum.Avg, Max: sum.Max, Jitter: sum.Jitter}
	if st.Recv == 0 {
		st.Min, st.Avg, st.Max, st.Jitter = 0, 0, 0, 0
		return st
	}
	sort.Float64s(ok)
	st.Median = pct(ok, 50)
	st.P90 = pct(ok, 90)
	return st
}

// pct 取第 p 百分位（线性插值），ok 必须已排序。
func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if len(sorted) == 1 {
		return sorted[0]
	}
	pos := (p / 100) * float64(len(sorted)-1)
	lo := int(pos)
	if lo >= len(sorted)-1 {
		return sorted[len(sorted)-1]
	}
	frac := pos - float64(lo)
	return sorted[lo] + frac*(sorted[lo+1]-sorted[lo])
}

// sseLock 让并发 worker 能安全地往同一个 SSE 响应写。
type sseLock struct {
	mu sync.Mutex
	sw *sseWriter
}

func (s *sseLock) send(ev string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sw.send(ev, v)
}

// handleEpRun: GET /api/endpoints/run?lines=1,2,3&conc=16&count=2&mode=both&vendor=aws,oracle&limit=0
// 全程 SSE，事件：meta / resolve / line_start / progress / result / line_done / note / done / error
// epRunning 保证同一时刻只有一个批量测试在跑 —— 多条请求会互相改钉线出口，结果全错。
var epRunning int32

func handleEpRun(w http.ResponseWriter, r *http.Request) {
	if !atomic.CompareAndSwapInt32(&epRunning, 0, 1) {
		writeJSON(w, 409, map[string]string{"error": "已有一个端点测试在跑（它会切换钉线出口），等它结束再开"})
		return
	}
	defer atomic.StoreInt32(&epRunning, 0)
	if !tryExitGate("端点逐线测试") {
		holder, _ := exitGateBusy()
		writeJSON(w, 409, map[string]string{"error": holder + " 正在用线(会切换钉线出口), 等它结束再开"})
		return
	}
	defer releaseExitGate()
	cat, _ := loadEpCatalog()
	if len(cat.Endpoints) == 0 {
		http.Error(w, "端点目录未内嵌", 500)
		return
	}
	q := r.URL.Query()

	// 线路
	lines := []string{"1", "2", "3"}
	if v := strings.TrimSpace(q.Get("lines")); v != "" {
		lines = nil
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p == "1" || p == "2" || p == "3" {
				lines = append(lines, p)
			}
		}
		if len(lines) == 0 {
			lines = []string{"1", "2", "3"}
		}
	}

	conc, _ := strconv.Atoi(q.Get("conc"))
	if conc <= 0 || conc > 32 {
		conc = 16
	}
	count, _ := strconv.Atoi(q.Get("count"))
	if count <= 0 || count > 5 {
		count = 2
	}
	mode := q.Get("mode")
	if mode != "icmp" && mode != "tcp" {
		mode = "both"
	}
	fam := famOf(q)

	// 厂商 / 数量过滤
	epSel := cat.Endpoints
	if v := strings.TrimSpace(q.Get("vendor")); v != "" {
		keep := map[string]bool{}
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				keep[p] = true
			}
		}
		var f []EpEndpoint
		for _, e := range epSel {
			if keep[e.Vendor] {
				f = append(f, e)
			}
		}
		epSel = f
	}
	// 纯 v6 检查点在 v4 模式下没有 A 记录（api6.ipify.org / v6.ident.me / ipv6-check-perf.radar.cloudflare.com），
	// 直接剔除，免得每次都报 3 个「无记录」；反之 v6 模式下剔除没有 v6 主机的端点。
	if fam == 4 {
		var f []EpEndpoint
		for _, e := range epSel {
			if e.Fam != "6" {
				f = append(f, e)
			}
		}
		epSel = f
	} else {
		var f []EpEndpoint
		for _, e := range epSel {
			if e.Host6 != "" {
				f = append(f, e)
			}
		}
		epSel = f
	}
	// 自定义端点：extra=vps.example.com 或 extra=vps:8443（多个用逗号），跟各厂商放一起比
	if v := strings.TrimSpace(q.Get("extra")); v != "" {
		n := 0
		for _, raw := range strings.Split(v, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			raw = strings.TrimPrefix(strings.TrimPrefix(raw, "https://"), "http://")
			raw = strings.TrimSuffix(raw, "/")
			host, port := raw, 443
			if h, ps, err := net.SplitHostPort(raw); err == nil {
				if pv, e2 := strconv.Atoi(ps); e2 == nil && pv > 0 && pv < 65536 {
					host, port = h, pv
				}
			}
			if host == "" {
				continue
			}
			n++
			epSel = append(epSel, EpEndpoint{
				ID: "custom:" + host, Vendor: "custom", VendorName: "自定义",
				Region: "自定义端点", Method: "TCP", Host: host, Path: "/",
				Fam: "4", Port: port,
			})
		}
		_ = n
	}
	if lim, _ := strconv.Atoi(q.Get("limit")); lim > 0 && lim < len(epSel) {
		epSel = epSel[:lim]
	}
	if len(epSel) == 0 {
		http.Error(w, "过滤后没有端点", 400)
		return
	}

	s, ok := sseStart(w)
	if !ok {
		return
	}
	sw := &sseLock{sw: &sseWriter{w: w, f: s}}
	ctx := r.Context()

	if fam == 6 && localV6Addr() == "" {
		sw.send("error", map[string]string{"error": "容器没有全局 IPv6 地址，无法测 v6"})
		return
	}

	sw.send("meta", map[string]any{
		"total": len(epSel), "lines": lines, "mode": mode, "fam": fam,
		"conc": conc, "count": count, "verified": cat.Verified, "source": cat.Source,
		"custom": len(epSel) - len(cat.Endpoints),
	})

	// ---- 阶段一：解析（三线共用同一批真 IP）----
	type hostIP struct {
		ip  string
		err string
	}
	ipmap := map[string]hostIP{}
	var ipMu sync.Mutex
	sem := make(chan struct{}, 6)   // ★ 解析并发压到 6：24 会触发 doh.pub 限流（返回 HTML）
	var wg sync.WaitGroup
	hosts := map[string]bool{}
	for _, e := range epSel {
		h := e.Host
		if fam == 6 && e.Host6 != "" {
			h = e.Host6
		}
		if h != "" {
			hosts[h] = true
		}
	}
	total := len(hosts)
	var dones int64
	var dMu sync.Mutex
	for h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			time.Sleep(time.Duration(len(h)%7) * 25 * time.Millisecond) // 抖动，避开限流窗口
			ip, errMsg := epResolve(ctx, h, fam)
			ipMu.Lock()
			if ip == "" {
				ipmap[h] = hostIP{err: errMsg}
			} else {
				ipmap[h] = hostIP{ip: ip}
			}
			ipMu.Unlock()
			dMu.Lock()
			dones++
			d := dones
			dMu.Unlock()
			if d%25 == 0 || int(d) == total {
				sw.send("resolve", map[string]any{"done": d, "total": total})
			}
		}(h)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	sw.send("resolve", map[string]any{"done": dones, "total": total})

	// ---- 阶段二：逐条线跑 ----
	prev := getExit()
	defer func() {
		if err := setExit(prev); err == nil {
			sw.send("note", map[string]string{"msg": "已恢复原出口: " + exitLabel(prev)})
		}
	}()

	started := time.Now()
	for _, wan := range lines {
		if ctx.Err() != nil {
			return
		}
		if err := setExit(wan); err != nil {
			sw.send("line_start", map[string]any{"wan": wan, "error": err.Error()})
			continue
		}
		time.Sleep(1500 * time.Millisecond) // 等 conntrack / 路由 / DNS 缓存切换
		sw.send("line_start", map[string]any{"wan": wan, "label": exitLabel(wan)})

		var idx int64
		var iMu sync.Mutex
		wg2 := sync.WaitGroup{}
		sem2 := make(chan struct{}, conc)
		for _, e := range epSel {
			wg2.Add(1)
			go func(e EpEndpoint) {
				defer wg2.Done()
				select {
				case sem2 <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem2 }()

				h := e.Host
				if fam == 6 && e.Host6 != "" {
					h = e.Host6
				}
				ipMu.Lock()
				hi, okIP := ipmap[h]
				ipMu.Unlock()
				res := epResult{ID: e.ID, Wan: wan, IP: hi.ip}
				if !okIP || hi.ip == "" {
					res.Err = hi.err
					if res.Err == "" {
						res.Err = "解析失败"
					}
					sw.send("result", res)
					return
				}
				probeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
				defer cancel()
				port := 443
				if e.Port > 0 {
					port = e.Port
				}
				res.Port = port
				if mode == "both" || mode == "tcp" {
					sum, probes := TCPing(probeCtx, hi.ip, port, count, 150, fam)
					rtts := make([]float64, 0, len(probes))
					for _, pr := range probes {
						if pr.Loss {
							rtts = append(rtts, 0)
						} else {
							rtts = append(rtts, pr.Ms)
						}
					}
					res.Tcp = statsFromSamples(count, rtts, sum)
				}
				if (mode == "both" || mode == "icmp") && ctx.Err() == nil {
					sum, samples, _ := Ping(probeCtx, hi.ip, count, 150, fam)
					rtts := make([]float64, 0, len(samples))
					for _, s := range samples {
						if s.Loss {
							rtts = append(rtts, 0)
						} else {
							rtts = append(rtts, s.RTT)
						}
					}
					res.Icmp = statsFromSamples(count, rtts, sum)
				}
				sw.send("result", res)

				iMu.Lock()
				idx++
				n := idx
				iMu.Unlock()
				if n%20 == 0 || int(n) == len(epSel) {
					sw.send("progress", map[string]any{"wan": wan, "done": n, "total": len(epSel)})
				}
			}(e)
		}
		wg2.Wait()
		sw.send("line_done", map[string]any{"wan": wan, "label": exitLabel(wan), "done": idx})
	}
	unresolved := 0
	ipMu.Lock()
	for h := range hosts {
		if hi := ipmap[h]; hi.ip == "" {
			unresolved++
		}
	}
	ipMu.Unlock()
	sw.send("done", map[string]any{
		"seconds":    int(time.Since(started).Seconds()),
		"endpoints":  len(epSel),
		"lines":      len(lines),
		"hosts":      len(hosts),
		"unresolved": unresolved,
	})
}

// handleEpCatalogStats: 目录概览（厂商计数）——前端首屏用，避免重复解析大 JSON。
func handleEpCatalogStats(w http.ResponseWriter, r *http.Request) {
	cat, _ := loadEpCatalog()
	type vc struct {
		Key   string `json:"key"`
		Name  string `json:"name"`
		Count int    `json:"count"`
		Tier  string `json:"tier"`
	}
	cnt := map[string]int{}
	for _, e := range cat.Endpoints {
		cnt[e.Vendor]++
	}
	var list []vc
	for k := range cat.Vendors {
		name := k
		tier := ""
		var meta struct {
			Name string `json:"name"`
			Tier string `json:"tier"`
		}
		if err := json.Unmarshal(cat.Vendors[k], &meta); err == nil {
			if meta.Name != "" {
				name = meta.Name
			}
			tier = meta.Tier
		}
		list = append(list, vc{Key: k, Name: name, Count: cnt[k], Tier: tier})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Count > list[j].Count })
	writeJSON(w, 200, map[string]any{
		"verified": cat.Verified, "source": cat.Source,
		"endpoints": len(cat.Endpoints), "vendors": list,
		"running": atomic.LoadInt32(&epRunning) == 1,
	})
}

var _ = fmt.Sprintf // 保留 fmt 以备调试
