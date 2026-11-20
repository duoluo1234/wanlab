package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static/index.html
var staticFS embed.FS

//go:embed static/manifest.webmanifest static/icon-192.png static/icon-512.png static/apple-touch-icon.png static/icon.svg
var appFS embed.FS

func serveAppAsset(name, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := appFS.ReadFile("static/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(b)
	}
}

// indexPageRaw/indexPageGz/indexETag 首页在启动时预读+预压缩:
// 页面 128KB, gzip 后约四分之一, 手机打开明显更快; ETag 让重复打开走 304,
// 内容随二进制走, 改版后哈希自动变化、缓存自动失效。
var indexPageRaw, indexPageGz, indexETag = func() ([]byte, []byte, string) {
	b, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		return nil, nil, ""
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	zw.Write(b)
	zw.Close()
	sum := sha256.Sum256(b)
	return b, buf.Bytes(), `"` + hex.EncodeToString(sum[:8]) + `"`
}()

// Line 一条 WAN 线路的定义: id 固定 wan1/wan2/wan3(与 ROS 路由标记 to-wanN 对应),
// label 是面板上的显示名(自定, 如运营商名), pppoe_iface 是 ROS 上的 pppoe-client 名。
type Line struct {
	ID            string  `json:"id"`
	Label         string  `json:"label"`
	PPPoEiface    string  `json:"pppoe_iface"`
	BandwidthMbps float64 `json:"bandwidth_mbps,omitempty"` // 该线理论带宽, 聚合分担/限速按各线此值占比派生; <=0 按 1000
}

type Config struct {
	Listen        string         `json:"listen"`
	ROSBase       string         `json:"ros_base"`
	ROSHost       string         `json:"ros_host"` // SNMP 目标(IP)
	ROSUser       string         `json:"ros_user"`
	ROSPass       string         `json:"ros_pass"`
	SNMPCommunity string         `json:"snmp_community"` // SNMPv2c 只读团体名(仅本机 IP 可用)
	IfIndex       map[string]int `json:"if_index"`       // wan1/wan2/wan3 -> ROS ifIndex(SNMP)
	FleetKey      string         `json:"fleet_key"`
	Nodes         []Node         `json:"nodes"`
	Lines         []Line         `json:"lines"` // 线路定义(id/label/pppoe_iface); 空则用通用默认
	// FleetDomainSuffix 机队域名后缀(如 ".example.com"): nodesync 页用它把
	// node-sync 表里的域名条目关联到机队节点(key = 去后缀的主机名); 空 = 不启用该派生。
	FleetDomainSuffix string `json:"fleet_domain_suffix"`
	// LanCIDR 本地局域网段: 钉线/聚合规则用它排除内网目标, NAT 新增用它校验目标 IP。
	LanCIDR string `json:"lan_cidr"`
	// OpenClash / mihomo 控制 API(用于读取真实分流链路, 见 split_mihomo.go); 空 = 不启用
	MihomoAPI    string `json:"mihomo_api"`
	MihomoSecret string `json:"mihomo_secret"`
	// Mac 直连开关(macdirect.go): 三项都配齐才启用, 缺任一项该功能在 API 层关闭。
	MacLeaseMAC   string `json:"mac_lease_mac"`   // 目标设备的网卡 MAC(DHCP 静态租约按它找)
	MacProxyAddr  string `json:"mac_proxy_addr"`  // 代理模式地址
	MacDirectAddr string `json:"mac_direct_addr"` // 直连模式地址(mangle 里需有对应豁免规则)
}

// lineDefs 返回生效的线路定义: 配置优先; 无配置时回退为通用三线
// (标签 WAN1/WAN2/WAN3, 接口名 pppoe-wan1/2/3)。
func lineDefs() []Line {
	if len(cfg.Lines) > 0 {
		return cfg.Lines
	}
	return []Line{
		{ID: "wan1", Label: "WAN1", PPPoEiface: "pppoe-wan1"},
		{ID: "wan2", Label: "WAN2", PPPoEiface: "pppoe-wan2"},
		{ID: "wan3", Label: "WAN3", PPPoEiface: "pppoe-wan3"},
	}
}

// lineIDs 返回配置中各线路的 id(按配置顺序); 聚合等按线遍历处统一用它, 不写死 wan1..3。
func lineIDs() []string {
	defs := lineDefs()
	ids := make([]string, len(defs))
	for i, l := range defs {
		ids[i] = l.ID
	}
	return ids
}

// lineByIdx 按下标(0 起)取线路定义。
func lineByIdx(i int) (Line, bool) {
	defs := lineDefs()
	if i < 0 || i >= len(defs) {
		return Line{}, false
	}
	return defs[i], true
}

// lineLabelIdx 第 i 条线的显示标签(取不到时回退 WAN<n>)。
func lineLabelIdx(i int) string {
	if l, ok := lineByIdx(i); ok && l.Label != "" {
		return l.Label
	}
	return fmt.Sprintf("WAN%d", i+1)
}

// lanCIDR 生效的局域网段(默认 192.168.0.0/24)。
func lanCIDR() string {
	if cfg.LanCIDR != "" {
		return cfg.LanCIDR
	}
	return "192.168.0.0/24"
}

// iperf 服务端空闲自动关闭: 测完不在公网 VPS 上长期留着 iperf3 + 5201 放行
var (
	iperfIdleMu    sync.Mutex
	iperfIdleTimer *time.Timer
)

// scheduleIperfStop 每轮测完重置空闲计时器; 120s 内没有新测试就关掉节点上的服务端并收回端口。
func scheduleIperfStop(n Node) {
	iperfIdleMu.Lock()
	defer iperfIdleMu.Unlock()
	if iperfIdleTimer != nil {
		iperfIdleTimer.Stop()
	}
	iperfIdleTimer = time.AfterFunc(120*time.Second, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		log.Printf("iperf 空闲 120s, 自动关闭 %s 的服务端", n.Key)
		IperfStop(ctx, n)
	})
}

// cancelIperfStop 手动关闭服务端时取消待执行的自动关闭。
func cancelIperfStop() {
	iperfIdleMu.Lock()
	defer iperfIdleMu.Unlock()
	if iperfIdleTimer != nil {
		iperfIdleTimer.Stop()
		iperfIdleTimer = nil
	}
}

var (
	cfg     Config
	ros     *Ros
	myIP    string
	pinID   string
	pinMu   sync.Mutex // 切出口/建规则串行化
	curExit = "off"    // "1"/"2"/"3"/"off"
	exitMu  sync.RWMutex
)

func loadConfig() Config {
	c := Config{
		Listen:        "0.0.0.0:8688",
		ROSBase:       "https://192.168.0.1",
		ROSHost:       "192.168.0.1",
		ROSUser:       "admin",
		ROSPass:       "",
		SNMPCommunity: "wanlab",
		IfIndex:       map[string]int{"wan1": 10, "wan2": 9, "wan3": 8},
		FleetKey:      "/etc/wanlab/fleet_key",
		Nodes: []Node{
			{Key: "node1", Label: "node1 示例节点", IP: "203.0.113.10"},
			{Key: "node2", Label: "node2 示例节点", IP: "203.0.113.20"},
		},
	}
	if b, err := os.ReadFile("/etc/wanlab/config.json"); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

func nodeByKey(k string) (Node, bool) {
	for _, n := range cfg.Nodes {
		if n.Key == k {
			return n, true
		}
	}
	return Node{}, false
}

// ---------- 出口切换 ----------

func getExit() string {
	exitMu.RLock()
	defer exitMu.RUnlock()
	return curExit
}

// ---- 切线独占闸 (2026-11-14 审计修) ----
// 会连续切换钉线出口的长任务 (体检/聚合/端点/对比/自定义 iperf/新节点验证) 先占闸再跑:
// 它们都是「存 prev → 逐线切 → defer 恢复」的套路, 两个重叠就会互相污染 prev,
// 收尾把对方的线还原掉。单个 setExit 由 pinMu 串行, 这里管的是整段任务。
var exitGateMu sync.Mutex
var exitGateName string

func tryExitGate(name string) bool {
	exitGateMu.Lock()
	defer exitGateMu.Unlock()
	if exitGateName != "" {
		return false
	}
	exitGateName = name
	return true
}

func releaseExitGate() {
	exitGateMu.Lock()
	exitGateName = ""
	exitGateMu.Unlock()
}

func exitGateBusy() (string, bool) {
	exitGateMu.Lock()
	defer exitGateMu.Unlock()
	return exitGateName, exitGateName != ""
}

func setExit(wan string) error {
	if wan != "1" && wan != "2" && wan != "3" && wan != "off" && wan != "v6" && wan != "v6u" {
		return fmt.Errorf("非法出口: %s", wan)
	}
	pinMu.Lock()
	defer pinMu.Unlock()

	// v6 模式: 关 v4 钉线, 打开对应线的 v6 直连规则(m=第一线 / u=第二线)
	if wan == "v6" || wan == "v6u" {
		line, other := "m", "u"
		name := lineLabelIdx(0)
		if wan == "v6u" {
			line, other, name = "u", "m", lineLabelIdx(1)
		}
		addr := localV6Addr()
		if addr == "" {
			return fmt.Errorf("容器没有全局 IPv6 地址")
		}
		if err := ros.EnsureV6Rules(line, addr, true); err != nil {
			return err
		}
		if err := ros.EnsureV6Rules(other, addr, false); err != nil {
			return fmt.Errorf("停用另一条 v6 线规则失败(可能两条 v6 规则同时开着): %v", err)
		}
		if pinID == "" {
			if r, err := ros.FindPinRule(myIP); err == nil && r != nil {
				pinID = r.ID
			}
		}
		if pinID != "" {
			if err := ros.PatchPinRule(pinID, map[string]any{"disabled": "yes"}); err != nil {
				return err
			}
		}
		runCmd(context.Background(), "ip", "route", "flush", "cache")
		exitMu.Lock()
		curExit = wan
		exitMu.Unlock()
		log.Printf("出口切换 -> %s(IPv6 直连走%s, %s)", wan, name, addr)
		return nil
	}
	// 其它模式: 先关掉 v6 直连规则; 关不掉就别往下走, 免得 v4 钉了新线、v6 还留在旧线
	if err := ros.DisableAllV6Rules(); err != nil {
		return fmt.Errorf("关闭 v6 直连规则失败: %v", err)
	}
	if pinID == "" {
		r, err := ros.FindPinRule(myIP)
		if err != nil {
			return err
		}
		if r != nil {
			pinID = r.ID
		}
	}
	if pinID == "" {
		mark := "to-wan1"
		if wan == "2" {
			mark = "to-wan2"
		} else if wan == "3" {
			mark = "to-wan3"
		}
		r, err := ros.CreatePinRule(myIP, mark, wan == "off")
		if err != nil {
			return err
		}
		pinID = r.ID
	} else {
		fields := map[string]any{}
		if wan == "off" {
			fields["disabled"] = "yes"
		} else {
			fields["disabled"] = "no"
			fields["new-routing-mark"] = "to-wan" + wan
		}
		if err := ros.PatchPinRule(pinID, fields); err != nil {
			return err
		}
	}
	// 清路由缓存, 让已在途的连接也换线
	if _, err := runCmd(context.Background(), "ip", "route", "flush", "cache"); err != nil {
		log.Printf("flush cache: %v", err)
	}
	exitMu.Lock()
	curExit = wan
	exitMu.Unlock()
	log.Printf("出口切换 -> %s (rule %s)", wan, pinID)
	return nil
}

// syncExitFromROS 启动时从 ROS 读取规则真实状态, 避免重启面板后显示与实际不一致。
func syncExitFromROS() {
	// v6 直连: 哪条线的规则是启用的, 出口就是哪张卡(m=第一线/v6, u=第二线/v6u)
	for _, sw := range []struct{ line, exit string }{{"m", "v6"}, {"u", "v6u"}} {
		if r6, err := ros.FindV6RuleByTag(v6Lines()[sw.line].tag); err == nil && r6 != nil && r6.Disabled != "true" {
			curExit = sw.exit
			if r, err := ros.FindPinRule(myIP); err == nil && r != nil {
				pinID = r.ID
			}
			// 容器重建后 eth0 的 ULA 会跟着 MAC 变, 规则里的 src 就成了死地址(静默不生效)。
			// 启动时对一次, 另有一个 +12s 的延迟复查(容器刚起来时 SLAAC 地址可能还没到)。
			reconcileV6Src()
			return
		}
	}
	r, err := ros.FindPinRule(myIP)
	if err != nil {
		log.Printf("读取钉线规则失败: %v", err)
		return
	}
	if r == nil {
		curExit = "off"
		return
	}
	pinID = r.ID
	if r.Disabled == "true" {
		curExit = "off"
		return
	}
	switch r.Mark {
	case "to-wan1":
		curExit = "1"
	case "to-wan2":
		curExit = "2"
	case "to-wan3":
		curExit = "3"
	default:
		curExit = "off"
	}
}

// reconcileV6Src 对一次 v6 钉线规则的 src-address: 与本机当前实际源地址不一致
// (容器重建/重连后 MAC 变、SLAAC 地址跟着变)就按当前地址重写, 否则规则看着在、
// 实际匹配不到包, 钉线静默失效。幂等, 可反复调用。
func reconcileV6Src() {
	addr := localV6Addr()
	if addr == "" {
		return
	}
	for _, line := range []string{"m", "u"} {
		r6, err := ros.FindV6RuleByTag(v6Lines()[line].tag)
		if err != nil || r6 == nil || r6.Disabled == "true" {
			continue
		}
		if r6.SrcAddress == addr+"/128" {
			return
		}
		other := "u"
		if line == "u" {
			other = "m"
		}
		log.Printf("v6 钉线源地址已变(%s -> %s), 同步规则", r6.SrcAddress, addr)
		if err := ros.EnsureV6Rules(line, addr, true); err != nil {
			log.Printf("同步 v6 钉线失败: %v", err)
		}
		ros.EnsureV6Rules(other, addr, false)
		return
	}
}

// ---------- HTTP 基础设施 ----------
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func sseStart(w http.ResponseWriter) (http.Flusher, bool) {
	f, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return nil, false
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	fmt.Fprint(w, ": ok\n\n")
	f.Flush()
	return f, true
}

type sseWriter struct {
	w http.ResponseWriter
	f http.Flusher
}

func (s *sseWriter) send(event string, payload any) {
	b, _ := json.Marshal(payload)
	fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", event, b)
	s.f.Flush()
}

func (s *sseWriter) note(msg string) { s.send("note", map[string]string{"msg": msg}) }

// resolveTarget 把域名解析成真 IP(默认 223.5.5.5), 返回首个 A 记录。
func resolveTarget(ctx context.Context, target, resolver string, fam int) (string, DNSResult) {
	if ip := parseIPAny(target); ip != "" {
		return ip, DNSResult{Name: target, Resolver: "(IP 直连)", Records: []DNSRecord{}}
	}
	typ := "A"
	if fam == 6 {
		typ = "AAAA"
	}
	r := Resolve(ctx, target, typ, resolver)
	for _, rec := range r.Records {
		if (fam == 6 && rec.Type == "AAAA") || (fam != 6 && rec.Type == "A") {
			return rec.Value, r
		}
	}
	if len(r.Records) > 0 {
		return r.Records[0].Value, r
	}
	return "", r
}

// famOf 读 ?fam=4|6, 默认 4。
// famOf 决定探测用的地址族。
// 显式 fam=4/6 优先；否则如果 target 本身是 IPv6 字面量，自动按 v6 处理
// （否则 tcp4 拨号到 v6 目标必然 100% 丢包，测试台会误报节点全挂）。
func famOf(q map[string][]string) int {
	if v, ok := q["fam"]; ok && len(v) > 0 {
		switch v[0] {
		case "6", "6u", "6d":
			return 6
		case "4":
			return 4
		}
	}
	if v, ok := q["target"]; ok && len(v) > 0 {
		t := strings.TrimSpace(v[0])
		if strings.HasPrefix(t, "[") {
			t = strings.TrimPrefix(t, "[")
			if i := strings.Index(t, "]"); i >= 0 {
				t = t[:i]
			}
		} else if strings.Count(t, ":") >= 2 {
			// 去掉可能的 :port 后缀，例如 2406:3003::1:6000
			if i := strings.LastIndex(t, "]"); i >= 0 {
				t = t[:i]
			}
		}
		if ip := net.ParseIP(t); ip != nil && ip.To4() == nil {
			return 6
		}
	}
	return 4
}

// parseIPAny 接受 v4/v6(可带方括号或 :port), 返回规范 IP 字面量。
func parseIPAny(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}

func parseIPLoose(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// 支持 1.1.1.1 / [2400::1] / 域名: 端口
	if strings.Count(s, ":") == 1 {
		if h, _, ok := strings.Cut(s, ":"); ok {
			s = h
		}
	}
	s = strings.Trim(s, "[]")
	if ip := parseIP(s); ip != "" {
		return ip
	}
	return ""
}

// ---------- handlers ----------

func handleStatus(w http.ResponseWriter, r *http.Request) {
	lines, err := ros.Lines()
	resp := map[string]any{
		"ip":      myIP,
		"exit":    getExit(),
		"ros":     cfg.ROSBase,
		"version": ros.RosVersion(),
		"nodes":   cfg.Nodes,
		"time":    time.Now().Format("2006-01-02 15:04:05"),
	}
	if err != nil {
		resp["ros_error"] = err.Error()
	}
	resp["lines"] = lines
	if r, err := ros.FindPinRule(myIP); err == nil && r != nil {
		resp["pin"] = map[string]any{"id": r.ID, "mark": r.Mark, "disabled": r.Disabled == "true", "packets": r.Packets}
	}
	v6 := map[string]any{"addr": localV6Addr(), "enabled": false}
	for _, sw := range []struct{ line, exit string }{{"m", "v6"}, {"u", "v6u"}} {
		if r6, err := ros.FindV6RuleByTag(v6Lines()[sw.line].tag); err == nil && r6 != nil {
			v6["rule_id"] = r6.ID
			if r6.Disabled != "true" {
				v6["enabled"], v6["line"], v6["exit"] = true, sw.line, sw.exit
			}
		}
	}
	resp["v6"] = v6
	writeJSON(w, 200, resp)
}

func handleExit(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Wan string `json:"wan"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	if holder, busy := exitGateBusy(); busy {
		writeJSON(w, 409, map[string]string{"error": holder + " 正在用线, 等它结束再手动切"})
		return
	}
	if err := setExit(body.Wan); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "exit": getExit()})
}

func handleResolve(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Resolver string `json:"resolver"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Name == "" {
		writeJSON(w, 400, map[string]string{"error": "缺少 name"})
		return
	}
	if body.Type == "" {
		body.Type = "A"
	}
	if body.Resolver == "" {
		body.Resolver = "223.5.5.5"
	}
	writeJSON(w, 200, Resolve(r.Context(), body.Name, body.Type, body.Resolver))
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := strings.TrimSpace(q.Get("target"))
	if target == "" {
		http.Error(w, "缺少 target", 400)
		return
	}
	count, _ := strconv.Atoi(q.Get("count"))
	if count <= 0 || count > 100 {
		count = 5
	}
	interval, _ := strconv.Atoi(q.Get("interval"))
	fam := famOf(q)
	resolver := q.Get("resolver")
	if resolver == "" {
		resolver = "doh.pub"
	}
	s, ok := sseStart(w)
	if !ok {
		return
	}
	sw := &sseWriter{w: w, f: s}
	ctx := r.Context()
	isIP := parseIPAny(target) != ""
	if !isIP {
		sw.note("解析 " + target + " (via " + resolver + ")")
	}
	ip, dr := resolveTarget(ctx, target, resolver, fam)
	sw.send("resolve", dr)
	if ip == "" {
		sw.send("error", map[string]string{"error": "解析失败, 无法 ping"})
		return
	}
	sw.note("出口=" + exitLabel(getExit()) + " 目标真IP=" + ip)
	sm, samples, err := Ping(ctx, ip, count, interval, fam)
	sm.IP = ip
	sm.Resolve = dr.Ms
	sm.FakeIP = dr.FakeIP
	for _, rec := range dr.Records {
		sm.Resolved = append(sm.Resolved, rec.Value)
	}
	for _, s := range samples {
		sw.send("packet", s)
	}
	if err != nil && len(samples) == 0 {
		sw.send("error", map[string]string{"error": oneline(err.Error())})
		return
	}
	sw.send("summary", sm)
}

// handleTCPing: ICMP 被墙时用 TCP 握手测延迟(走当前钉线出口)。
func handleTCPing(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := strings.TrimSpace(q.Get("target"))
	if target == "" {
		http.Error(w, "缺少 target", 400)
		return
	}
	port, _ := strconv.Atoi(q.Get("port"))
	if port <= 0 {
		port = 443
	}
	count, _ := strconv.Atoi(q.Get("count"))
	if count <= 0 || count > 100 {
		count = 5
	}
	interval, _ := strconv.Atoi(q.Get("interval"))
	fam := famOf(q)
	resolver := q.Get("resolver")
	if resolver == "" {
		resolver = "doh.pub"
	}
	s, ok := sseStart(w)
	if !ok {
		return
	}
	sw := &sseWriter{w: w, f: s}
	ctx := r.Context()
	ip, dr := resolveTarget(ctx, target, resolver, fam)
	sw.send("resolve", dr)
	if ip == "" {
		sw.send("error", map[string]string{"error": "解析失败"})
		return
	}
	sw.note("TCP 握手 · 出口=" + exitLabel(getExit()) + " · " + net.JoinHostPort(ip, strconv.Itoa(port)))
	sm, probes := TCPing(ctx, ip, port, count, interval, fam)
	sm.IP = ip
	sm.Resolve = dr.Ms
	sm.FakeIP = dr.FakeIP
	for _, pr := range probes {
		sw.send("packet", PingSample{Seq: pr.Seq, RTT: pr.Ms, Loss: pr.Loss, Line: "tcp"})
	}
	sw.send("summary", sm)
}

func handleTrace(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := strings.TrimSpace(q.Get("target"))
	if target == "" {
		http.Error(w, "缺少 target", 400)
		return
	}
	maxHops, _ := strconv.Atoi(q.Get("max"))
	if maxHops <= 0 || maxHops > 40 {
		maxHops = 20
	}
	qn, _ := strconv.Atoi(q.Get("q"))
	proto := q.Get("proto")
	if proto != "icmp" && proto != "tcp" {
		proto = "udp"
	}
	resolver := q.Get("resolver")
	if resolver == "" {
		resolver = "doh.pub"
	}
	s, ok := sseStart(w)
	if !ok {
		return
	}
	sw := &sseWriter{w: w, f: s}
	ctx := r.Context()
	fam := famOf(r.URL.Query())
	ip, dr := resolveTarget(ctx, target, resolver, fam)
	sw.send("resolve", dr)
	if ip == "" {
		sw.send("error", map[string]string{"error": "解析失败"})
		return
	}
	sw.note("出口=" + exitLabel(getExit()) + " 目标=" + ip + " · " + strings.ToUpper(proto) + " · 最多 " + strconv.Itoa(maxHops) + " 跳")
	err := Traceroute(ctx, ip, maxHops, qn, proto, fam, func(line string) {
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" {
			return
		}
		if h := parseHop(line); h != nil {
			sw.send("hop", h)
			return
		}
		sw.send("raw", map[string]string{"line": line})
	})
	if err != nil {
		sw.send("error", map[string]string{"error": oneline(err.Error())})
		return
	}
	sw.send("done", map[string]string{"msg": "完成"})
}

func handleExitInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, ExitInfoOf(r.Context(), famOf(r.URL.Query())))
}

// handleCompare: 依次切三条线, 各测 出口IP + ping, 最后恢复原出口。
func handleCompare(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := strings.TrimSpace(q.Get("target"))
	if target == "" {
		target = "1.1.1.1"
	}
	count, _ := strconv.Atoi(q.Get("count"))
	if count <= 0 || count > 20 {
		count = 5
	}
	s, ok := sseStart(w)
	if !ok {
		return
	}
	sw := &sseWriter{w: w, f: s}
	ctx := r.Context()
	if ex := getExit(); ex == "v6" || ex == "v6u" {
		sw.send("error", map[string]string{"error": "IPv6 模式不支持三线对比(先切回某条 v4 线)"})
		return
	}
	if !tryExitGate("三线对比") {
		holder, _ := exitGateBusy()
		sw.send("error", map[string]string{"error": holder + " 正在用线, 等它结束"})
		return
	}
	defer releaseExitGate()
	prev := getExit()
	defer func() {
		if err := setExit(prev); err == nil {
			sw.note("已恢复原出口: " + exitLabel(prev))
		}
	}()
	for _, wan := range []string{"1", "2", "3"} {
		if err := setExit(wan); err != nil {
			sw.send("line", map[string]any{"wan": wan, "error": err.Error()})
			continue
		}
		sw.note("切到 " + exitLabel(wan) + ", 等路由生效…")
		time.Sleep(1500 * time.Millisecond)
		ip, dr := resolveTarget(ctx, target, "doh.pub", 4)
		info := ExitInfoOf(ctx, 4)
		res := map[string]any{"wan": wan, "label": exitLabel(wan), "exit_ip": info.IP, "colo": info.Colo, "loc": info.Loc, "org": info.Org, "target_ip": ip}
		if ip != "" {
			sm, _, err := Ping(ctx, ip, count, 300, 4)
			res["ping"] = sm
			if err != nil && sm.Recv == 0 {
				res["ping_error"] = oneline(err.Error())
			}
		} else {
			res["error"] = "解析失败: " + dr.Error
		}
		sw.send("line", res)
	}
	sw.send("done", map[string]string{"msg": "完成"})
}

func handleIperf(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Node    string `json:"node"`
		Dir     string `json:"dir"`
		Secs    int    `json:"secs"`
		Streams int    `json:"streams"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	n, ok := nodeByKey(body.Node)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "未知节点"})
		return
	}
	if body.Dir != "down" {
		body.Dir = "up"
	}
	out, err := IperfPrepare(r.Context(), n)
	if err != nil || !strings.Contains(out, "IPERF_UP") {
		writeJSON(w, 500, map[string]string{"error": "节点 iperf3 服务端未就绪: " + oneline(out+" "+errStr(err))})
		return
	}
	res := IperfRun(r.Context(), n, body.Dir, body.Secs, body.Streams)
	scheduleIperfStop(n) // 空闲 120s 自动收端口, 避免公网长期挂着 iperf3
	writeJSON(w, 200, res)
}

func handleIperfCtl(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Node string `json:"node"`
		On   bool   `json:"on"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	n, ok := nodeByKey(body.Node)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "未知节点"})
		return
	}
	if body.On {
		out, err := IperfPrepare(r.Context(), n)
		scheduleIperfStop(n)
		writeJSON(w, 200, map[string]any{"out": oneline(out), "error": errStr(err)})
		return
	}
	cancelIperfStop()
	writeJSON(w, 200, map[string]any{"out": oneline(IperfStop(r.Context(), n))})
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Node    string `json:"node"`
		Threads int    `json:"threads"`
		Secs    int    `json:"secs"`
		Mode    string `json:"mode"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if body.Mode == "" {
		body.Mode = "fleet"
	}
	if body.Mode == "cf" {
		res := HTTPRunMode(r.Context(), Node{Label: "Cloudflare"}, body.Threads, body.Secs, "cf")
		writeJSON(w, 200, res)
		return
	}
	n, ok := nodeByKey(body.Node)
	if !ok {
		writeJSON(w, 400, map[string]string{"error": "未知节点"})
		return
	}
	if out, err := HTTPPrepare(r.Context(), n); err != nil {
		writeJSON(w, 500, map[string]string{"error": "节点准备失败: " + oneline(out) + " " + errStr(err)})
		return
	}
	res := HTTPRunMode(r.Context(), n, body.Threads, body.Secs, "fleet")
	HTTPCleanup(r.Context(), n)
	writeJSON(w, 200, res)
}

func errStr(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}

func exitLabel(wan string) string {
	switch wan {
	case "1", "2", "3":
		i := int(wan[0] - '1')
		if l, ok := lineByIdx(i); ok {
			return l.Label + " " + l.ID
		}
		return "wan" + wan
	case "v6":
		return lineLabelIdx(0) + " IPv6 直连"
	case "v6u":
		return lineLabelIdx(1) + " IPv6 直连"
	default:
		return "旁路由/默认(不钉线)"
	}
}

// recoverMW 防止单个请求的 panic 拖掉连接/进程(面板类服务的保险丝)。
func recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if e := recover(); e != nil {
				log.Printf("panic %s %s: %v", r.Method, r.URL.Path, e)
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func main() {
	cfg = loadConfig()
	ros = NewRos(cfg.ROSBase, cfg.ROSUser, cfg.ROSPass)
	myIP = LocalIP()
	if myIP == "" {
		log.Fatal("拿不到本机 eth0 IPv4")
	}
	log.Printf("本机 %s, ROS %s", myIP, cfg.ROSBase)
	syncExitFromROS()
	// 开机清聚合残留 (2026-11-14 审计修): 上次进程若死在聚合中途, ROS 上会留聚合
	// mangle/限速队列, 让之后的测试流量被分流/限速而不自知。aggCleanup 幂等,
	// 且只认 "WANLAB 三线聚合" 标记, 不误伤其它规则。
	if n := ros.aggCleanup(); n > 0 {
		log.Printf("开机清理: 已删除 %d 条聚合残留规则", n)
	}
	go pingScheduler() // 每小时机队 ping 采样(见 pinghist.go)
	// 容器刚起来时 SLAAC 地址可能还没下发, 12s 后再对一次 v6 钉线源地址
	go func() {
		time.Sleep(12 * time.Second)
		reconcileV6Src()
	}()
	go startRateSampler(context.Background())

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if indexETag != "" {
			w.Header().Set("ETag", indexETag)
			w.Header().Set("Cache-Control", "no-cache")
			if r.Header.Get("If-None-Match") == indexETag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		if indexPageGz != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Vary", "Accept-Encoding")
			w.Write(indexPageGz)
			return
		}
		w.Write(indexPageRaw)
	})
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/wanrate", handleWanRate)
	mux.HandleFunc("/api/asn", handleASN)
	mux.HandleFunc("/api/exit", handleExit)
	mux.HandleFunc("/api/resolve", handleResolve)
	mux.HandleFunc("/api/ping", handlePing)
	mux.HandleFunc("/api/trace", handleTrace)
	mux.HandleFunc("/api/tcping", handleTCPing)
	mux.HandleFunc("/api/exitinfo", handleExitInfo)
	mux.HandleFunc("/api/compare", handleCompare)
	mux.HandleFunc("/api/iperf", handleIperf)
	mux.HandleFunc("/api/iperf/custom", handleIperfCustom)
	mux.HandleFunc("/api/iperf/ctl", handleIperfCtl)
	mux.HandleFunc("/api/http", handleHTTP)
	mux.HandleFunc("/api/agg", handleAgg)
	mux.HandleFunc("/api/fleetcheck", handleFleetCheck)
	mux.HandleFunc("/api/fleetcheck/start", handleFleetCheckStart)
	mux.HandleFunc("/api/fleetcheck/stop", handleFleetCheckStop)
	mux.HandleFunc("/api/pagever", handlePageVer)
	mux.HandleFunc("/manifest.webmanifest", serveAppAsset("manifest.webmanifest", "application/manifest+json"))
	mux.HandleFunc("/icon-192.png", serveAppAsset("icon-192.png", "image/png"))
	mux.HandleFunc("/icon-512.png", serveAppAsset("icon-512.png", "image/png"))
	mux.HandleFunc("/apple-touch-icon.png", serveAppAsset("apple-touch-icon.png", "image/png"))
	mux.HandleFunc("/icon.svg", serveAppAsset("icon.svg", "image/svg+xml"))
	mux.HandleFunc("/api/fleet/add", handleFleetAdd)
	mux.HandleFunc("/api/fleet/add/start", handleFleetAddStart)
	mux.HandleFunc("/api/nodesync", handleNodeSync)
	mux.HandleFunc("/api/nodesync/apply", handleNodeSyncApply)
	mux.HandleFunc("/api/nodesync/latency", handleNodeSyncLatency)
	mux.HandleFunc("/api/pinghist", handlePingHist)
	mux.HandleFunc("/api/nat", handleNatList)
	mux.HandleFunc("/api/nat/add", handleNatAdd)
	mux.HandleFunc("/api/nat/toggle", handleNatToggle)
	mux.HandleFunc("/api/nat/remove", handleNatRemove)
	mux.HandleFunc("/api/pppoe", handlePppoe)
	mux.HandleFunc("/api/pppoe/redial", handlePppoeRedial)
	mux.HandleFunc("/api/pppoe/redial/start", handlePppoeRedialStart)
	mux.HandleFunc("/api/split", handleSplit)
	mux.HandleFunc("/api/macdirect", handleMacDirect)
	// 多云端点延迟矩阵（目录从 m2c.1ms.dog 对齐，见 endpoints.go）
	mux.HandleFunc("/api/endpoints", handleEndpoints)
	mux.HandleFunc("/api/endpoints/stats", handleEpCatalogStats)
	mux.HandleFunc("/api/endpoints/run", handleEpRun)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           recoverMW(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("wanlab 监听 %s", cfg.Listen)
	log.Fatal(srv.ListenAndServe())
}

// parseIP 单独抽出来, 方便 handler/exec 共用。
func parseIP(s string) string {
	if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil && ip.To4() != nil {
		return ip.String()
	}
	return ""
}
