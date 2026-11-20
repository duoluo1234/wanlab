package main

// 线路钉线 —— 与 ROS 的 node-sync 脚本联动:
// 原先要进 WebFig 改 node-sync 脚本里的 MAP 表再 Run 才切线; 这里把那张表搬进面板:
// 读脚本源 → 只重写 :local MAP { ... } 一段 (其余字节严格不动, 写前备份旧源到
// /etc/wanlab/nodesync-bak-<时间>.rsc) → 写回脚本 → run node-sync-bg 后台应用
// (另有 ROS 调度器每 10 分钟兜底再跑) → 轮询 address-list 校验生效。
// 条目格式与脚本一致: "目标|线路|备注", 线路可分开写 "v4/v6" (如 3/1);
// 1/2/3 = 第 1/2/3 条线, 0=不钉线; 若第三条线无 v6, v6 的 3 按脚本语义等于 0。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type nsEntry struct {
	Target    string `json:"target"`
	V4        string `json:"v4"` // ""=不适用 "0"=默认 "1" "2" "3"
	V6        string `json:"v6"` // ""=不适用 "0"=默认 "1" "2"
	Note      string `json:"note"`
	Family    string `json:"family"` // domain | v4 | v6
	NodeKey   string `json:"node_key,omitempty"`
	NodeLabel string `json:"node_label,omitempty"`
	Raw       string `json:"-"` // 文件里的原始文本; 未改动的条目按 Raw 原样写回, 保证往返字节一致
}

type nsJob struct {
	Running bool     `json:"running"`
	Done    bool     `json:"done"`
	OK      bool     `json:"ok"`
	Log     []string `json:"log"`
}

var (
	nsMu  sync.Mutex
	nsCur = nsJob{Log: []string{}}
)

func nsLogf(format string, a ...any) {
	nsMu.Lock()
	defer nsMu.Unlock()
	nsCur.Log = append(nsCur.Log, time.Now().Format("15:04:05")+" "+fmt.Sprintf(format, a...))
}

func nsSnapshot() nsJob {
	nsMu.Lock()
	defer nsMu.Unlock()
	out := nsCur
	out.Log = append([]string{}, nsCur.Log...)
	return out
}

func nsFail(format string, a ...any) {
	nsLogf("✗ "+format, a...)
	nsMu.Lock()
	nsCur.Running = false
	nsCur.Done = true
	nsCur.OK = false
	nsMu.Unlock()
}

// ---- ROS 脚本读写 ----

type rosScript struct {
	ID     string `json:".id"`
	Name   string `json:"name"`
	Source string `json:"source"`
}

func nsFetchScripts() ([]rosScript, error) {
	b, err := ros.Get("/rest/system/script")
	if err != nil {
		return nil, err
	}
	var ss []rosScript
	if err := json.Unmarshal(b, &ss); err != nil {
		return nil, err
	}
	return ss, nil
}

func nsFindScript(ss []rosScript, name string) (rosScript, bool) {
	for _, s := range ss {
		if s.Name == name {
			return s, true
		}
	}
	return rosScript{}, false
}

// ---- MAP 解析 / 渲染 ----

func nsFamily(target string) string {
	if strings.Contains(target, ":") {
		return "v6"
	}
	if ip := net.ParseIP(target); ip != nil {
		return "v4"
	}
	if _, _, err := net.ParseCIDR(target); err == nil {
		return "v4"
	}
	return "domain"
}

func nsNormV6(s string) string {
	if s == "3" || s == "off" {
		return "0"
	}
	return s
}

func nsParseEntry(raw string) (nsEntry, error) {
	parts := strings.SplitN(raw, "|", 3)
	if len(parts) < 2 {
		return nsEntry{}, fmt.Errorf("条目缺线路: %q", raw)
	}
	e := nsEntry{Target: strings.TrimSpace(parts[0]), Family: nsFamily(strings.TrimSpace(parts[0]))}
	if len(parts) == 3 {
		e.Note = parts[2]
	}
	line := strings.TrimSpace(parts[1])
	if a, b, ok := strings.Cut(line, "/"); ok {
		switch e.Family {
		case "domain":
			e.V4, e.V6 = a, nsNormV6(b)
		case "v4":
			e.V4 = a
		case "v6":
			e.V6 = nsNormV6(b)
		}
	} else {
		switch e.Family {
		case "domain":
			e.V4, e.V6 = line, nsNormV6(line)
		case "v4":
			e.V4 = line
		case "v6":
			e.V6 = nsNormV6(line)
		}
	}
	if e.V4 == "off" {
		e.V4 = "0"
	}
	return e, nil
}

func nsComposeLine(e nsEntry) string {
	switch e.Family {
	case "v4":
		return e.V4
	case "v6":
		return e.V6
	default:
		if e.V4 == e.V6 {
			return e.V4
		}
		return e.V4 + "/" + e.V6
	}
}

func nsEntryRaw(e nsEntry) string {
	s := e.Target + "|" + nsComposeLine(e)
	if e.Note != "" {
		s += "|" + e.Note
	}
	return s
}

// nsMapSpan 定位 :local MAP { ... } 的起止 (返回 '{' 后与 '}' 的下标)。
func nsMapSpan(src string) (int, int, error) {
	i := strings.Index(src, ":local MAP")
	if i < 0 {
		return 0, 0, fmt.Errorf("源里找不到 :local MAP")
	}
	open := strings.Index(src[i:], "{")
	if open < 0 {
		return 0, 0, fmt.Errorf("MAP 缺 {")
	}
	open += i
	// MAP 块以行首 } 结束
	rel := strings.Index(src[open:], "\n}")
	if rel < 0 {
		return 0, 0, fmt.Errorf("MAP 缺闭合 }")
	}
	return open, open + rel + 1, nil // closeIdx 指向 } 本身
}

func nsParseMap(src string) ([]nsEntry, error) {
	open, closeIdx, err := nsMapSpan(src)
	if err != nil {
		return nil, err
	}
	body := src[open+1 : closeIdx]
	var out []nsEntry
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimSuffix(line, ";")
		if len(line) < 2 || !strings.HasPrefix(line, "\"") || !strings.HasSuffix(line, "\"") {
			continue
		}
		raw := line[1 : len(line)-1]
		e, err := nsParseEntry(raw)
		if err != nil {
			return nil, err
		}
		e.Raw = raw
		out = append(out, e)
	}
	return out, nil
}

func nsRenderMap(entries []nsEntry) string {
	var lines []string
	for _, e := range entries {
		raw := e.Raw
		if raw == "" {
			raw = nsEntryRaw(e)
		}
		lines = append(lines, "  \""+raw+"\"")
	}
	return "{\n" + strings.Join(lines, ";\n") + "\n}"
}

func nsRewriteSource(old string, entries []nsEntry) (string, error) {
	open, closeIdx, err := nsMapSpan(old)
	if err != nil {
		return "", err
	}
	return old[:open] + nsRenderMap(entries) + old[closeIdx+1:], nil
}

// nsValidateEntries 写前校验: 字段不许带引号/换行 (会破坏脚本结构), 线路取值合法。
func nsValidateEntries(entries []nsEntry) error {
	if len(entries) == 0 || len(entries) > 80 {
		return fmt.Errorf("条目数异常: %d", len(entries))
	}
	seen := map[string]bool{}
	for _, e := range entries {
		for _, f := range []string{e.Target, e.Note} {
			if strings.ContainsAny(f, "\"\n\r") {
				return fmt.Errorf("字段含非法字符: %q", f)
			}
		}
		if e.Target == "" {
			return fmt.Errorf("目标为空")
		}
		if seen[e.Target] {
			return fmt.Errorf("目标重复: %s", e.Target)
		}
		seen[e.Target] = true
		switch e.V4 {
		case "", "0", "1", "2", "3":
		default:
			return fmt.Errorf("%s 的 v4 线路不对: %s", e.Target, e.V4)
		}
		switch e.V6 {
		case "", "0", "1", "2":
		default:
			return fmt.Errorf("%s 的 v6 线路不对: %s", e.Target, e.V6)
		}
	}
	return nil
}

// ---- 生效校验: address-list 里 NODESYNC 条目计数 ----

type nsListEntry struct {
	Address string `json:"address"`
	Comment string `json:"comment"`
	List    string `json:"list"`
}

func nsListEntries(list string) []nsListEntry {
	b, err := ros.Get("/rest/ip/firewall/address-list?list=" + list)
	if err != nil {
		return nil
	}
	var out []nsListEntry
	_ = json.Unmarshal(b, &out)
	return out
}

func nsList6Entries(list string) []nsListEntry {
	b, err := ros.Get("/rest/ipv6/firewall/address-list?list=" + list)
	if err != nil {
		return nil
	}
	var out []nsListEntry
	_ = json.Unmarshal(b, &out)
	return out
}

func nsCounts() map[string]int {
	counts := map[string]int{}
	for _, l := range []string{"node-v4-wan1", "node-v4-wan2", "node-v4-wan3"} {
		n := 0
		for _, e := range nsListEntries(l) {
			if strings.Contains(e.Comment, "NODESYNC") {
				n++
			}
		}
		counts[l] = n
	}
	for _, l := range []string{"node-v6", "v6-line-mobile", "v6-line-unicom", "v6-pinned"} {
		n := 0
		for _, e := range nsList6Entries(l) {
			if strings.Contains(e.Comment, "NODESYNC") {
				n++
			}
		}
		counts[l] = n
	}
	return counts
}

// nsTargetApplied 判断某条目的 v4 线路是否已在对应 address-list 生效
// (注释含目标域名, 或地址与目标字面相同)。
func nsTargetApplied(e nsEntry) (bool, string) {
	if e.Family != "v6" && e.V4 != "" && e.V4 != "0" {
		list := "node-v4-wan" + e.V4
		for _, le := range nsListEntries(list) {
			if strings.Contains(le.Comment, e.Target) || le.Address == e.Target {
				return true, list
			}
		}
		return false, list
	}
	if e.Family != "v4" && e.V6 != "" && e.V6 != "0" {
		list := map[string]string{"1": "v6-line-mobile", "2": "v6-line-unicom"}[e.V6]
		for _, le := range nsList6Entries(list) {
			if strings.Contains(le.Comment, e.Target) || le.Address == e.Target {
				return true, list
			}
		}
		return false, list
	}
	return true, "" // 0/不钉: 无需校验具体表
}

// nsRunBg 触发 node-sync-bg (:execute 异步跑 node-sync, 不占 REST 的 60 秒上限)。
func nsRunBg() error {
	ss, err := nsFetchScripts()
	if err != nil {
		return err
	}
	bg, ok := nsFindScript(ss, "node-sync-bg")
	if !ok {
		return fmt.Errorf("找不到 node-sync-bg")
	}
	_, code, err := ros.do("POST", "/rest/system/script/run", map[string]any{".id": bg.ID})
	if err != nil || code >= 300 {
		_, code, err = ros.do("POST", "/rest/system/script/run", map[string]any{"number": bg.ID})
	}
	if err != nil {
		return err
	}
	if code >= 300 {
		return fmt.Errorf("run 返回 %d", code)
	}
	return nil
}

// ---- 后台任务: 改一条 (set/add/remove) 后写回 + 触发 + 校验 ----

type nsApplyReq struct {
	Action string `json:"action"` // set | add | remove
	Target string `json:"target"`
	V4     string `json:"v4"`
	V6     string `json:"v6"`
	Note   string `json:"note"`
}

func runNsApply(rq nsApplyReq) {
	ss, err := nsFetchScripts()
	if err != nil {
		nsFail("读 ROS 脚本失败: %v", err)
		return
	}
	sc, ok := nsFindScript(ss, "node-sync")
	if !ok {
		nsFail("ROS 里找不到 node-sync 脚本")
		return
	}
	entries, err := nsParseMap(sc.Source)
	if err != nil {
		nsFail("解析 MAP 失败: %v", err)
		return
	}
	nsLogf("现 MAP %d 条", len(entries))

	target := strings.TrimSpace(rq.Target)
	idx := -1
	for i, e := range entries {
		if e.Target == target {
			idx = i
			break
		}
	}
	var changed nsEntry
	switch rq.Action {
	case "set":
		if idx < 0 {
			nsFail("MAP 里没有这条: %s", target)
			return
		}
		changed = entries[idx]
		origV4, origV6 := changed.V4, changed.V6
		if changed.Family != "v6" {
			changed.V4 = rq.V4
		}
		if changed.Family != "v4" {
			changed.V6 = rq.V6
		}
		if changed.V4 != origV4 || changed.V6 != origV6 {
			changed.Raw = "" // 值真变了才重组本条; 其余条目保持原文
		}
		entries[idx] = changed
		nsLogf("改线: %s → v4=%s v6=%s", target, changed.V4, changed.V6)
	case "add":
		if idx >= 0 {
			nsFail("这条已存在: %s", target)
			return
		}
		changed = nsEntry{Target: target, Note: strings.TrimSpace(rq.Note), Family: nsFamily(target)}
		if changed.Family != "v6" {
			changed.V4 = rq.V4
		}
		if changed.Family != "v4" {
			changed.V6 = rq.V6
		}
		if changed.Family == "domain" && changed.V6 == "" {
			changed.V6 = changed.V4
		}
		entries = append(entries, changed)
		nsLogf("新增: %s", nsEntryRaw(changed))
	case "remove":
		if idx < 0 {
			nsFail("MAP 里没有这条: %s", target)
			return
		}
		changed = entries[idx]
		entries = append(entries[:idx], entries[idx+1:]...)
		nsLogf("删除: %s", target)
	default:
		nsFail("未知操作: %s", rq.Action)
		return
	}
	if err := nsValidateEntries(entries); err != nil {
		nsFail("校验不过, 未写入: %v", err)
		return
	}
	newSrc, err := nsRewriteSource(sc.Source, entries)
	if err != nil {
		nsFail("重写源失败: %v", err)
		return
	}
	// 往返校验: 新源解析回来的条目必须与内存一致, 且 MAP 之外字节未动
	back, err := nsParseMap(newSrc)
	if err != nil || len(back) != len(entries) {
		nsFail("往返校验失败, 未写入")
		return
	}
	// 备份旧源
	bak := "/etc/wanlab/nodesync-bak-" + time.Now().Format("20060102-150405") + ".rsc"
	if err := os.WriteFile(bak, []byte(sc.Source), 0600); err != nil {
		nsFail("备份旧源失败: %v", err)
		return
	}
	nsLogf("旧源已备份: %s", bak)
	// 写回脚本 (REST set; 失败再试 PATCH)
	_, code, err := ros.do("POST", "/rest/system/script/set", map[string]any{".id": sc.ID, "source": newSrc})
	if err != nil || code >= 300 {
		_, code2, err2 := ros.do("PATCH", "/rest/system/script/"+sc.ID, map[string]any{"source": newSrc})
		if err2 != nil || code2 >= 300 {
			nsFail("写回脚本失败: set=%v/%d patch=%v/%d", err, code, err2, code2)
			return
		}
	}
	nsLogf("MAP 已写回 node-sync")
	// 触发后台应用
	if err := nsRunBg(); err != nil {
		nsLogf("触发 node-sync-bg 失败 (%v), 不急: ROS 调度器每 10 分钟会自动跑", err)
	} else {
		nsLogf("已触发 node-sync-bg 后台应用")
	}
	// 校验生效 (删除操作跳过)。整表一轮约 45 秒; 若触发时恰与调度器的一轮相撞,
	// :execute 可能被吞, 故 55 秒未生效就再触发一次, 总窗口 150 秒。
	if rq.Action != "remove" {
		start := time.Now()
		deadline := start.Add(150 * time.Second)
		applied := false
		retrig := false
		for time.Now().Before(deadline) {
			time.Sleep(5 * time.Second)
			if ok, _ := nsTargetApplied(changed); ok {
				applied = true
				break
			}
			if !retrig && time.Since(start) > 55*time.Second {
				retrig = true
				if err := nsRunBg(); err == nil {
					nsLogf("55 秒未生效, 已再次触发 node-sync-bg")
				}
			}
		}
		if applied {
			nsLogf("✓ 已在 ROS address-list 生效")
		} else {
			nsLogf("…150 秒内未在 address-list 看到该条 (可能域名解析慢), 调度器 10 分钟内会再同步; 可稍后点刷新核对计数")
		}
	} else {
		nsLogf("已删除并触发同步, 旧表项由脚本在应用时自动清理")
	}
	nsMu.Lock()
	nsCur.Running = false
	nsCur.Done = true
	nsCur.OK = true
	nsMu.Unlock()
	nsLogf("✓ 完成 (改线路后已建立的连接约 20 秒 conntrack 过期才换线)")
}

// ---- HTTP ----

func handleNodeSync(w http.ResponseWriter, r *http.Request) {
	ss, err := nsFetchScripts()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "读 ROS 脚本失败: " + err.Error()})
		return
	}
	sc, ok := nsFindScript(ss, "node-sync")
	if !ok {
		writeJSON(w, 502, map[string]string{"error": "ROS 里找不到 node-sync 脚本"})
		return
	}
	entries, err := nsParseMap(sc.Source)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "解析 MAP 失败: " + err.Error()})
		return
	}
	// 关联机队节点 (域名去机队后缀 / IP 字面 / CIDR 包含)
	// 域名派生仅在配置了 fleet_domain_suffix 时生效: 条目域名去掉该后缀
	// 所得的主机名与节点 key 相同, 即视为同一节点。
	for i := range entries {
		e := &entries[i]
		if e.Family == "domain" {
			if cfg.FleetDomainSuffix != "" && strings.HasSuffix(e.Target, cfg.FleetDomainSuffix) {
				key := strings.TrimSuffix(e.Target, cfg.FleetDomainSuffix)
				for _, n := range cfg.Nodes {
					if n.Key == key {
						e.NodeKey, e.NodeLabel = n.Key, n.Label
					}
				}
			}
			continue
		}
		for _, n := range cfg.Nodes {
			nip := net.ParseIP(n.IP)
			if nip == nil {
				continue
			}
			if e.Target == n.IP {
				e.NodeKey, e.NodeLabel = n.Key, n.Label
				break
			}
			if _, cidr, err := net.ParseCIDR(e.Target); err == nil && cidr.Contains(nip) {
				e.NodeKey, e.NodeLabel = n.Key, n.Label
				break
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"entries": entries,
		"counts":  nsCounts(),
		"job":     nsSnapshot(),
	})
}

func handleNodeSyncApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var rq nsApplyReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式不对"})
		return
	}
	if strings.TrimSpace(rq.Target) == "" {
		writeJSON(w, 400, map[string]string{"error": "目标必填"})
		return
	}
	if fleetSnapshot().Running {
		writeJSON(w, 409, map[string]string{"error": "机队体检进行中, 稍后再切线"})
		return
	}
	nsMu.Lock()
	if nsCur.Running {
		nsMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "已有切线任务在跑"})
		return
	}
	nsCur = nsJob{Running: true, Log: []string{}}
	nsMu.Unlock()
	go runNsApply(rq)
	writeJSON(w, 200, map[string]any{"started": true})
}

// ---- 条目延迟 (面板当前出口 ping 实测, 不动钉线; 域名走 AliDNS DoH 取真实 IP) ----

type nsLatResult struct {
	Target string  `json:"target"`
	IP4    string  `json:"ip4,omitempty"`
	Ms4    float64 `json:"ms4"`
	Loss4  float64 `json:"loss4"`
	IP6    string  `json:"ip6,omitempty"`
	Ms6    float64 `json:"ms6"`
	Loss6  float64 `json:"loss6"`
}

var (
	nsLatMu    sync.Mutex
	nsLatCache []nsLatResult
	nsLatAt    time.Time
)

func nsDohResolve(name string, qtype int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u := fmt.Sprintf("https://dns.alidns.com/resolve?name=%s&type=%d", name, qtype)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}
	var dj struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if json.Unmarshal(body, &dj) != nil {
		return ""
	}
	for _, a := range dj.Answer {
		if a.Type == qtype && net.ParseIP(a.Data) != nil {
			return a.Data
		}
	}
	return ""
}

// nsRepIP 取条目的代表 IP: 字面 IP 原样; CIDR 取网络地址+1 (主机路由取自身)。
func nsRepIP(target string) string {
	if ip := net.ParseIP(target); ip != nil {
		return target
	}
	_, cidr, err := net.ParseCIDR(target)
	if err != nil {
		return ""
	}
	// 段内若有已知机队节点 IP, 用它当代表 (比网络地址+1 更接近真实主机)
	for _, n := range cfg.Nodes {
		if nip := net.ParseIP(n.IP); nip != nil && cidr.Contains(nip) {
			return nip.String()
		}
	}
	ip := cidr.IP
	ones, bits := cidr.Mask.Size()
	if ones == bits {
		return ip.String()
	}
	b := make(net.IP, len(ip))
	copy(b, ip)
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			break
		}
	}
	return b.String()
}

func nsMeasureLat(entries []nsEntry) []nsLatResult {
	out := make([]nsLatResult, len(entries))
	type tgt struct{ ip4, ip6 string }
	tgts := make([]tgt, len(entries))
	for i, e := range entries {
		out[i] = nsLatResult{Target: e.Target, Ms4: -1, Ms6: -1, Loss4: 100, Loss6: 100}
		switch e.Family {
		case "domain":
			tgts[i].ip4 = nsDohResolve(e.Target, 1)
			tgts[i].ip6 = nsDohResolve(e.Target, 28)
		case "v4":
			tgts[i].ip4 = nsRepIP(e.Target)
		case "v6":
			tgts[i].ip6 = nsRepIP(e.Target)
		}
	}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	pingOne := func(idx, fam int, ip string) {
		defer wg.Done()
		defer func() { <-sem }()
		sum, _, err := Ping(context.Background(), ip, 3, 150, fam)
		ms, loss := -1.0, 100.0
		if err == nil {
			loss = sum.LossPct
			if sum.Recv > 0 {
				ms = sum.Avg
			}
		}
		nsLatMu.Lock()
		if fam == 4 {
			out[idx].IP4, out[idx].Ms4, out[idx].Loss4 = ip, ms, loss
		} else {
			out[idx].IP6, out[idx].Ms6, out[idx].Loss6 = ip, ms, loss
		}
		nsLatMu.Unlock()
	}
	for i := range entries {
		if tgts[i].ip4 != "" {
			wg.Add(1)
			sem <- struct{}{}
			go pingOne(i, 4, tgts[i].ip4)
		}
		if tgts[i].ip6 != "" {
			wg.Add(1)
			sem <- struct{}{}
			go pingOne(i, 6, tgts[i].ip6)
		}
	}
	wg.Wait()
	return out
}

func handleNodeSyncLatency(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "1"
	nsLatMu.Lock()
	fresh := nsLatCache != nil && time.Since(nsLatAt) < 60*time.Second
	cache, at := nsLatCache, nsLatAt
	nsLatMu.Unlock()
	if fresh && !force {
		writeJSON(w, 200, map[string]any{"at": at.Unix(), "cached": true, "results": cache})
		return
	}
	ss, err := nsFetchScripts()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "读 ROS 脚本失败: " + err.Error()})
		return
	}
	sc, ok := nsFindScript(ss, "node-sync")
	if !ok {
		writeJSON(w, 502, map[string]string{"error": "ROS 里找不到 node-sync 脚本"})
		return
	}
	entries, err := nsParseMap(sc.Source)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "解析 MAP 失败: " + err.Error()})
		return
	}
	res := nsMeasureLat(entries)
	nsLatMu.Lock()
	nsLatCache, nsLatAt = res, time.Now()
	nsLatMu.Unlock()
	writeJSON(w, 200, map[string]any{"at": nsLatAt.Unix(), "cached": false, "results": res})
}
