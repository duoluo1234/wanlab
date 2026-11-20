package main

// 分流归属矩阵的 HTTP 入口：GET /api/split
// 可选参数 ?refresh=1 强制重测（默认也每次实时跑，探测点都是轻量回显，<2s 完成）

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	splitMu   sync.Mutex
	splitLast []SplitRow
	splitAt   time.Time
)

// wanExitIPs 读当前三条线的 v4 出口 IP（直接从 ROS 的 pppoe 接口地址取，最准）。
// wanExitIPs 读三条线的 v4 出口 IP。
// ★ 坑：pppoe 接口上不止一个地址（还有 100.64/10 CGNAT 的临时/管理地址），
//   直接取第一个会拿到 100.x ⇒ 必须跳过 CGNAT/私网，取真正的公网地址。
func wanExitIPs() map[string]string {
	out := map[string]string{}
	b, err := ros.Get("/rest/ip/address")
	if err != nil {
		return out
	}
	var arr []map[string]any
	if json.Unmarshal(b, &arr) != nil {
		return out
	}
	for _, def := range lineDefs() {
		line, iface := def.Label, def.PPPoEiface
		for _, a := range arr {
			if ifc, _ := a["interface"].(string); ifc != iface {
				continue
			}
			s, _ := a["address"].(string)
			i := strings.IndexByte(s, '/')
			if i <= 0 || !strings.Contains(s[:i], ".") {
				continue
			}
			ip := s[:i]
			if isCGNATOrPrivate(ip) {
				continue // 跳过 100.64/10、私网
			}
			out[line] = ip
			break
		}
	}
	return out
}

// isCGNATOrPrivate 判断是否 CGNAT/私网/保留地址（不能作为出口标识）。
func isCGNATOrPrivate(ip string) bool {
	if strings.HasPrefix(ip, "100.") { // 100.64.0.0/10 CGNAT（本网 ROS 上确有）
		return true
	}
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "127.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		var o2 int
		if _, err := fmt.Sscanf(ip, "172.%d.", &o2); err == nil && o2 >= 16 && o2 <= 31 {
			return true
		}
	}
	return false
}

// nodeIPMap 机队节点 key -> v4 IP（v6 节点单独标出）。
func nodeIPMap() map[string]string {
	m := map[string]string{}
	for _, n := range cfg.Nodes {
		if strings.Contains(n.IP, ":") {
			m[n.Label] = n.IP
		} else {
			m[n.Label] = n.IP
		}
	}
	return m
}

func handleSplit(w http.ResponseWriter, r *http.Request) {
	exits := wanExitIPs()
	nodes := nodeIPMap()

	cctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	// IP 归属矩阵 与 主流站点走向 并行跑
	var rows []SplitRow
	var sites []SiteRow
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); rows = SplitTunnel(cctx, exits, nodes) }()
	go func() { defer wg.Done(); sites = SplitSites(cctx, exits, nodes) }()
	wg.Wait()

	// 站点测完后，读 OpenClash 真实分流链路来覆盖判定
	// （整机出口只能反映"某一次请求"，而 OpenClash 是按域名分策略组的）
	conns := fetchMihomoConns(cctx)
	mihomoOK := len(conns) > 0
	if mihomoOK {
		OverrideSites(sites, conns)
	}

	splitMu.Lock()
	splitLast, splitAt = rows, time.Now()
	splitMu.Unlock()

	// 汇总：按线路统计命中的探测点数量，前端给个"一眼结论"
	summary := map[string]int{}
	for _, r := range rows {
		if r.Line != "" {
			summary[r.Line]++
		}
	}
	log.Printf("split: %d IP探测点 + %d 站点, mihomo连接=%d, 出口=%v", len(rows), len(sites), len(conns), exits)
	writeJSON(w, http.StatusOK, map[string]any{
		"at":         time.Now().Format("15:04:05"),
		"exit":       getExit(),
		"exits":      exits,
		"rows":       rows,
		"sites":      sites,
		"siteSum":    siteSummaryWithMihomo(sites),
		"mihomoOK":   mihomoOK,
		"connCount":  len(conns),
		"summary":    summary,
		"count":      len(rows),
	})
}
