package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// v6 直连钉线(NAT66 时代): 内网设备源地址都是 ULA(fd00:192:168::/64), ROS 做 NAT66 masquerade 出网。
// 面板按「容器 ULA /128 源地址」钉线, 每条线两条规则, 都插在 proxy-src-check6 跳转之前:
//   ① mark-connection (v6nat-line1 / v6nat-line2) —— 走既有 NAT66 masquerade + 回程机制
//   ② mark-routing    (to-wan1 / to-wan2, passthrough=no) —— 阻断后续 lan-ula-src 规则把流量改走默认策略
//
// ★ cm 规则必须排在 routing 规则之前: routing 规则 passthrough=no 会中断 prerouting 链,
//   排它后面就永远打不上连接标记。
// ★ 旧规则(停用中, 源是旧 PD GUA)用同 tag 原地迁移, 避免 ROS 里留孤儿规则。
// ★ 查找一律用 Contains 而不是 HasPrefix, 且每次 Ensure/Disable 都先 pruneV6Dupes:
//   注释一旦被整理(加「【钉线】NN 」前缀之类)前缀匹配就失效, 面板会当成没规则而
//   重复新建, 表里越攒越多。Contains + 自愈清理对注释前缀免疫。
const (
	v6TagLine1 = "WANLAB 线路1 IPv6"
	v6TagLine2 = "WANLAB 线路2 IPv6"
	v6TagCML1  = "WANLAB 线路1 v6连接标记"
	v6TagCML2  = "WANLAB 线路2 v6连接标记"
)

type v6Line struct{ tag, cmTag, mark, cm, name string }

// v6Lines: "m"=第一线(to-wan1) / "u"=第二线(to-wan2); name 取配置 lines 的标签。
func v6Lines() map[string]v6Line {
	return map[string]v6Line{
		"m": {v6TagLine1, v6TagCML1, "to-wan1", "v6nat-line1", lineLabelIdx(0)},
		"u": {v6TagLine2, v6TagCML2, "to-wan2", "v6nat-line2", lineLabelIdx(1)},
	}
}

func allV6Tags() []string {
	return []string{v6TagLine1, v6TagLine2, v6TagCML1, v6TagCML2}
}

// localV6Addr 返回 eth0 上会真正作为源地址的 v6。
//
// 容器里常同时有静态地址(fd00:192:168::216, docker --ipv6)和 SLAAC 地址
// (fd00:192:168:0:<EUI64 of MAC>), 内核按 RFC 6724 实测选 **SLAAC 那条**,
// 只有它能被 mangle 的 src-address 匹配到 —— 猜错就是「规则在、实际不生效」。
//
// 顺序: ① 按 MAC 算 EUI-64 地址, 存在就用它(macvlan 的 MAC 已在 compose 里钉死,
// 结果确定, 且不受启动瞬间 SLAAC 还没到的影响之外的抖动) ② 问内核 route get
// ③ 退回原逻辑(优先 ULA, 否则第一个全局地址)。
func localV6Addr() string {
	ifc, err := net.InterfaceByName("eth0")
	if err != nil {
		return ""
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return ""
	}
	if a, ok := pickEUI64(ifc.HardwareAddr, addrs); ok {
		return a
	}
	if a := kernelV6Src("2606:4700:4700::1111"); a != "" {
		return a
	}
	first := ""
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.To4() != nil || ipn.IP.IsLinkLocalUnicast() || !ipn.IP.IsGlobalUnicast() {
			continue
		}
		if ipn.IP.IsPrivate() { // ULA fc00::/7
			return ipn.IP.String()
		}
		if first == "" {
			first = ipn.IP.String()
		}
	}
	return first
}

// pickEUI64 按网卡 MAC 算出 SLAAC 地址, 若该地址确实在网卡上就返回它。
// 同前缀取任一全局地址的 /64 作前缀(本环境内网全是同一个 ULA /64)。
func pickEUI64(mac net.HardwareAddr, addrs []net.Addr) (string, bool) {
	if len(mac) != 6 {
		return "", false
	}
	var prefix []byte
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.To4() != nil || ipn.IP.IsLinkLocalUnicast() || !ipn.IP.IsGlobalUnicast() {
			continue
		}
		prefix = ipn.IP.To16()[:8]
		break
	}
	if prefix == nil {
		return "", false
	}
	want := make(net.IP, 16)
	copy(want[:8], prefix)
	want[8] = mac[0] ^ 0x02
	want[9], want[10] = mac[1], mac[2]
	want[11], want[12] = 0xff, 0xfe
	want[13], want[14], want[15] = mac[3], mac[4], mac[5]
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if ok && ipn.IP.Equal(want) {
			return want.String(), true
		}
	}
	return "", false
}

// kernelV6Src 用 ip -6 route get 问内核: 去 target 会用哪个源地址。
func kernelV6Src(target string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := runCmd(ctx, "ip", "-6", "route", "get", target)
	if err != nil {
		return ""
	}
	f := strings.Fields(out)
	for i, w := range f {
		if w == "src" && i+1 < len(f) {
			return f[i+1]
		}
	}
	return ""
}

// v6Prefix64 取地址所在 /64(用于"排除内网目标")。
func v6Prefix64(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "::/0"
	}
	return (&net.IPNet{IP: ip.Mask(net.CIDRMask(64, 128)), Mask: net.CIDRMask(64, 128)}).String()
}

// FindV6Rules 按注释**包含** tag 查找面板管理的全部 v6 规则。
//
// ★ 不能用 HasPrefix: 手工整理注释时给规则加了「【钉线】NN 」前缀, 前缀一变
// HasPrefix 就查不到 ⇒ 面板以为规则不存在 ⇒ 每次切线路都新建一套, 旧规则变
// disabled 僵尸堆在表里(2026-10-31 清掉 4 条)。Contains 才对前缀免疫。
func (r *Ros) FindV6Rules(tag string) ([]MangleRule, error) {
	b, err := r.Get("/rest/ipv6/firewall/mangle")
	if err != nil {
		return nil, err
	}
	var all []MangleRule
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	var out []MangleRule
	for i := range all {
		if strings.Contains(all[i].Comment, tag) {
			out = append(out, all[i])
		}
	}
	return out, nil
}

// primaryV6 从一组同 tag 规则里选「正本」: 优先启用中的; 同状态优先注释不带
// 「【」前缀的(面板自己写的不带前缀, 被整理过的带); 仍并列取表里最靠前那条。
func primaryV6(rs []MangleRule) *MangleRule {
	if len(rs) == 0 {
		return nil
	}
	best := 0
	for i := 1; i < len(rs); i++ {
		b, c := rs[best], rs[i]
		if b.Disabled == "true" && c.Disabled != "true" {
			best = i
			continue
		}
		if (b.Disabled == "true") == (c.Disabled == "true") &&
			strings.HasPrefix(b.Comment, "【") && !strings.HasPrefix(c.Comment, "【") {
			best = i
		}
	}
	return &rs[best]
}

// FindV6RuleByTag 按注释查找面板管理的某条 v6 规则(返回正本)。
func (r *Ros) FindV6RuleByTag(tag string) (*MangleRule, error) {
	rs, err := r.FindV6Rules(tag)
	if err != nil {
		return nil, err
	}
	return primaryV6(rs), nil
}

// pruneV6Dupes 删掉同 tag 的历史副本, 只留正本。返回删掉的条数。
// 这是自愈: 即使以后注释再被整理成别的形态, 也不会越攒越多。
func (r *Ros) pruneV6Dupes(tag string) (int, error) {
	rs, err := r.FindV6Rules(tag)
	if err != nil {
		return 0, err
	}
	if len(rs) <= 1 {
		return 0, nil
	}
	p := primaryV6(rs)
	n := 0
	for i := range rs {
		if rs[i].ID == p.ID {
			continue
		}
		if _, _, err := r.do("DELETE", "/rest/ipv6/firewall/mangle/"+rs[i].ID, nil); err != nil {
			log.Printf("清理重复 v6 规则 %s(%s) 失败: %v", rs[i].ID, rs[i].Comment, err)
			continue
		}
		n++
	}
	return n, nil
}

// v6JumpRuleID 返回 prerouting 里 jump 到 proxy-src-check6 的规则 id(新规则插它前面)。
func (r *Ros) v6JumpRuleID() (string, error) {
	b, err := r.Get("/rest/ipv6/firewall/mangle")
	if err != nil {
		return "", err
	}
	var all []struct {
		ID         string `json:".id"`
		Chain      string `json:"chain"`
		JumpTarget string `json:"jump-target"`
	}
	if json.Unmarshal(b, &all) != nil {
		return "", fmt.Errorf("解析 v6 mangle 失败")
	}
	for _, m := range all {
		if m.Chain == "prerouting" && m.JumpTarget == "proxy-src-check6" {
			return m.ID, nil
		}
	}
	return "", nil // 没有代理跳转链时直接追加即可
}

func disStr(off bool) string {
	if off {
		return "yes"
	}
	return "no"
}

// EnsureV6Rules 建/改/启停一条线的 v6 钉线规则组(①连接标记 ②路由标记)。
// line: "m"(第一线) / "u"(第二线)。addr 面板源地址(容器 ULA)。
func (r *Ros) EnsureV6Rules(line, addr string, enable bool) error {
	ln, ok := v6Lines()[line]
	if !ok {
		return fmt.Errorf("未知 v6 线路: %s", line)
	}
	excl := "!" + v6Prefix64(addr)

	// ⓪ 先自愈: 同 tag 的历史副本(注释前缀变过留的僵尸)只留正本, 其余删掉
	for _, t := range []string{ln.tag, ln.cmTag} {
		if n, err := r.pruneV6Dupes(t); err != nil {
			log.Printf("清理 %s 重复规则失败: %v", t, err)
		} else if n > 0 {
			log.Printf("清理 %s 重复规则 %d 条", t, n)
		}
	}

	// ① 路由标记规则(先建/改, cm 规则要插它前面)
	rule, err := r.FindV6RuleByTag(ln.tag)
	if err != nil {
		return err
	}
	if rule == nil {
		body := map[string]any{
			"chain":            "prerouting",
			"action":           "mark-routing",
			"src-address":      addr + "/128",
			"dst-address":      excl,
			"new-routing-mark": ln.mark,
			"passthrough":      "no",
			"comment":          ln.tag + ": 面板v6出口固定走" + ln.name + ", 勿手改",
		}
		if jump, _ := r.v6JumpRuleID(); jump != "" {
			body["place-before"] = jump
		}
		if !enable {
			body["disabled"] = "yes"
		}
		rb, _, err := r.do("PUT", "/rest/ipv6/firewall/mangle", body)
		if err != nil {
			return err
		}
		var resp struct {
			ID string `json:".id"`
		}
		json.Unmarshal(rb, &resp)
		rule = &MangleRule{ID: resp.ID}
	} else {
		fields := map[string]any{
			"src-address":      addr + "/128",
			"dst-address":      excl,
			"new-routing-mark": ln.mark,
			"disabled":         disStr(!enable),
		}
		if err := r.PatchPinRuleV6(rule.ID, fields); err != nil {
			return err
		}
	}

	// ② 连接标记(必须在 ① 之前)
	cmRule, err := r.FindV6RuleByTag(ln.cmTag)
	if err != nil {
		return err
	}
	if cmRule == nil {
		body := map[string]any{
			"chain":               "prerouting",
			"action":              "mark-connection",
			"src-address":         addr + "/128",
			"dst-address":         excl,
			"new-connection-mark": ln.cm,
			"passthrough":         "yes",
			"comment":             ln.cmTag + ": 面板v6 NAT66连接标记, 勿手改",
		}
		if rule.ID != "" {
			body["place-before"] = rule.ID
		}
		if !enable {
			body["disabled"] = "yes"
		}
		_, _, err := r.do("PUT", "/rest/ipv6/firewall/mangle", body)
		return err
	}
	fields := map[string]any{
		"src-address":         addr + "/128",
		"dst-address":         excl,
		"new-connection-mark": ln.cm,
		"disabled":            disStr(!enable),
	}
	return r.PatchPinRuleV6(cmRule.ID, fields)
}

// DisableAllV6Rules 停用面板管理的全部 v6 规则(切回 v4 出口时)。
// 顺带清掉同 tag 的重复副本, 避免僵尸规则长期堆积。
func (r *Ros) DisableAllV6Rules() error {
	for _, t := range allV6Tags() {
		if n, err := r.pruneV6Dupes(t); err != nil {
			log.Printf("清理 %s 重复规则失败: %v", t, err)
		} else if n > 0 {
			log.Printf("清理 %s 重复规则 %d 条", t, n)
		}
	}
	b, err := r.Get("/rest/ipv6/firewall/mangle")
	if err != nil {
		return err
	}
	var all []MangleRule
	if err := json.Unmarshal(b, &all); err != nil {
		return err
	}
	for i := range all {
		if all[i].Disabled == "true" {
			continue
		}
		for _, t := range allV6Tags() {
			if strings.Contains(all[i].Comment, t) {
				if err := r.PatchPinRuleV6(all[i].ID, map[string]any{"disabled": "yes"}); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}

// PatchPinRuleV6 单独命名: /ipv6 的 mangle 和 v4 不是同一个路径。
func (r *Ros) PatchPinRuleV6(id string, fields map[string]any) error {
	_, _, err := r.do("PATCH", "/rest/ipv6/firewall/mangle/"+id, fields)
	return err
}

// V6State 给状态页用。
type V6State struct {
	Addr    string `json:"addr"`
	RuleID  string `json:"rule_id,omitempty"`
	Line    string `json:"line,omitempty"` // m=第一线 u=第二线 ""=未钉线
	Enabled bool   `json:"enabled"`
	Error   string `json:"error,omitempty"`
}
