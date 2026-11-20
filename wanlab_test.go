package main

import (
	"net"
	"testing"
	"time"
)

func TestParseHop(t *testing.T) {
	h := parseHop("  3  198.51.100.2  21.391 ms")
	if h == nil || h.Hop != 3 || len(h.Addr) != 1 || h.Addr[0] != "198.51.100.2" {
		t.Fatalf("hop 解析错: %+v", h)
	}
	if len(h.RTT) != 1 || h.RTT[0] != "21.391 ms" {
		t.Fatalf("rtt 解析错: %+v", h.RTT)
	}
	if s := parseHop(" 9  *"); s == nil || s.Hop != 9 || len(s.Addr) != 0 {
		t.Fatalf("超时跳解析错: %+v", s)
	}
	if parseHop("traceroute to 1.1.1.1, 12 hops max") != nil {
		t.Fatal("表头不应被当成跳")
	}
	if m := parseHop(" 5  10.0.0.1  1.2 ms  10.0.0.2  3.4 ms"); len(m.Addr) != 2 || len(m.RTT) != 2 {
		t.Fatalf("多地址解析错: %+v", m)
	}
}

func TestParseIPLoose(t *testing.T) {
	for in, want := range map[string]string{
		"1.1.1.1": "1.1.1.1", " 8.8.8.8 ": "8.8.8.8",
		"1.1.1.1:443": "1.1.1.1", "google.com": "", "": "",
	} {
		if got := parseIPLoose(in); got != want {
			t.Fatalf("parseIPLoose(%q)=%q want %q", in, got, want)
		}
	}
}

func TestFakeIPRange(t *testing.T) {
	if !fakeNet.Contains(net.ParseIP("198.18.8.105")) {
		t.Fatal("198.18/15 应判 fake-ip")
	}
	if fakeNet.Contains(net.ParseIP("142.250.78.142")) {
		t.Fatal("真 IP 被误判 fake")
	}
}

func TestASDisplay(t *testing.T) {
	cases := []struct{ as, org, cc, want string }{
		{"", "", "HK", "中国香港"}, // 空 AS 不能 panic(线上踩过)
		{"AS9929 CHINA UNICOM", "CUII", "CN", "AS9929 中国联通 9929 · 中国"},
		{"AS13335 Cloudflare", "", "HK", "AS13335 Cloudflare · 中国香港"},
		{"AS3258 xTom Japan Corporation", "", "JP", "AS3258 xTom 日本 · 日本"},
	}
	for _, c := range cases {
		if got := asDisplay(c.as, c.org, c.cc); got != c.want {
			t.Fatalf("asDisplay(%q,%q)=%q want %q", c.as, c.cc, got, c.want)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	for ip, want := range map[string]bool{
		"100.66.160.1": true, // CGNAT
		"192.168.88.1": true, // 私网
		"10.0.0.1":     true,
		"210.13.67.30": false, // 公网
		"1.1.1.1":      false,
	} {
		if got := isPrivateIP(ip); got != want {
			t.Fatalf("isPrivateIP(%s)=%v want %v", ip, got, want)
		}
	}
}

func TestRateApply(t *testing.T) {
	rateTable = map[string]WanRate{}
	rateBase = map[string]lineStamp{}
	t0 := time.Now()
	// 基线读数(第一轮只有计数器, 没有速率)
	apply(map[string]lineStamp{"wan3": {Rx: 0, Tx: 0, At: t0}})
	// 1 秒 +12.5MB / +2.5MB => 100 / 20 Mbps
	apply(map[string]lineStamp{"wan3": {Rx: 12500000, Tx: 2500000, At: t0.Add(time.Second)}})
	if r := rateTable["wan3"]; r.Down < 99 || r.Down > 101 || r.Up < 19 || r.Up > 21 {
		t.Fatalf("速率换算错: %+v", r)
	}
	// 窗口太短(0.3 秒) => 沿用上一轮, 不能被 0 覆盖
	apply(map[string]lineStamp{"wan3": {Rx: 13500000, Tx: 2600000, At: t0.Add(1300 * time.Millisecond)}})
	if r := rateTable["wan3"]; r.Down < 99 {
		t.Fatalf("短窗口被清零: %+v", r)
	}
	// 计数器回退(重拨) => 归零而不是负值/峰值
	apply(map[string]lineStamp{"wan3": {Rx: 100, Tx: 50, At: t0.Add(2300 * time.Millisecond)}})
	if r := rateTable["wan3"]; r.Down != 0 || r.Up != 0 {
		t.Fatalf("回退未归零: %+v", r)
	}
	// ★每线独立 dt 回归(2026-11-19): 慢轮后 5 秒才读到下一轮, 增量必须按 5 秒算,
	// 不能按名义 1 秒算出 5 倍尖峰(线上曾飙到 3530Mbps)。
	apply(map[string]lineStamp{"wan3": {Rx: 100 + 62500000, Tx: 50 + 12500000, At: t0.Add(7300 * time.Millisecond)}})
	if r := rateTable["wan3"]; r.Down < 99 || r.Down > 101 {
		t.Fatalf("慢轮速率被算成尖峰: %+v", r)
	}
}

func TestV6Prefix64(t *testing.T) {
	if got := v6Prefix64("2409:8a1e:99b3:b6b0:be24:11ff:feec:526a"); got != "2409:8a1e:99b3:b6b0::/64" {
		t.Fatalf("v6Prefix64 = %q", got)
	}
}

func TestAggLopsided(t *testing.T) {
	// 期望分担由各线 bandwidth_mbps 占比派生; 本用例锁定 1000:2000:1000 = 1:2:1 口径。
	oldLines := cfg.Lines
	cfg.Lines = []Line{
		{ID: "wan1", Label: "WAN1", PPPoEiface: "pppoe-wan1", BandwidthMbps: 1000},
		{ID: "wan2", Label: "WAN2", PPPoEiface: "pppoe-wan2", BandwidthMbps: 2000},
		{ID: "wan3", Label: "WAN3", PPPoEiface: "pppoe-wan3", BandwidthMbps: 1000},
	}
	defer func() { cfg.Lines = oldLines }()
	mk := func(a, b, c float64) map[string]AggLine {
		return map[string]AggLine{"wan1": {Down: a}, "wan2": {Down: b}, "wan3": {Down: c}}
	}
	// 正好 1:2:1 (25/50/25) => 不偏斜
	if aggLopsided(mk(250, 500, 250)) {
		t.Fatal("1:2:1 标准分布却判成偏斜")
	}
	// 均分 3 份 => 联通只有 33%, 低于期望的 50-18=32% 边界附近, 属于可接受的偏差
	if aggLopsided(mk(330, 340, 330)) {
		t.Fatal("近似均分不该判偏斜(联通 34% 仍在容差内)")
	}
	// 全压联通 => 偏斜
	if !aggLopsided(mk(0, 1550, 0)) {
		t.Fatal("全压一条线没判成偏斜")
	}
	// 流量太小(启动瞬间) => 不判
	if aggLopsided(mk(0, 50, 0)) {
		t.Fatal("小流量不该判偏斜")
	}
	// 联通之外两条出力, 联通=0 => 偏斜
	if !aggLopsided(mk(800, 850, 0)) {
		t.Fatal("联通为 0 应判偏斜(期望 50%)")
	}
	// 移动吃太多 (62%) => 偏斜
	if !aggLopsided(mk(620, 200, 180)) {
		t.Fatal("移动 62% 应判偏斜(期望 25%)")
	}
	// 9929 吃太多 (50%) => 偏斜
	if !aggLopsided(mk(250, 250, 500)) {
		t.Fatal("9929 50% 应判偏斜(期望 25%)")
	}
	// 39/33/28 => 各条都在容差内
	if aggLopsided(mk(390, 330, 280)) {
		t.Fatal("39/33/28 不该判偏斜")
	}
}

func TestAggShare(t *testing.T) {
	sh := aggShare(map[string]AggLine{"wan1": {Down: 250}, "wan2": {Down: 500}, "wan3": {Down: 250}})
	if sh["wan1"] < 0.249 || sh["wan1"] > 0.251 || sh["wan2"] < 0.499 || sh["wan2"] > 0.501 {
		t.Fatalf("占比算错: %v", sh)
	}
	if len(aggShare(map[string]AggLine{})) != 0 {
		t.Fatal("空数据应返回空 map")
	}
}

func TestPrimaryV6(t *testing.T) {
	mk := func(id, dis, cm string) MangleRule {
		return MangleRule{ID: id, Disabled: dis, Comment: cm}
	}
	const tag = "WANLAB 移动IPv6"
	// 空集合 => nil
	if primaryV6(nil) != nil {
		t.Fatal("空集合应返回 nil")
	}
	// 单条直接返回
	if p := primaryV6([]MangleRule{mk("*1", "false", tag+": x")}); p == nil || p.ID != "*1" {
		t.Fatalf("单条应原样返回: %+v", p)
	}
	// 启用优先于停用
	got := primaryV6([]MangleRule{mk("*1", "true", tag), mk("*2", "false", tag)})
	if got.ID != "*2" {
		t.Fatalf("应选启用中的那条, 实际 %s", got.ID)
	}
	// 同状态优先不带「【」前缀的(面板自己写的那条)
	got = primaryV6([]MangleRule{mk("*1", "false", "【钉线】09 "+tag), mk("*2", "false", tag)})
	if got.ID != "*2" {
		t.Fatalf("应选无【前缀的那条, 实际 %s", got.ID)
	}
	// 全是【前缀 + 全停用 => 取最靠前
	got = primaryV6([]MangleRule{mk("*1", "true", "【钉线】09 "+tag), mk("*2", "true", "【钉线】10 "+tag)})
	if got.ID != "*1" {
		t.Fatalf("并列应取最靠前, 实际 %s", got.ID)
	}
}

func TestCleanHost(t *testing.T) {
	ok := map[string]string{
		"198.51.100.11":         "198.51.100.11",
		"  speed.example.com  ": "speed.example.com",
		"[2400:c620:32:c6::a]":  "2400:c620:32:c6::a",
		"2400:c620:32:c6::a":    "2400:c620:32:c6::a",
		"my-host_1.example.lan": "my-host_1.example.lan",
	}
	for in, want := range ok {
		got, err := cleanHost(in)
		if err != nil || got != want {
			t.Fatalf("cleanHost(%q) = %q,%v; 期望 %q", in, got, err, want)
		}
	}
	bad := []string{"", "   ", "-c", "--help", "1.2.3.4 -p 1", "a;b", "a|b", "$(id)", "a b"}
	for _, in := range bad {
		if got, err := cleanHost(in); err == nil {
			t.Fatalf("cleanHost(%q) 应报错, 实际 %q", in, got)
		}
	}
}

func TestHostFam(t *testing.T) {
	cases := map[string]int{
		"198.51.100.11":        4,
		"2400:c620:32:c6::a":   6,
		"2606:4700:4700::1111": 6,
		"speed.example.com":    4,
	}
	for in, want := range cases {
		if got := hostFam(in); got != want {
			t.Fatalf("hostFam(%q) = %d, 期望 %d", in, got, want)
		}
	}
}
