package main

import "testing"

// 聚合分配用例按 1000:2000:1000 的带宽档案标定(目标份额 1:2:1 由 bandwidth_mbps 派生)。
func init() {
	cfg.Lines = []Line{
		{ID: "wan1", Label: "WAN1", PPPoEiface: "pppoe-wan1", BandwidthMbps: 1000},
		{ID: "wan2", Label: "WAN2", PPPoEiface: "pppoe-wan2", BandwidthMbps: 2000},
		{ID: "wan3", Label: "WAN3", PPPoEiface: "pppoe-wan3", BandwidthMbps: 1000},
	}
}

// aggAllocByRate: 每流速率相同时退化为目标份额 1:2:1 的线程比。
func TestAggAllocEqualPerFlow(t *testing.T) {
	a := aggAllocByRate(32, map[string]float64{"wan1": 50, "wan2": 50, "wan3": 50})
	if a["wan2"] <= a["wan1"] || a["wan2"] <= a["wan3"] {
		t.Fatalf("每流相同应联通线程最多, got %v", a)
	}
	sum := a["wan1"] + a["wan2"] + a["wan3"]
	if sum < 29 || sum > 32 {
		t.Fatalf("总线程应接近 32, got %v (sum=%d)", a, sum)
	}
}

// 每流速率慢的线应拿到更多线程: 联通每流只有另两线一半时, 联通线程应明显多于 16。
func TestAggAllocSlowLineGetsMore(t *testing.T) {
	a := aggAllocByRate(32, map[string]float64{"wan1": 100, "wan2": 25, "wan3": 100})
	if a["wan2"] < 18 {
		t.Fatalf("慢线应加线程, got %v", a)
	}
	if a["wan1"] >= a["wan2"] || a["wan3"] >= a["wan2"] {
		t.Fatalf("慢线线程应最多, got %v", a)
	}
}

// 每流速率极高时不给多余线程: 三线都能被少数流喂满, 总线程应显著小于预算。
func TestAggAllocCapsAtLineRate(t *testing.T) {
	a := aggAllocByRate(32, map[string]float64{"wan1": 500, "wan2": 500, "wan3": 500})
	sum := a["wan1"] + a["wan2"] + a["wan3"]
	if sum >= 32 {
		t.Fatalf("每流 500Mbps 时不应把 32 线程全用掉, got %v", a)
	}
	for _, wan := range lineIDs() {
		if a[wan] < 3 {
			t.Fatalf("每线至少 3 线程, got %v", a)
		}
	}
}
