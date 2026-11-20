package main

// 每小时机队 Ping 采样: v4 节点 × 三线(wan1/wan2/wan3), v6 节点 × 双线(第一/第二线 IPv6 直连),
// 结果追加到 /etc/wanlab/pinghist.jsonl, 供「Ping 趋势」页签看逐时与时段延迟变化。
// 采样要切出口, 必须过切线独占闸; 闸忙则跳过这一小时(不排队、不硬抢), 测完恢复原出口。

import (
	"context"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const pingHistFile = "/etc/wanlab/pinghist.jsonl"

type HistSample struct {
	Key  string  `json:"key"`
	Line string  `json:"line"`
	Avg  float64 `json:"avg"`  // ms; -1 = 全丢/不可达
	Loss float64 `json:"loss"` // %
}

type HistRun struct {
	TS      string       `json:"ts"`
	Unix    int64        `json:"unix"`
	Samples []HistSample `json:"samples"`
}

func round1(x float64) float64 { return math.Round(x*10) / 10 }

func runPingRound() {
	if !tryExitGate("Ping 定时采样") {
		holder, _ := exitGateBusy()
		log.Printf("ping 采样跳过: %s 正在用线", holder)
		return
	}
	defer releaseExitGate()
	ctx := context.Background()
	prev := getExit()
	defer func() {
		if err := setExit(prev); err != nil {
			log.Printf("ping 采样: 恢复出口 %s 失败: %v", prev, err)
		}
	}()

	var v4Nodes, v6Nodes []Node
	for _, n := range cfg.Nodes {
		if strings.Contains(n.IP, ":") {
			v6Nodes = append(v6Nodes, n)
		} else {
			v4Nodes = append(v4Nodes, n)
		}
	}
	groups := []struct {
		line  string
		nodes []Node
	}{{"1", v4Nodes}, {"2", v4Nodes}, {"3", v4Nodes}, {"v6", v6Nodes}, {"v6u", v6Nodes}}

	run := HistRun{TS: time.Now().Format("2006-01-02 15:04"), Unix: time.Now().Unix()}
	for _, g := range groups {
		if len(g.nodes) == 0 {
			continue
		}
		if err := setExit(g.line); err != nil {
			log.Printf("ping 采样: 钉线 %s 失败: %v, 跳过该线", g.line, err)
			continue
		}
		time.Sleep(1200 * time.Millisecond)
		for _, node := range g.nodes {
			fam := 4
			if strings.Contains(node.IP, ":") {
				fam = 6
			}
			s := HistSample{Key: node.Key, Line: g.line, Avg: -1, Loss: 100}
			if sm, _, err := Ping(ctx, node.IP, 5, 200, fam); err == nil && sm.Recv > 0 {
				s.Avg = round1(sm.Avg)
				s.Loss = round1(sm.LossPct)
			}
			run.Samples = append(run.Samples, s)
		}
	}

	b, err := json.Marshal(run)
	if err == nil {
		if f, ferr := os.OpenFile(pingHistFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); ferr == nil {
			f.Write(append(b, '\n'))
			f.Close()
		}
	}
	compactPingHist()
	log.Printf("ping 采样完成: %s, %d 个样本", run.TS, len(run.Samples))
}

// compactPingHist 数据保留 10 天: 超过 400 轮时只留最近 240 轮(10 天)。
func compactPingHist() {
	data, err := os.ReadFile(pingHistFile)
	if err != nil {
		return
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) <= 400 {
		return
	}
	keep := lines[len(lines)-240:]
	os.WriteFile(pingHistFile, []byte(strings.Join(keep, "\n")+"\n"), 0644)
}

func readPingRuns(n int) []HistRun {
	out := []HistRun{}
	data, err := os.ReadFile(pingHistFile)
	if err != nil {
		return out
	}
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var r HistRun
		if json.Unmarshal([]byte(ln), &r) == nil && len(r.Samples) > 0 {
			out = append(out, r)
		}
	}
	if len(out) > n {
		out = out[len(out)-n:]
	}
	return out
}

func handlePingHist(w http.ResponseWriter, r *http.Request) {
	n := 240 // 默认近 10 天
	if v := r.URL.Query().Get("runs"); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x > 0 && x <= 240 {
			n = x
		}
	}
	writeJSON(w, 200, map[string]any{"runs": readPingRuns(n)})
}

// pingScheduler 开机 2 分钟先采一轮, 之后每小时 :03 采一轮。
func pingScheduler() {
	time.Sleep(2 * time.Minute)
	runPingRound()
	for {
		now := time.Now()
		next := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 3, 0, 0, now.Location())
		if !next.After(now) {
			next = next.Add(time.Hour)
		}
		time.Sleep(time.Until(next))
		runPingRound()
	}
}
