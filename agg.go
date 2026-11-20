package main

// 三线聚合拉一个文件（单客户端、单 URL、三口同时出力）
//
// 原理：ROS 的 ECMP 路由对同源同目的只走一个桶（实测 16 线程全落一条线），
// 所以必须用 PCC：先按源端口把连接分 3 桶打 connection-mark，再按 mark 打
// routing-mark 进 to-wan1/2/3。这样 N 条连接才会真的摊到三条线上。
//
// 与面板自身的「出口钉线」互斥：钉线规则 passthrough=no 会压住聚合规则，
// 故测试期间临时禁用钉线，测完原样恢复（disabled 值也恢复）。

import (
	"math"
	"log"
	"os"
	"sort"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const aggComment = "WANLAB 三线聚合(临时): 面板自动建删, 勿手改"

// 与 exec.go 的 HTTPPrepare/HTTPCleanup/HTTPRunMode 配合使用。

// AggPoint 聚合测试中的每秒三线下行速率(Mbps), 前端画下载曲线用。
type AggPoint struct {
	T    float64 `json:"t"`
	Wan1 float64 `json:"wan1"`
	Wan2 float64 `json:"wan2"`
	Wan3 float64 `json:"wan3"`
}

type AggLine struct {
	Down float64 `json:"down"` // 测试窗口内平均下行 Mbps
	Up   float64 `json:"up"`
}

type AggResult struct {
	Node     string             `json:"node"`
	Threads  int                `json:"threads"`
	Seconds  float64            `json:"seconds"`
	Bytes    int64              `json:"bytes"`
	Mbps     float64            `json:"mbps"`      // 客户端有效载荷
	SumLines float64            `json:"sum_lines"` // 三口接口口径合计
	Lines    map[string]AggLine `json:"lines"`     // wan1/wan2/wan3
	Samples  int                `json:"samples"`
	Restored string             `json:"restored"` // 钉线恢复情况
	Attempts int                `json:"attempts"` // 1=一次跑通, >1=因分布不均自动重跑
	Lopsided bool               `json:"lopsided,omitempty"` // 重跑后仍偏离 1:2:1 期望
	Ratio    string             `json:"ratio"`              // 目标分担比例
	LimitTotal int              `json:"limit_total"`       // 本次使用的三线合计上限(Mbps)
	TheoryTotal int             `json:"theory_total"`      // 线路理论总带宽(1000+2000+1000)
	AutoScaled bool             `json:"auto_scaled"`       // 是否因为测试机带宽不足而等比缩过
	Limits   map[string]int     `json:"limits"`            // 每线限速
	Warning  string             `json:"warning,omitempty"` // 测试机带宽不足等提示
	Rounds   int                `json:"rounds"`             // 实际跑了几轮
	Alloc    map[string]int     `json:"alloc,omitempty"`    // 最终各线线程数
	AttemptLog []string         `json:"attempt_log,omitempty"` // 每轮的线程分配与实际占比
	LineNodes map[string]string `json:"line_nodes,omitempty"` // 每线用的源站
	Shares   map[string]float64 `json:"shares,omitempty"`   // 实际占比
	Series   []AggPoint         `json:"series,omitempty"`   // 每秒速率, 前端画曲线
	Error    string             `json:"error,omitempty"`
}

type aggRule struct {
	ID      string `json:".id"`
	Comment string `json:"comment"`
}

func (r *Ros) aggRuleList() ([]aggRule, error) {
	b, err := r.Get("/rest/ip/firewall/mangle")
	if err != nil {
		return nil, err
	}
	var all []aggRule
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	var out []aggRule
	for _, x := range all {
		if strings.Contains(x.Comment, "WANLAB 三线聚合") {
			out = append(out, x)
		}
	}
	return out, nil
}

// aggCleanup 删掉所有聚合规则（幂等；按子串匹配，别用全等）。
func (r *Ros) aggCleanup() int {
	// 先删限速队列(避免队列残留卡住面板自己的流量)
	if qs, _, err := r.do("GET", "/rest/queue/simple", nil); err == nil {
		var list []map[string]any
		if json.Unmarshal(qs, &list) == nil {
			for _, q := range list {
				if strings.Contains(fmt.Sprint(q["comment"]), "WANLAB 三线聚合") {
					if id, _ := q[".id"].(string); id != "" {
						_, _, _ = r.do("DELETE", "/rest/queue/simple/"+id, nil)
					}
				}
			}
		}
	}
	rules, err := r.aggRuleList()
	if err != nil {
		return 0
	}
	n := 0
	for _, x := range rules {
		if _, _, err := r.do("DELETE", "/rest/ip/firewall/mangle/"+x.ID, nil); err == nil {
			n++
		}
	}
	return n
}

// aggPortBase 每条线占用的本机源端口段(400 个/线, 低于内核临时端口区 32768)。
// 用「源端口段 → 路由表」直接钉线, 不再用 PCC 均分: 这样客户端开几条连接就决定分担多少,
// 1:2:1 由线程数直接控制, 不再受源端口哈希随机性影响。
// aggPortBaseOf 按线路在配置中的下标派生源端口段基址(400 个/线, 低于内核临时端口区 32768)。
func aggPortBaseOf(wan string) int {
	for i, l := range lineDefs() {
		if l.ID == wan {
			return 21000 + 400*i
		}
	}
	return 21000
}

// aggLimitTotal 三线合并的目标总带宽(Mbps)。队列按 1:2:1 切分这个数。
// 不再是写死的 1000: 三条线带宽不一(见 aggLineCap 的 1:2:1), 写死总数会把宽线卡住 —— 上限必须跟着
// 「实测能打到多少」或用户手动指定走, 否则等于给线路降速。
var aggLimitTotal = 1000

// aggLimitOf 返回某条线的下载限速(Mbps): 按各线理论带宽占比切分 aggLimitTotal。
func aggLimitOf(wan string) int {
	return aggLimitOfFor(aggLimitTotal, wan)
}

// aggLimitOfFor 按给定总量 + 线路理论带宽占比算某条线的限速(Mbps)。
// 例: 三条线 1000/2000/1000 时占比为 25%/50%/25%。
func aggLimitOfFor(total int, wan string) int {
	caps := aggLineCapMap()
	capTotal := aggCapTotal()
	if capTotal <= 0 || len(caps) == 0 {
		return total / 3
	}
	c, ok := caps[wan]
	if !ok {
		return int(math.Round(float64(total) / float64(len(caps))))
	}
	return int(math.Round(float64(total) * c / capTotal))
}

// buildPlanNodes 把 srcNodes 轮转分配到三条线, 用于探速(此时还没建队列)。
func buildPlanNodes(srcNodes []Node, alloc map[string]int) map[string]aggJob {
	p := map[string]aggJob{}
	for _, l := range lineDefs() {
		p[l.ID] = aggJob{Nodes: srcNodes, Threads: alloc[l.ID]}
	}
	return p
}

// aggUpdateQueues 按新的总量改写三条线的限速(探速之后才发现测试机带宽不足时用)。
func (r *Ros) aggUpdateQueues(total int) error {
	qs, _, err := r.do("GET", "/rest/queue/simple", nil)
	if err != nil {
		return err
	}
	var list []map[string]any
	if err := json.Unmarshal(qs, &list); err != nil {
		return err
	}
	for _, q := range list {
		name, _ := q["name"].(string)
		if !strings.HasPrefix(name, "WANLAB-agg-") {
			continue
		}
		wan := strings.TrimPrefix(name, "WANLAB-agg-")
		id, _ := q[".id"].(string)
		if id == "" {
			continue
		}
		lim := aggLimitOfFor(total, wan)
		if _, _, err := r.do("PATCH", "/rest/queue/simple/"+id, map[string]any{
			"max-limit": fmt.Sprintf("%dM/%dM", lim*2, lim),
		}); err != nil {
			return err
		}
	}
	return nil
}

// aggPortSpan 每条线的端口段宽度(留够重跑换段的空间, 避免 TIME_WAIT 撞端口)
const aggPortSpan = 400

func (r *Ros) aggSetup(ip string, total int) error {
	if total > 0 {
		aggLimitTotal = total
	}
	capped := total > 0 // total=0 = 不限速: 不建 packet-mark 规则与限速队列, 让三线自然跑到顶
	for _, wan := range lineIDs() {
		base := aggPortBaseOf(wan)
		resp, _, err := r.do("PUT", "/rest/ip/firewall/mangle", map[string]any{
			"chain":            "prerouting",
			"action":           "mark-routing",
			"src-address":      ip,
			"dst-address":      "!" + lanCIDR(),
			"protocol":         "tcp",
			"src-port":         fmt.Sprintf("%d-%d", base, base+aggPortSpan-1),
			"new-routing-mark": "to-" + wan,
			"passthrough":      "no",
			"comment":          fmt.Sprintf("%s %s", aggComment, wan),
		})
		if err != nil {
			return fmt.Errorf("建分流规则失败(%s): %w", wan, err)
		}
		// 再打一个 packet-mark, 给下面的队列限速用
		if capped {
		presp, _, pErr := r.do("PUT", "/rest/ip/firewall/mangle", map[string]any{
			"chain":             "prerouting",
			"action":            "mark-packet",
			"src-address":       ip,
			"dst-address":       "!" + lanCIDR(),
			"protocol":          "tcp",
			"src-port":          fmt.Sprintf("%d-%d", base, base+aggPortSpan-1),
			"new-packet-mark":   "aggq-" + wan,
			"passthrough":       "yes",
			"comment":           fmt.Sprintf("%s 队列标记 %s", aggComment, wan),
		})
		if pErr != nil {
			return fmt.Errorf("建队列标记失败(%s): %w", wan, pErr)
		}
		if id, ok := lastRuleID(presp); ok {
			_, _, _ = r.do("POST", "/rest/ip/firewall/mangle/move", map[string]any{"numbers": id, "destination": "0"})
		}
		}
		// 下载方向的标记: 回包是 WAN→客户端, 目的端口才是客户端源端口,
		// 上面那条 src-port 规则只匹配上传, 单靠它队列限不住下载。
		if capped {
		rresp, _, rErr := r.do("PUT", "/rest/ip/firewall/mangle", map[string]any{
			"chain":            "prerouting",
			"action":           "mark-packet",
			"in-interface-list": "WAN",
			"protocol":         "tcp",
			"dst-port":         fmt.Sprintf("%d-%d", base, base+aggPortSpan-1),
			"new-packet-mark": "aggq-" + wan,
			"passthrough":     "yes",
			"comment":         fmt.Sprintf("%s 队列标记(下行) %s", aggComment, wan),
		})
		if rErr != nil {
			return fmt.Errorf("建下行队列标记失败(%s): %w", wan, rErr)
		}
		if id, ok := lastRuleID(rresp); ok {
			_, _, _ = r.do("POST", "/rest/ip/firewall/mangle/move", map[string]any{"numbers": id, "destination": "0"})
		}
		}
		// 单条线的限速: 用队列把每条线的带宽钉死到 25/50/25, 光靠线程数分不准
		if capped {
		lim := aggLimitOf(wan)
		if _, _, qErr := r.do("PUT", "/rest/queue/simple", map[string]any{
			"name":         "WANLAB-agg-" + wan,
			"target":       ip + "/32",
			"packet-marks": "aggq-" + wan,
			"max-limit":    fmt.Sprintf("%dM/%dM", lim*2, lim), // ROS 格式: 上传/下载, 下载按份额限死
			"comment":      aggComment + " " + wan,
		}); qErr != nil {
			return fmt.Errorf("建限速队列失败(%s): %w", wan, qErr)
		}
		}
		// ★必须置顶: 追加到链尾会落在别的 passthrough=no 规则后面, ROS 直接把它标成
		// invalid(永不匹配), 表现为三条线都不走自己那段端口。建完立刻 move 到第 0 条。
		if id, ok := lastRuleID(resp); ok {
			_, _, mErr := r.do("POST", "/rest/ip/firewall/mangle/move", map[string]any{
				"numbers": id, "destination": "0",
			})
			if mErr != nil {
				return fmt.Errorf("规则置顶失败(%s): %w", wan, mErr)
			}
		}
	}
	return nil
}

// lastRuleID 从 PUT 返回的规则对象里取 .id
func lastRuleID(b []byte) (string, bool) {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return "", false
	}
	id, _ := m[".id"].(string)
	return id, id != ""
}

// aggLastPerLine 保存上一轮 aggRun 的客户端侧分线字节数与耗时(秒)。
// 用客户端 curl 自己的字节数算分担比例, 比 SNMP 采样准 —— 后者会把家里其它流量也算进去。
var aggLastPerLine [2]any

// aggJob 一条线的任务: 用哪台源站拉、开多少连接。
type aggJob struct {
	Nodes   []Node // 该线的线程轮流打这几台源站(单台 VPS 上行 1G, 喂不满宽线)
	Threads int
}

// pickAggNodes 自动模式: 三条线各挑一台不同的源站。
// ★单源实测行不通: 三线都从同一台拉时, RTT/丢包较差的那条线会被另外两条饿死(只拿到 2%),
// 只有每线独立源站, 分担比例才反映家宽本身。
func pickAggNodes(n int) []Node {
	// 优先级 = 配置 nodes 的书写顺序(把实测稳的源站排前面即可);
	// 没装文件服务/被限速的节点不要放进名单, 选了也是死流。
	var out []Node
	used := map[string]bool{}
	for _, nd := range cfg.Nodes {
		if !used[nd.IP] {
			used[nd.IP] = true
			out = append(out, nd)
		}
		if len(out) >= n {
			break
		}
	}
	return out
}
// aggRun 按 plan 给每条线分配线程数, 每条连接用该线端口段内的独立源端口,
// 由 ROS 的「源端口段 → 路由表」规则钉住, 所以实际分担比例 ≈ 线程比例。
// offset 让每次重跑换一段端口, 避免上一轮的 TIME_WAIT 端口 bind 失败。
func aggRun(ctx context.Context, plan map[string]aggJob, secs, offset int) HTTPResult {
	total := 0
	for _, jb := range plan {
		total += jb.Threads
	}
	if total < 1 {
		total = 1
	}
	if secs < 3 {
		secs = 10
	}
	r := HTTPResult{Node: "多源自动", Threads: total, Seconds: float64(secs), Mode: "agg"}
	type res struct {
		bytes int64
		wan   string
		code  int
		err   error
	}
	ch := make(chan res, total)
	cctx, cancel := context.WithTimeout(ctx, time.Duration(secs+20)*time.Second)
	defer cancel()
	start := time.Now()
	launchIdx := 0
	for _, wan := range lineIDs() {
		base := aggPortBaseOf(wan)
		jb := plan[wan]
		n := jb.Threads
		if n < 1 || len(jb.Nodes) == 0 {
			continue
		}
		if offset+n > aggPortSpan {
			offset = 0 // 放不下就从头开始
		}
		for j := 0; j < n; j++ {
			nodeIP := jb.Nodes[j%len(jb.Nodes)].IP
			stagger := time.Duration(launchIdx) * 25 * time.Millisecond // 起流错峰, 避免 32 条连接同毫秒 SYN 冲撞
			launchIdx++
			go func(port int, nodeIP, wan string) {
				if stagger > 0 {
					time.Sleep(stagger)
				}
				url := fmt.Sprintf("http://%s:8899/2g.bin?x=%d", nodeIP, time.Now().UnixNano())
				out, err := runCmd(cctx, "curl", "-4", "-s", "-o", "/dev/null", "-m", strconv.Itoa(secs),
					"--local-port", strconv.Itoa(port),
					"-w", "%{http_code} %{size_download}", url)
				fields := strings.Fields(out)
				var code int
				var n int64
				if len(fields) == 2 {
					code, _ = strconv.Atoi(fields[0])
					n, _ = strconv.ParseInt(fields[1], 10, 64)
				}
				ch <- res{bytes: n, wan: wan, code: code, err: err}
			}(base+offset+j, nodeIP, wan)
		}
	}
	var sum int64
	var lastErr string
	perLine := map[string]int64{"wan1": 0, "wan2": 0, "wan3": 0}
	for i := 0; i < total; i++ {
		rr := <-ch
		sum += rr.bytes
		if _, ok := perLine[rr.wan]; ok {
			perLine[rr.wan] += rr.bytes
		}
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
	r.Bytes = sum
	r.Mbps = float64(sum) * 8 / el / 1e6
	aggLastPerLine[0], aggLastPerLine[1] = perLine, el
	if sum == 0 {
		r.Error = "没有收到数据"
		if lastErr != "" {
			r.Error += ": " + lastErr
		}
	}
	return r
}

// aggRateCollector 在测试窗口内用 PPPoE 计数器差值算每线速率:
// 每 500ms 读一次累计计数器, 每点速率 = 该线两次读数的字节差 / 两次读取的真实
// 时间差。旧实现是每秒去抄瞬时速率快照(采样器自己的节拍与抄表节拍互相漂移,
// 还会重复抄到同一个快照), 精度差且尖峰失真; 计数器差值与节拍无关, 慢读/快读
// 都准确。窗口平均同样由首尾计数器差值直接算, 不再对瞬时值做二次平均。
type aggRateCollector struct {
	mu     sync.Mutex
	base   map[string]lineStamp // 窗口起点读数
	last   map[string]lineStamp // 上一个采样点读数
	start  time.Time
	series []AggPoint
	stop   chan struct{}
	done   chan struct{}
}

func newAggRateCollector(since time.Time) *aggRateCollector {
	snap := rateCountersSnapshot()
	return &aggRateCollector{
		base:  snap,
		last:  snap,
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
		start: since,
	}
}

func (c *aggRateCollector) run() {
	defer close(c.done)
	tk := time.NewTicker(500 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-c.stop:
			return
		case <-tk.C:
			cur := rateCountersSnapshot()
			pt := AggPoint{T: math.Round(time.Since(c.start).Seconds()*10) / 10}
			vals := map[string]*float64{"wan1": &pt.Wan1, "wan2": &pt.Wan2, "wan3": &pt.Wan3}
			c.mu.Lock()
			for k, dst := range vals {
				now, ok1 := cur[k]
				prev, ok2 := c.last[k]
				if !ok1 || !ok2 {
					continue
				}
				dt := now.At.Sub(prev.At).Seconds()
				if dt >= 0.3 && now.Rx >= prev.Rx {
					v := float64(now.Rx-prev.Rx) * 8 / dt / 1e6
					if v <= 6000 { // 与采样器同一道计数器跳变护栏
						*dst = v
					}
				}
			}
			c.last = cur
			c.series = append(c.series, pt)
			c.mu.Unlock()
		}
	}
}

func (c *aggRateCollector) finish() (map[string]AggLine, int, []AggPoint) {
	close(c.stop)
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	end := rateCountersSnapshot()
	out := map[string]AggLine{}
	for _, k := range lineIDs() {
		b, ok1 := c.base[k]
		e, ok2 := end[k]
		if !ok1 || !ok2 {
			continue
		}
		dt := e.At.Sub(b.At).Seconds()
		if dt < 0.5 || e.Rx < b.Rx || e.Tx < b.Tx {
			continue
		}
		out[k] = AggLine{
			Down: float64(e.Rx-b.Rx) * 8 / dt / 1e6,
			Up:   float64(e.Tx-b.Tx) * 8 / dt / 1e6,
		}
	}
	return out, len(c.series), c.series
}

// aggLineCapMap 各线的理论带宽(Mbps): 由配置 lines[].bandwidth_mbps 派生(未配按 1000)。
// 分担比例按这个理论值算(例: 1000:2000:1000 = 1:2:1), 不用实测值。
func aggLineCapMap() map[string]float64 {
	out := map[string]float64{}
	for _, l := range lineDefs() {
		bw := l.BandwidthMbps
		if bw <= 0 {
			bw = 1000
		}
		out[l.ID] = bw
	}
	return out
}

// aggCapTotal 各线理论总带宽
func aggCapTotal() float64 {
	t := 0.0
	for _, v := range aggLineCapMap() {
		t += v
	}
	return t
}

// aggAllocTotal 汇总各线已分配的流数。
func aggAllocTotal(m map[string]int) int {
	t := 0
	for _, v := range m {
		t += v
	}
	return t
}

// aggTargetShareMap 各线期望分担比例: 按理论带宽占比(例: 1000/2000/1000 → 25%/50%/25%)。
func aggTargetShareMap() map[string]float64 {
	caps := aggLineCapMap()
	total := 0.0
	for _, v := range caps {
		total += v
	}
	out := map[string]float64{}
	if total <= 0 {
		return out
	}
	for k, v := range caps {
		out[k] = v / total
	}
	return out
}

// aggLopsided 按 1:2:1 的期望值判断是否没按比例分担: 任一条偏离期望超过 ±18 个百分点就算偏斜。
// 容差口径由 wanlab_test.go 的 TestAggLopsided 锁定: 均分 33/34/33 与 39/33/28 都必须算不偏斜
// (wan2 期望 50%, 33% 距下限只差 17 个点), 容差小于 17 都会误杀这两类正常分布;
// 曾收紧到 ±8 导致单测失败, 已回滚到 ±18 并在此注明, 改口径须同步改测试用例。
func aggLopsided(lines map[string]AggLine) bool {
	var sum float64
	for _, l := range lines {
		if l.Down > 0 {
			sum += l.Down
		}
	}
	if sum < 100 { // 启动瞬间流量太小, 判了也没意义
		return false
	}
	for k, want := range aggTargetShareMap() {
		got := lines[k].Down / sum
		if got < want-0.18-1e-9 || got > want+0.18+1e-9 {
			return true
		}
	}
	return false
}

// aggShare 返回三线实际占比, 给响应和日志用。
func aggShare(lines map[string]AggLine) map[string]float64 {
	var sum float64
	for _, l := range lines {
		if l.Down > 0 {
			sum += l.Down
		}
	}
	out := map[string]float64{}
	if sum <= 0 {
		return out
	}
	for k, l := range lines {
		out[k] = l.Down / sum
	}
	return out
}

func readyStr(ok bool) string {
	if ok {
		return "就绪"
	}
	return "超时未就绪"
}

// aggWaitReady 逐线探活: 用每线端口段高位端口(+350 起, 不占正式测试端口)从该线
// 源站拉一小段数据, 3 秒内拿到 >1MB 才算该线规则已收敛可用。三线全就绪立即返回,
// 否则每 2 秒重试, 最多 12 轮(~30 秒); 仍未就绪也返回, 由正式测试结果说话。
func aggWaitReady(ctx context.Context, lineSrc map[string][]Node) map[string]bool {
	ready := map[string]bool{"wan1": false, "wan2": false, "wan3": false}
	for round := 0; round < 12; round++ {
		all := true
		for _, wan := range lineIDs() {
			if ready[wan] {
				continue
			}
			nodes := lineSrc[wan]
			if len(nodes) == 0 {
				ready[wan] = true
				continue
			}
			port := aggPortBaseOf(wan) + 350 + round
			url := fmt.Sprintf("http://%s:8899/2g.bin?probe=%d", nodes[0].IP, time.Now().UnixNano())
			cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			out, _ := runCmd(cctx, "curl", "-4", "-s", "-o", "/dev/null", "-m", "3",
				"--local-port", strconv.Itoa(port),
				"-w", "%{http_code} %{size_download}", url)
			cancel()
			if f := strings.Fields(out); len(f) == 2 {
				if n, err := strconv.ParseInt(f[1], 10, 64); err == nil && n > 1_000_000 {
					ready[wan] = true
				}
			}
			if !ready[wan] {
				all = false
			}
		}
		if all {
			return ready
		}
		select {
		case <-ctx.Done():
			return ready
		case <-time.After(2 * time.Second):
		}
	}
	return ready
}

// aggAllocByRate 按「目标份额 ÷ 每流实测速率」分配线程(2026-11-19 改, 取代固定 1:2:1 线程数)。
// ★旧策略的问题: 线程按理论带宽固定切 1:2:1, 默认每流速率三线相同; 实测每流速率
// 随 (线路×源站) 组合差 3~5 倍(RTT 32ms 的近端源 vs 160ms 的远端源), 线程份额
// 根本不等于字节份额, 慢线永远吃不饱、快线线程浪费, 重跑同分配也永远纠正不过来。
// 现在: 先探速得到每线每流速率, 线程数 ∝ 份额/每流速率; 已能喂满的线不给多余线程
// (上限 = 喂满理论带宽所需线程 ×1.3 + 2), 省下的线程让给慢线。
func aggAllocByRate(total int, perFlow map[string]float64) map[string]int {
	// 缺测的线用已测中位数兜底
	var vals []float64
	for _, wan := range lineIDs() {
		if v := perFlow[wan]; v > 0 {
			vals = append(vals, v)
		}
	}
	fallback := 60.0
	if len(vals) > 0 {
		sort.Float64s(vals)
		fallback = vals[len(vals)/2]
	}
	weight := map[string]float64{}
	sumW := 0.0
	for _, wan := range lineIDs() {
		pf := perFlow[wan]
		if pf <= 0 {
			pf = fallback
		}
		weight[wan] = aggTargetShareMap()[wan] / pf
		sumW += weight[wan]
	}
	alloc := map[string]int{}
	used := 0
	for _, wan := range lineIDs() {
		n := int(math.Round(float64(total) * weight[wan] / sumW))
		if n < 3 {
			n = 3
		}
		// 喂满上限: 超过理论带宽所需线程再多给只是挤源站
		pf := perFlow[wan]
		if pf <= 0 {
			pf = fallback
		}
		if capN := int(math.Ceil(aggLineCapMap()[wan]/pf*1.3)) + 2; n > capN {
			n = capN
		}
		alloc[wan] = n
		used += n
	}
	// 总量校正: 超了从最大头扣, 少了(因喂满上限省下的)不硬凑——省线程是目的之一
	for used > total {
		big := "wan2"
		for _, wan := range lineIDs() {
			if alloc[wan] > alloc[big] {
				big = wan
			}
		}
		if alloc[big] <= 3 {
			break
		}
		alloc[big]--
		used--
	}
	return alloc
}

// aggProbe 并行探速: 每线 4 流 × 4 秒, 返回每线总速率与每流速率。
// 用正式测试同一套端口段分流, 探到的就是正式跑的路径。
func aggProbe(ctx context.Context, lineSrc map[string][]Node, offset int) (perLine, perFlow map[string]float64) {
	plan := map[string]aggJob{}
	for _, wan := range lineIDs() {
		if len(lineSrc[wan]) > 0 {
			plan[wan] = aggJob{Nodes: lineSrc[wan], Threads: 4}
		}
	}
	aggRun(ctx, plan, 4, offset)
	perLine = map[string]float64{}
	perFlow = map[string]float64{}
	if pl, ok := aggLastPerLine[0].(map[string]int64); ok {
		el, _ := aggLastPerLine[1].(float64)
		if el < 0.2 {
			el = 0.2
		}
		for _, wan := range lineIDs() {
			perLine[wan] = float64(pl[wan]) * 8 / el / 1e6
			perFlow[wan] = perLine[wan] / 4
		}
	}
	return perLine, perFlow
}

// aggFleetRates 读最近一次机队体检结果, 返回 (节点,线路) -> 下行 Mbps 与采样时间。
func aggFleetRates() (map[string]map[string]float64, string) {
	b, err := os.ReadFile(fleetCheckFile)
	if err != nil {
		return nil, ""
	}
	var fc struct {
		FinishedAt string `json:"finished_at"`
		Results    []struct {
			Key      string  `json:"key"`
			Line     string  `json:"line"`
			Status   string  `json:"status"`
			DownMbps float64 `json:"down_mbps"`
		} `json:"results"`
	}
	if json.Unmarshal(b, &fc) != nil {
		return nil, ""
	}
	out := map[string]map[string]float64{}
	lineName := map[string]string{"1": "wan1", "2": "wan2", "3": "wan3"}
	for _, r := range fc.Results {
		wan, ok := lineName[r.Line]
		if !ok || r.Status != "ok" || r.DownMbps <= 0 {
			continue
		}
		if out[r.Key] == nil {
			out[r.Key] = map[string]float64{}
		}
		out[r.Key][wan] = r.DownMbps
	}
	return out, fc.FinishedAt
}

// aggGroupOf 源站的「出口组」: 配置里同 group 的节点共享同一出口上限, 同组;
// 未配 group 的各成一组。自动分配时三条线尽量不同组, 避免总速率被同一出口顶住。
func aggGroupOf(key string) string {
	if nd, ok := nodeByKey(key); ok && nd.Group != "" {
		return nd.Group
	}
	return key
}

// aggAutoPlan 自动模式的每线候选与初始分配:
// 按机队体检矩阵给每条线排候选(实测下行降序), 贪心分配时跳过已被其它线占用的
// 出口组; 第二条线给两个不同组的源站轮转。体检数据缺失时回退按配置顺序选源。
// 明显慢的源站由下面的下行阈值挡掉; 某节点在某条线上实测差, 把它在配置里后置即可。
func aggAutoPlan() (lineSrc map[string][]Node, cand map[string][]Node, note string) {
	rates, finishedAt := aggFleetRates()
	cand = map[string][]Node{}
	if len(rates) == 0 {
		picked := pickAggNodes(2)
		lineSrc = map[string][]Node{}
		if len(picked) >= 2 {
			lineSrc["wan1"] = picked[0:1]
			lineSrc["wan2"] = picked[0:2]
			lineSrc["wan3"] = picked[1:2]
		} else {
			for _, wn := range lineIDs() {
				lineSrc[wn] = picked
			}
		}
		for wn, ns := range lineSrc {
			cand[wn] = ns
		}
		return lineSrc, cand, "无体检数据, 回退按配置顺序选源"
	}
	nodeOf := map[string]Node{}
	for _, nd := range cfg.Nodes {
		nodeOf[nd.Key] = nd
	}
	for _, wan := range lineIDs() {
		type candT struct {
			key  string
			down float64
		}
		var cs []candT
		for key, per := range rates {
			d := per[wan]
			if d < 200 {
				continue
			}
			if _, ok := nodeOf[key]; ok {
				cs = append(cs, candT{key, d})
			}
		}
		sort.Slice(cs, func(i, j int) bool { return cs[i].down > cs[j].down })
		var list []Node
		for i, c := range cs {
			if i >= 4 {
				break
			}
			list = append(list, nodeOf[c.key])
		}
		cand[wan] = list
	}
	// 贪心分配: 先定最难的 wan2(宽线), 再 wan1、wan3; 优先没被占用的出口组
	usedGroup := map[string]bool{}
	usedNode := map[string]bool{}
	lineSrc = map[string][]Node{}
	pickFor := func(wan string, n int) []Node {
		var out []Node
		inOut := func(nd Node) bool {
			for _, o := range out {
				if o.Key == nd.Key {
					return true
				}
			}
			return false
		}
		// 三趟: ①组与节点都没被占 ②节点没被占(同组可) ③任意候选补齐
		for pass := 0; pass < 3 && len(out) < n; pass++ {
			for _, nd := range cand[wan] {
				if len(out) >= n {
					break
				}
				if inOut(nd) {
					continue
				}
				if pass == 0 && (usedGroup[aggGroupOf(nd.Key)] || usedNode[nd.Key]) {
					continue
				}
				if pass == 1 && usedNode[nd.Key] {
					continue
				}
				out = append(out, nd)
				usedGroup[aggGroupOf(nd.Key)] = true
				usedNode[nd.Key] = true
			}
		}
		return out
	}
	lineSrc["wan2"] = pickFor("wan2", 2)
	lineSrc["wan1"] = pickFor("wan1", 1)
	lineSrc["wan3"] = pickFor("wan3", 1)
	for _, wan := range lineIDs() { // 某线候选为空时回退旧方案对应线
		if len(lineSrc[wan]) == 0 {
			picked := pickAggNodes(2)
			if len(picked) > 0 {
				lineSrc[wan] = picked[0:1]
				cand[wan] = lineSrc[wan]
			}
		}
		if len(cand[wan]) == 0 {
			cand[wan] = lineSrc[wan]
		}
	}
	return lineSrc, cand, "体检矩阵 " + finishedAt
}

// handleAgg: POST /api/agg {node, threads, secs}
func handleAgg(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Node       string `json:"node"`
		Threads    int    `json:"threads"`
		Secs       int    `json:"secs"`
		LimitTotal int    `json:"limit_total"` // 三线合计限速(Mbps), 0=按理论值(只封顶不压速)
		Rounds     int    `json:"rounds"`      // 手动跑几轮(1~5), 起速慢就多跑几轮看稳定值
		Src        map[string]string `json:"src"` // 每线自选源站 {"wan1":"node1"}, 缺省=自动/单源
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	if body.Threads <= 0 {
		body.Threads = 32
	}
	if body.Threads > 128 {
		body.Threads = 128
	}
	if body.Secs < 5 {
		body.Secs = 12
	}
	if body.Secs > 60 {
		body.Secs = 60
	}
	rounds := body.Rounds
	if rounds < 1 {
		rounds = 1
	}
	if rounds > 5 {
		rounds = 5
	}
	if !tryExitGate("三线聚合") {
		holder, _ := exitGateBusy()
		writeJSON(w, 409, map[string]string{"error": holder + " 正在用线, 等它结束再聚合"})
		return
	}
	defer releaseExitGate()
	// 源站: 指定节点(单源) 或 auto(多源分线, 避免单台源站上行成为总带宽天花板)。
	// ★2026-11-13 改回多源: 单源实测三线合计被卡在源站一台的出口(~2.1G),
	//   而三线理论合计 4G; 且单源时同源多路 TCP 互相抢占, 分担比例失真。
	//   wan2 是宽线, 给它两台源站轮转; wan1/wan3 各一台。
	autoMode := body.Node == "" || strings.EqualFold(body.Node, "auto")
	var srcNodes []Node
	lineSrc := map[string][]Node{}
	cand := map[string][]Node{}
	nodeLabel := ""
	if autoMode {
		var note string
		lineSrc, cand, note = aggAutoPlan()
		if len(lineSrc["wan1"]) == 0 && len(lineSrc["wan2"]) == 0 && len(lineSrc["wan3"]) == 0 {
			writeJSON(w, 500, map[string]string{"error": "没有可用源站"})
			return
		}
		nodeLabel = "多源自动(" + note + ")"
	} else {
		n, ok := nodeByKey(body.Node)
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "未知节点"})
			return
		}
		srcNodes = []Node{n}
		for _, wn := range lineIDs() {
			lineSrc[wn] = srcNodes
			cand[wn] = srcNodes
		}
		nodeLabel = n.Label
	}

	// 每线自选源站(可选, 2026-11-13): body.Src 指定后覆盖上面的自动/单源分配,
	// 未指定的线保持原分配。源站集合按覆盖后的 lineSrc 重算, 供 HTTPPrepare 准备。
	if len(body.Src) > 0 {
		for _, wn := range lineIDs() {
			key, ok := body.Src[wn]
			if !ok || key == "" {
				continue
			}
			n, ok := nodeByKey(key)
			if !ok {
				writeJSON(w, 400, map[string]string{"error": "未知节点: " + key})
				return
			}
			lineSrc[wn] = []Node{n}
			cand[wn] = []Node{n}
		}
		srcNodes = srcNodes[:0]
		seenSrc := map[string]bool{}
		for _, wn := range lineIDs() {
			for _, nd := range lineSrc[wn] {
				if !seenSrc[nd.Key] {
					seenSrc[nd.Key] = true
					srcNodes = append(srcNodes, nd)
				}
			}
		}
		nodeLabel = "自选源站"
	}
	steps := []string{}
	step := func(format string, a ...any) { steps = append(steps, fmt.Sprintf(format, a...)) }
	keysOf := func(ns []Node) string {
		ks := []string{}
		for _, nd := range ns {
			ks = append(ks, nd.Key)
		}
		return strings.Join(ks, "+")
	}
	step("源站分配: WAN1→%s / WAN2→%s / WAN3→%s (%s)", keysOf(lineSrc["wan1"]), keysOf(lineSrc["wan2"]), keysOf(lineSrc["wan3"]), nodeLabel)
	if !autoMode && len(body.Src) == 0 {
		step("⚠ 单源模式: 三线共用一台源站, 总速率上限就是这台源站的出口(实测 gao 单源出口约 1.6G), 分配再准也超不过去; 要跑满三线请用自动模式或每线自选不同源站")
	}
	pinMu.Lock() // 与切出口互斥, 避免规则互相踩
	defer pinMu.Unlock()

	// 准备集合 = 每线候选的并集(探速可能换源, 候选都要先放行 8899)
	srcNodes = srcNodes[:0]
	{
		seen := map[string]bool{}
		for _, wn := range lineIDs() {
			for _, nd := range cand[wn] {
				if !seen[nd.Key] {
					seen[nd.Key] = true
					srcNodes = append(srcNodes, nd)
				}
			}
		}
	}
	for _, sn := range srcNodes {
		if out, err := HTTPPrepare(r.Context(), sn); err != nil {
			writeJSON(w, 500, map[string]string{"error": "源站准备失败(" + sn.Key + "): " + oneline(out) + " " + errStr(err)})
			return
		}
		step("源站 %s(%s) 已准备: 已放行 8899 并确认测速文件", sn.Key, sn.IP)
	}
	defer func() {
		for _, sn := range srcNodes {
			HTTPCleanup(context.Background(), sn)
		}
	}()

	ip := myIP
	if ip == "" {
		ip = LocalIP()
	}
	if ip == "" {
		writeJSON(w, 500, map[string]string{"error": "取不到本机 eth0 IPv4"})
		return
	}

	// 1) 暂停面板自己的钉线(它 passthrough=no, 会压住聚合规则)
	restored := "本来就没有钉线规则"
	if p, err := ros.FindPinRule(ip); err == nil && p != nil {
		wasDisabled := p.Disabled == "true"
		if !wasDisabled {
			if err := ros.PatchPinRule(p.ID, map[string]any{"disabled": "yes"}); err != nil {
				writeJSON(w, 500, map[string]string{"error": "暂停钉线失败: " + err.Error()})
				return
			}
		}
		// 测完恢复原先的 disabled 状态与 mark
		defer func() {
			fields := map[string]any{"new-routing-mark": p.Mark}
			if wasDisabled {
				fields["disabled"] = "yes"
			} else {
				fields["disabled"] = "no"
			}
			_ = ros.PatchPinRule(p.ID, fields)
		}()
		restored = "测完已恢复钉线 " + p.Mark
	}

	if restored == "本来就没有钉线规则" {
		step("面板钉线: 无钉线规则, 不需要暂停")
	} else {
		step("面板钉线: 已暂停钉线规则(它 passthrough=no 会压住聚合分流), 测完自动恢复")
	}

	// 2) 建聚合规则。先按线路理论值(1000/2000/1000)建, 探速后如果这台测试机喂不满再改写队列限速。
	ros.aggCleanup()
	defer ros.aggCleanup()
	theoryTotal := int(aggCapTotal())
	totalLimit := body.LimitTotal // >0 = 省流量限速档; 0 = 不限速(不建队列, 自然跑到顶)
	effLimit := totalLimit
	if effLimit <= 0 {
		effLimit = theoryTotal
	}
	autoScaled := false
	if err := ros.aggSetup(ip, totalLimit); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if totalLimit > 0 {
		step("ROS 规则已写入: 3 条源端口分流(mark-routing) + 每线限速队列 %d/%d/%d Mbps", aggLimitOfFor(totalLimit, "wan1"), aggLimitOfFor(totalLimit, "wan2"), aggLimitOfFor(totalLimit, "wan3"))
	} else {
		step("ROS 规则已写入: 3 条源端口分流(mark-routing), 不限速(无队列), 自然跑到顶")
	}

	// ★2.5) 规则收敛探活(2026-11-13 实测定位的根因修复): mangle/队列刚建好就立刻
	// 并发起流时, 先建的两条线(端口段)的连接会在 ROS 里被黑洞——先收到约 2MB,
	// 然后回程断流、conntrack 条目消失, 只有最后建的那条线存活, 三线合计被卡在
	// 单线 ~880Mbps; 同样的流晚 10~20 秒再起就完全正常。故正式开测前逐线用高位
	// 探测端口拉小流量探活, 三线都通过才开测(最多等约 30 秒, 等不到也照常开测)。
	readyMap := aggWaitReady(r.Context(), lineSrc)
	readyLog := fmt.Sprintf("规则收敛探活: WAN1 %s / WAN2 %s / WAN3 %s", readyStr(readyMap["wan1"]), readyStr(readyMap["wan2"]), readyStr(readyMap["wan3"]))
	log.Printf("agg %s", readyLog)

	buildPlan := func(al map[string]int) map[string]aggJob {
		p := map[string]aggJob{}
		for _, wan := range lineIDs() {
			p[wan] = aggJob{Nodes: lineSrc[wan], Threads: al[wan]} // 每条线用自己的源站组, 线程在组内轮转
		}
		return p
	}

	// 3) 探速定分配(2026-11-19 改): 先每线 4 流探 4 秒, 实测每流速率;
	//    某线探速远低于体检预期(<45%)且还有候选源站时换源再探一次。
	fleetRates, _ := aggFleetRates()
	perLine, perFlow := aggProbe(r.Context(), lineSrc, 390)
	step("探速(每线 4 流×4 秒): WAN1 %.0f / WAN2 %.0f / WAN3 %.0f Mbps", perLine["wan1"], perLine["wan2"], perLine["wan3"])
	// tried 记录每条线探过的源站, 换源只向前不回头(防 jp->gao->jp 乒乓);
	// 换源门槛: 探速是三线同时探(互相争抢), 与体检的单线独占数值不可直接比,
	// 预期门槛放宽到 30%, 另加 120Mbps 绝对门槛。
	// bestProbe 记录每条线探到过的最好源站组合, 换源只升不降: 某次换源后更差就还原。
	bestProbeVal := map[string]float64{}
	bestProbeSrc := map[string][]Node{}
	recordBest := func() {
		for _, wan := range lineIDs() {
			if perLine[wan] > bestProbeVal[wan] {
				bestProbeVal[wan] = perLine[wan]
				bestProbeSrc[wan] = append([]Node{}, lineSrc[wan]...)
			}
		}
	}
	recordBest()
	tried := map[string]map[string]bool{}
	for _, wan := range lineIDs() {
		tried[wan] = map[string]bool{}
		if len(lineSrc[wan]) > 0 {
			tried[wan][lineSrc[wan][0].Key] = true
		}
	}
	for swapRound := 0; swapRound < 2; swapRound++ {
		swapped := false
		for _, wan := range lineIDs() {
			cs := cand[wan]
			if len(cs) <= 1 || len(lineSrc[wan]) == 0 {
				continue
			}
			curKey := lineSrc[wan][0].Key
			expect := fleetRates[curKey][wan]
			bad := perLine[wan] < 120 || (expect > 0 && perLine[wan] < expect*0.30)
			if !bad {
				continue
			}
			// 找下一个没在该线用过的候选
			var next *Node
			for i := range cs {
				if cs[i].Key != curKey && !tried[wan][cs[i].Key] {
					n := cs[i]
					// 该候选是否已是这条线当前源站组的一员(wan2 双源时第二台不算换)
					already := false
					for _, o := range lineSrc[wan] {
						if o.Key == n.Key {
							already = true
						}
					}
					if !already {
						next = &n
						break
					}
				}
			}
			if next == nil {
				continue
			}
			step("探速换源: %s 的 %s 只有 %.0f Mbps(预期 %.0f), 换 %s 再探", wan, curKey, perLine[wan], expect, next.Key)
			tried[wan][next.Key] = true
			if len(lineSrc[wan]) > 1 {
				lineSrc[wan] = []Node{*next, lineSrc[wan][1]}
			} else {
				lineSrc[wan] = []Node{*next}
			}
			swapped = true
		}
		if !swapped {
			break
		}
		perLine, perFlow = aggProbe(r.Context(), lineSrc, 394)
		step("换源后探速: WAN1 %.0f / WAN2 %.0f / WAN3 %.0f Mbps", perLine["wan1"], perLine["wan2"], perLine["wan3"])
		recordBest()
	}
	// 还原到各自探速最好的源站组合(换源探差了的线不硬用新源)
	for _, wan := range lineIDs() {
		if bs := bestProbeSrc[wan]; len(bs) > 0 && bs[0].Key != lineSrc[wan][0].Key {
			step("源站还原: %s 换源后探速未超过最初的 %.0f Mbps, 还原为 %s", wan, bestProbeVal[wan], keysOf(bs))
			lineSrc[wan] = bs
		}
	}
	perLine, perFlow = aggProbe(r.Context(), lineSrc, 398)
	step("最终探速(定分配): WAN1 %.0f / WAN2 %.0f / WAN3 %.0f Mbps", perLine["wan1"], perLine["wan2"], perLine["wan3"])

	// 4) 自适应分配 + 多轮取优: 线程 ∝ 目标份额/每流速率; 每轮后按本轮实测
	//    每流速率重算分配; 最终取「总速率最高」的一轮(旧版取最接近 1:2:1 的一轮,
	//    会选一条慢但匀的轮, 且大数字与分线数字来自不同轮, 互相打架)。
	alloc := aggAllocByRate(body.Threads, perFlow)
	step("开始测速: 探速定分配 %d 线程(WAN1/WAN2/WAN3 = %d/%d/%d, 按每流速率 %.0f/%.0f/%.0f Mbps), 每轮 %d 秒, 最多 %d 轮, 取总速率最高轮",
		alloc["wan1"]+alloc["wan2"]+alloc["wan3"], alloc["wan1"], alloc["wan2"], alloc["wan3"],
		perFlow["wan1"], perFlow["wan2"], perFlow["wan3"], body.Secs, rounds)
	var res HTTPResult
	var lines map[string]AggLine
	var series []AggPoint
	var attemptLog []string
	samples := 0
	attempts := 0
	bestMbps := -1.0
	var bestRes HTTPResult
	var bestSeries []AggPoint
	bestAlloc := alloc
	for attempts < rounds {
		attempts++
		col := newAggRateCollector(time.Now())
		go col.run()
		curRes := aggRun(r.Context(), buildPlan(alloc), body.Secs, (attempts-1)*100)
		curLines, curSamples, curSeries := col.finish()
		// 用客户端侧字节数覆盖接口口径, 避免被家里其它流量干扰
		if pl, ok := aggLastPerLine[0].(map[string]int64); ok {
			el, _ := aggLastPerLine[1].(float64)
			if el < 0.2 {
				el = 0.2
			}
			fixed := map[string]AggLine{}
			for _, k := range lineIDs() {
				fixed[k] = AggLine{Down: float64(pl[k]) * 8 / el / 1e6, Up: curLines[k].Up}
			}
			curLines = fixed
		}
		sh := aggShare(curLines)
		dev := 0.0
		for k, w := range aggTargetShareMap() {
			if d := math.Abs(sh[k] - w); d > dev {
				dev = d
			}
		}
		attemptLog = append(attemptLog, fmt.Sprintf("第%d轮 %d/%d/%d 线程 -> 合计 %.0f Mbps, 占比 %.0f%%/%.0f%%/%.0f%% (偏离 %.0f 个点)",
			attempts, alloc["wan1"], alloc["wan2"], alloc["wan3"], curRes.Mbps,
			sh["wan1"]*100, sh["wan2"]*100, sh["wan3"]*100, dev*100))
		if curRes.Error != "" {
			res, lines, series, samples = curRes, curLines, curSeries, curSamples
			break
		}
		if curRes.Mbps > bestMbps {
			bestMbps = curRes.Mbps
			bestRes, lines, bestSeries, samples = curRes, curLines, curSeries, curSamples
			bestAlloc = alloc
		}
		// 按本轮实测每流速率重算下一轮分配
		if attempts < rounds {
			newPerFlow := map[string]float64{}
			for _, wan := range lineIDs() {
				if alloc[wan] > 0 {
					newPerFlow[wan] = curLines[wan].Down / float64(alloc[wan])
				}
			}
			alloc = aggAllocByRate(body.Threads, newPerFlow)
		}
	}
	if bestMbps >= 0 {
		res, series, alloc = bestRes, bestSeries, bestAlloc
	}
	// 线程饥饿提示: 某线离理论带宽还差得远且按其实测每流速率算需要多得多的线程时,
	// 明说建议加大线程数, 而不是让用户对着低数字猜。
	if lines != nil {
		for _, wan := range lineIDs() {
			if bestAlloc[wan] <= 0 || lines[wan].Down <= 0 {
				continue
			}
			pf := lines[wan].Down / float64(bestAlloc[wan])
			need := int(math.Ceil(aggLineCapMap()[wan] / pf))
			if lines[wan].Down < aggLineCapMap()[wan]*0.6 && need > bestAlloc[wan]*3/2 {
				attemptLog = append(attemptLog, fmt.Sprintf("提示: %s 实测每流仅 %.0f Mbps, 填满 %.0fM 约需 %d 条流(本次给了 %d 条), 下次把总线程调到 %d 再测", wan, pf, aggLineCapMap()[wan], need, bestAlloc[wan], need+aggAllocTotal(bestAlloc)-bestAlloc[wan]))
			}
		}
	}

	lineNodes := map[string]string{}
	for _, wan := range lineIDs() {
		keys := []string{}
		for _, nd := range lineSrc[wan] {
			keys = append(keys, nd.Key)
		}
		lineNodes[wan] = strings.Join(keys, "+")
	}
	qNote := ""
	if totalLimit > 0 {
		qNote = "与限速队列"
	}
	fullLog := append([]string{}, steps...)
	fullLog = append(fullLog, readyLog)
	fullLog = append(fullLog, attemptLog...)
	fullLog = append(fullLog,
		"收尾: 已删除 ROS 上的临时分流规则"+qNote,
		"收尾: 已关闭各源站的 8899 放行",
		"收尾: "+restored)
	attemptLog = fullLog
	out := AggResult{
		Node: nodeLabel, Threads: alloc["wan1"] + alloc["wan2"] + alloc["wan3"], Seconds: res.Seconds,
		Bytes: res.Bytes, Mbps: res.Mbps, Lines: lines, Samples: samples,
		Restored: restored, Error: res.Error, Attempts: attempts,
		Ratio: "1:2:1", Series: series, Alloc: alloc, LineNodes: lineNodes, AttemptLog: attemptLog,
		LimitTotal: totalLimit, TheoryTotal: theoryTotal, AutoScaled: autoScaled, Rounds: attempts,
		Limits: map[string]int{"wan1": aggLimitOfFor(totalLimit, "wan1"), "wan2": aggLimitOfFor(totalLimit, "wan2"), "wan3": aggLimitOfFor(totalLimit, "wan3")},
	}
	for _, l := range lines {
		out.SumLines += l.Down
	}
	out.Shares = aggShare(lines)
	// 打不满理论合计时给个中性提示(2026-11-13 改): 此前文案一口咬定"测试端是瓶颈",
	// 实测证伪——同一测试端单线钉线可跑满每条线、聚合可达 ~2.2G; 合计低于理论值
	// 常见于源站出口合计或 ROS 转发上限, 不等于某条线路不达标, 看分线数值判断。
	if out.SumLines < float64(effLimit)*0.6 {
		out.Warning = fmt.Sprintf("实测合计 %.0f Mbps, 为理论合计 %d Mbps 的 %.0f%%: 低于理论值多半是源站出口合计或网关转发先到顶, 不代表线路不达标; 单条线是否达标看上面各线数值。", out.SumLines, effLimit, out.SumLines*100/float64(effLimit))
	}
	if aggLopsided(lines) {
		out.Lopsided = true
		log.Printf("agg 分布仍偏斜(重跑 %d 次): %v", attempts, lines)
	}
	if out.Lines == nil {
		out.Lines = map[string]AggLine{}
	}
	writeJSON(w, 200, out)
}

var _ = strings.TrimSpace
