package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// WanRate 是某条 PPPoE 的瞬时速率(家宽视角: rx=下行, tx=上行)。
type WanRate struct {
	Down float64 `json:"down"` // Mbps
	Up   float64 `json:"up"`   // Mbps
	Rx   uint64  `json:"rx"`   // 累计字节
	Tx   uint64  `json:"tx"`
}

var (
	rateMu    sync.RWMutex
	rateTable = map[string]WanRate{} // wan1/wan2/wan3
	rateAt    time.Time
	rateTicks int
	rateErr   string
	rateBase  = map[string]lineStamp{} // 每条线各自的上次计数器读数+读取时刻
	rateCur   = map[string]lineStamp{} // 每条线最新计数器读数+读取时刻
)

// lineStamp 单条线的累计计数器读数与「这条线自己的」读取时刻。
// ★为什么必须每线独立计时: 三条线是三次独立 snmpget 串行读回来的, ROS 忙时
// 单轮读取耗时能从 ~10ms 漂到数秒; 旧实现三线共用一个 dt(轮次结束-上轮结束),
// 当慢轮后跟快轮时, 先读的线真实计数区间比 dt 长得多, 算出的速率能飙到
// 4000~7000Mbps(物理上不可能)。每线用自己的两次读取时刻作 dt 后与轮速无关。
type lineStamp struct {
	Rx uint64    `json:"rx"`
	Tx uint64    `json:"tx"`
	At time.Time `json:"at"`
}

// rateCountersSnapshot 返回每条线最新累计计数器与读取时刻(聚合曲线用计数器差值算, 不用瞬时速率二次采样)。
func rateCountersSnapshot() map[string]lineStamp {
	rateMu.RLock()
	defer rateMu.RUnlock()
	out := make(map[string]lineStamp, len(rateCur))
	for k, v := range rateCur {
		out[k] = v
	}
	return out
}

// wanIfaceMap 由配置 lines 派生: ROS pppoe 接口名 -> 线路 id。
func wanIfaceMap() map[string]string {
	m := map[string]string{}
	for _, l := range lineDefs() {
		m[l.PPPoEiface] = l.ID
	}
	return m
}

func rateSnapshot() map[string]WanRate {
	rateMu.RLock()
	defer rateMu.RUnlock()
	out := make(map[string]WanRate, len(rateTable))
	for k, v := range rateTable {
		out[k] = v
	}
	return out
}

// ---- 采样方式一: SNMP(首选) ----
// 这台 ROS 的 REST/www-ssl 每建一条新连接要 3~4 秒(实测 7.24.5),
// 1 秒轮询会被拖成 4 秒一次; SNMP 读 ifHCInOctets 只要 ~3ms, 所以默认走 SNMP。
// OID: 1.3.6.1.2.1.31.1.1.1.6 = ifHCInOctets(64位), .10 = ifHCOutOctets

func snmpCounters() (map[string]lineStamp, error) {
	res := map[string]lineStamp{}
	var lastErr error
	for _, key := range lineIDs() {
		idx, ok := cfg.IfIndex[key]
		if !ok {
			lastErr = fmt.Errorf("缺少 %s 的 ifIndex", key)
			continue
		}
		// 每条线单独一次 GET: 某条超时不影响其它两条
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		out, err := runCmd(ctx, "snmpget", "-v2c", "-c", cfg.SNMPCommunity, "-On", "-Oq", "-t", "2", "-r", "2", cfg.ROSHost,
			fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.6.%d", idx), fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.10.%d", idx))
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("%s: %v", key, err)
			continue
		}
		var in, ou uint64
		var gotIn, gotOut bool
		for _, line := range strings.Split(out, "\n") {
			// -Oq 输出形如 ".1.3.6...6.8 58181519234"(空格分隔, 无 '=')
			line = strings.TrimSpace(line)
			var oid, val string
			if i := strings.Index(line, "="); i >= 0 {
				oid, val = strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])
			} else if f := strings.Fields(line); len(f) >= 2 {
				oid, val = f[0], f[1]
			}
			n, e := strconv.ParseUint(val, 10, 64)
			if e != nil {
				continue
			}
			if strings.HasSuffix(oid, fmt.Sprintf(".6.%d", idx)) {
				in, gotIn = n, true
			} else if strings.HasSuffix(oid, fmt.Sprintf(".10.%d", idx)) {
				ou, gotOut = n, true
			}
		}
		if !gotIn || !gotOut {
			lastErr = fmt.Errorf("%s: 计数器不全", key)
			continue
		}
		res[key] = lineStamp{Rx: in, Tx: ou, At: time.Now()}
	}
	if len(res) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("SNMP 无数据")
		}
		return nil, lastErr
	}
	return res, nil
}

// ---- 采样方式二: REST 兜底(snmpget 不可用时, 5 秒一次) ----

func restCounters() (map[string]lineStamp, error) {
	b, err := ros.Get("/rest/interface")
	if err != nil {
		return nil, err
	}
	var all []map[string]any
	if json.Unmarshal(b, &all) != nil {
		return nil, fmt.Errorf("REST 响应解析失败")
	}
	res := map[string]lineStamp{}
	now := time.Now()
	for _, it := range all {
		name, _ := it["name"].(string)
		if key, ok := wanIfaceMap()[name]; ok {
			rx, _ := strconv.ParseUint(str(it["rx-byte"]), 10, 64)
			tx, _ := strconv.ParseUint(str(it["tx-byte"]), 10, 64)
			res[key] = lineStamp{Rx: rx, Tx: tx, At: now}
		}
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("REST 未返回 pppoe 接口")
	}
	return res, nil
}

// apply 用每条线自己的两次读取时刻作 dt 算速率; 计数器回退(接口重建)或
// 算出速率超过物理合理上限(6000Mbps, 三线任何一条都不可能)时视为计数器
// 跳变: 本轮不更新速率, 只重置基线, 下一轮恢复正常。
func apply(cur map[string]lineStamp) {
	rateMu.Lock()
	defer rateMu.Unlock()
	rateTicks++
	rateAt = time.Now()
	for k, v := range cur {
		r := WanRate{Rx: v.Rx, Tx: v.Tx, Down: -1, Up: -1}
		if p, ok := rateBase[k]; ok {
			dt := v.At.Sub(p.At).Seconds()
			if dt >= 0.5 {
				if v.Rx < p.Rx || v.Tx < p.Tx {
					r.Down, r.Up = 0, 0 // 计数器回退(重拨/接口重建): 归零并以本轮重置基线
				} else {
					down := float64(v.Rx-p.Rx) * 8 / dt / 1e6
					up := float64(v.Tx-p.Tx) * 8 / dt / 1e6
					if down <= 6000 && up <= 6000 {
						r.Down, r.Up = down, up
					}
				}
			}
		}
		if r.Down < 0 {
			old := rateTable[k]
			r.Down, r.Up = old.Down, old.Up
		}
		rateTable[k] = r
		rateBase[k] = v
		rateCur[k] = v
	}
}

// startRateSampler 每秒采一次三线计数器: 优先 SNMP, 失败累计到 5 次才退回 REST。
// 节拍补偿: 本轮读取耗时从 1 秒里扣掉, 实际周期不再漂成 1s+读取耗时;
// 即使某轮读取很慢, 每线速率仍由自己的 dt 决定, 不再产生假尖峰。
func startRateSampler(ctx context.Context) {
	fails := 0
	for {
		roundStart := time.Now()
		cur, err := snmpCounters()
		if err != nil {
			fails++
			if fails < 5 || fails%5 != 0 { // 前 4 次只是跳过, 之后每 5 秒兜底读一次 REST
				rateMu.Lock()
				rateErr = err.Error()
				rateMu.Unlock()
				if !pace(ctx, roundStart) {
					return
				}
				continue
			}
			cur, err = restCounters()
			if err != nil {
				rateMu.Lock()
				rateErr = err.Error()
				rateMu.Unlock()
				if !pace(ctx, roundStart) {
					return
				}
				continue
			}
		} else {
			fails = 0
		}
		apply(cur)
		rateMu.Lock()
		rateErr = ""
		rateMu.Unlock()
		if !pace(ctx, roundStart) {
			return
		}
	}
}

// pace 等到本轮满 1 秒节拍; ctx 结束返回 false。
func pace(ctx context.Context, roundStart time.Time) bool {
	if el := time.Since(roundStart); el < time.Second {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(time.Second - el):
		}
	}
	return true
}

func handleWanRate(w http.ResponseWriter, r *http.Request) {
	rateMu.RLock()
	meta := map[string]any{"ticks": rateTicks, "at": rateAt.Unix(), "err": rateErr}
	rateMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"ts":   time.Now().Unix(),
		"rate": rateSnapshot(),
		"meta": meta,
	})
}
