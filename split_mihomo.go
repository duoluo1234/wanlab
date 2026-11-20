package main

// 读取 OpenClash / mihomo 的真实分流结果。
//
// ★ 为什么必须读这里：wanlab 原来的站点探测只用「整机出口 IP」判定走向，
//   但 OpenClash 是【按域名分策略组】的——不同域名会走完全不同的节点/策略组。
//   整机出口只能反映"某一次请求"，完全看不出这种分流。
//   只有问 mihomo 的 /connections 才能拿到每个域名的真实链路。
//
// mihomo API: GET http://<prx>:9090/connections
//   {"connections":[{"metadata":{"host":"www.youtube.com","destinationIP":"..."},
//                    "chains":["node1","📹 YouTube"]}]}
//   chains[0] = 最末跳节点（实际出口），chains[1..] = 命中的策略组层级。

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// mihomoConn 精简后的连接信息。
type mihomoConn struct {
	Host   string
	DestIP string
	Chains []string
}

// mihomoPath 命中某站点的链路结果。
type mihomoPath struct {
	Node string `json:"node"`  // 实际出口节点（chains[0]）
	Group string `json:"group"` // 命中的策略组（chains[1] 或最外层的非节点项）
	All  []string `json:"all"`  // 完整链路
}

// fetchMihomoConns 拉当前所有活跃连接（只读，轻量）。
// 未配置 mihomo_api 时直接返回 nil(跳过该功能); mihomo_secret 为空则不带鉴权头。
func fetchMihomoConns(ctx context.Context) []mihomoConn {
	base := cfg.MihomoAPI
	if base == "" {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	args := []string{"-s", "-m", "5", "--max-time", "5"}
	if cfg.MihomoSecret != "" {
		args = append(args, "-H", "Authorization: Bearer "+cfg.MihomoSecret)
	}
	args = append(args, base+"/connections")
	out, err := runCmd(cctx, "curl", args...)
	if err != nil || out == "" {
		return nil
	}
	var d struct {
		Connections []struct {
			Metadata struct {
				Host          string `json:"host"`
				DestinationIP string `json:"destinationIP"`
			} `json:"metadata"`
			Chains []string `json:"chains"`
		} `json:"connections"`
	}
	if json.Unmarshal([]byte(out), &d) != nil {
		return nil
	}
	res := make([]mihomoConn, 0, len(d.Connections))
	for _, c := range d.Connections {
		res = append(res, mihomoConn{
			Host:   strings.ToLower(c.Metadata.Host),
			DestIP: c.Metadata.DestinationIP,
			Chains: c.Chains,
		})
	}
	return res
}

// matchMihomoPath 按域名匹配该站点的真实链路。
// 匹配规则：host 相等 > host 以站点域名为后缀 > 目标 IP 相同。
func matchMihomoPath(conns []mihomoConn, host, ip string) *mihomoPath {
	host = strings.ToLower(host)
	// 站点主域（去 www.）用于宽松匹配
	base := strings.TrimPrefix(host, "www.")

	var best *mihomoConn
	for i := range conns {
		c := &conns[i]
		h := c.Host
		if h == "" {
			continue
		}
		if h == host || strings.HasSuffix(h, "."+base) || h == base {
			if best == nil || len(c.Chains) > len(best.Chains) {
				best = c
			}
		}
	}
	// 退一步：按目标 IP 匹配（有些连接没有 host）
	if best == nil && ip != "" {
		for i := range conns {
			if conns[i].DestIP == ip && len(conns[i].Chains) > 0 {
				best = &conns[i]
				break
			}
		}
	}
	if best == nil || len(best.Chains) == 0 {
		return nil
	}
	p := &mihomoPath{All: best.Chains}
	p.Node = best.Chains[0] // chains[0] = 最末跳（真实出口节点）
	// 策略组：取 chains 里第一个非节点项（通常 chains[1]）
	for _, c := range best.Chains[1:] {
		p.Group = c
		break
	}
	if p.Group == "" {
		p.Group = "DIRECT"
	}
	return p
}

// DIRECT 判定：链路里只有 DIRECT，说明没走代理。
func (p *mihomoPath) IsDirect() bool {
	if p == nil {
		return false
	}
	return strings.EqualFold(p.Node, "DIRECT") || strings.EqualFold(p.Node, "REJECT")
}

// OverrideSites 用 mihomo 真实链路覆盖站点走向结论。
// 已在探测时抓到链路的（mihomoHit）优先保留，不要被二次查询失败覆盖。
func OverrideSites(sites []SiteRow, conns []mihomoConn) {
	for i := range sites {
		if sites[i].mihomoHit {
			continue // 探测阶段已拿到真实链路，最可信
		}
		p := matchMihomoPath(conns, sites[i].Host, sites[i].IP)
		if p == nil {
			continue // 保持探测阶段的判定，不要清空
		}
		sites[i].MihomoNode = p.Node
		sites[i].MihomoGroup = p.Group
		sites[i].Chains = p.All
		if p.IsDirect() {
			sites[i].Line = "直连（" + p.Group + "）"
			sites[i].Kind = "direct"
		} else {
			sites[i].Line = "代理 → " + p.Node
			sites[i].Kind = "proxy"
		}
	}
}

// siteSummaryWithMihomo 汇总里额外统计"走代理的节点分布"。
func siteSummaryWithMihomo(rows []SiteRow) string {
	if len(rows) == 0 {
		return ""
	}
	okN, proxyN, directN, unknownN := 0, 0, 0, 0
	nodes := map[string]int{}
	for _, r := range rows {
		if r.OK {
			okN++
		}
		switch r.Kind {
		case "proxy":
			proxyN++
			if r.MihomoNode != "" {
				nodes[r.MihomoNode]++
			}
		case "direct":
			directN++
		default:
			unknownN++
		}
	}
	s := "可达 " + itoa(okN) + "/" + itoa(len(rows)) + " · 代理 " + itoa(proxyN) + " · 直连 " + itoa(directN)
	if unknownN > 0 {
		s += " · 未判 " + itoa(unknownN)
	}
	// 节点分布（最多列 4 个）
	if len(nodes) > 0 {
		type kv struct {
			k string
			v int
		}
		var arr []kv
		for k, v := range nodes {
			arr = append(arr, kv{k, v})
		}
		// 简单按次数降序
		for i := 0; i < len(arr); i++ {
			for j := i + 1; j < len(arr); j++ {
				if arr[j].v > arr[i].v {
					arr[i], arr[j] = arr[j], arr[i]
				}
			}
		}
		var parts []string
		for i, x := range arr {
			if i >= 4 {
				break
			}
			parts = append(parts, x.k+"×"+itoa(x.v))
		}
		s += " · 节点: " + strings.Join(parts, " ")
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
