package main

// 端口转发页签: ROS dstnat 规则的查看 / 新增 / 启停 / 删除(ROS 联动)。
// 两类规则: 公网转发(in-interface-list=WAN)与本机重定向(dst-address=路由器地址 ros_host)。
// 新增注释由面板按 ROS 现行规范拼装:「【NAT】NN 协议/外端口 说明 → 目标(面板添加 日期)」,
// 序号取现表最大值 +1;同(类,协议,外端口)的启用规则已存在时拒绝新增,防被先匹配的规则遮蔽。
// 每次写后回读校验。

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type NatRule struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"` // wan | lan | other
	Protocol string `json:"protocol"`
	DstPort  string `json:"dst_port"`
	ToAddr   string `json:"to_addresses"`
	ToPorts  string `json:"to_ports"`
	Disabled bool   `json:"disabled"`
	Comment  string `json:"comment"`
}

type rosNatRaw struct {
	ID          string `json:".id"`
	Chain       string `json:"chain"`
	Protocol    string `json:"protocol"`
	DstPort     string `json:"dst-port"`
	DstAddress  string `json:"dst-address"`
	InIfaceList string `json:"in-interface-list"`
	InIface     string `json:"in-interface"`
	Action      string `json:"action"`
	ToAddresses string `json:"to-addresses"`
	ToPorts     string `json:"to-ports"`
	Disabled    string `json:"disabled"`
	Comment     string `json:"comment"`
}

var natNumRe = regexp.MustCompile(`【NAT】(\d+)`)

func fetchAllNat() ([]rosNatRaw, error) {
	b, err := ros.Get("/rest/ip/firewall/nat")
	if err != nil {
		return nil, err
	}
	var raw []rosNatRaw
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func natKind(r rosNatRaw) string {
	if r.InIfaceList == "WAN" || r.InIface != "" {
		return "wan"
	}
	if r.DstAddress != "" {
		return "lan"
	}
	return "other"
}

func natList() ([]NatRule, int, error) {
	raw, err := fetchAllNat()
	if err != nil {
		return nil, 0, err
	}
	out := []NatRule{}
	maxNum := 0
	for _, r := range raw {
		if m := natNumRe.FindStringSubmatch(r.Comment); m != nil {
			if n, e := strconv.Atoi(m[1]); e == nil && n > maxNum {
				maxNum = n
			}
		}
		if r.Chain != "dstnat" || r.Action != "dst-nat" {
			continue
		}
		out = append(out, NatRule{ID: r.ID, Kind: natKind(r), Protocol: r.Protocol,
			DstPort: r.DstPort, ToAddr: r.ToAddresses, ToPorts: r.ToPorts,
			Disabled: r.Disabled == "true", Comment: r.Comment})
	}
	return out, maxNum + 1, nil
}

func handleNatList(w http.ResponseWriter, r *http.Request) {
	rules, next, err := natList()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "读 ROS NAT 失败: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"rules": rules, "next_num": next})
}

type natAddReq struct {
	Kind     string `json:"kind"`
	Protocol string `json:"protocol"`
	ExtPort  int    `json:"ext_port"`
	ToIP     string `json:"to_ip"`
	ToPort   int    `json:"to_port"`
	Note     string `json:"note"`
}

func handleNatAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var q natAddReq
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	q.Protocol = strings.ToLower(strings.TrimSpace(q.Protocol))
	q.Note = strings.TrimSpace(q.Note)
	if q.Kind != "wan" && q.Kind != "lan" {
		writeJSON(w, 400, map[string]string{"error": "类型只能是 wan(公网转发)或 lan(本机重定向)"})
		return
	}
	if q.Protocol != "tcp" && q.Protocol != "udp" {
		writeJSON(w, 400, map[string]string{"error": "协议只能是 tcp 或 udp"})
		return
	}
	if q.ExtPort < 1 || q.ExtPort > 65535 || q.ToPort < 1 || q.ToPort > 65535 {
		writeJSON(w, 400, map[string]string{"error": "端口须在 1-65535"})
		return
	}
	ip := net.ParseIP(strings.TrimSpace(q.ToIP))
	_, lan, lanErr := net.ParseCIDR(lanCIDR())
	if ip == nil || ip.To4() == nil || lanErr != nil || !lan.Contains(ip) {
		writeJSON(w, 400, map[string]string{"error": "目标 IP 须为局域网段 " + lanCIDR() + " 内的 IPv4"})
		return
	}
	if q.Note == "" {
		writeJSON(w, 400, map[string]string{"error": "说明必填(会进 ROS 规则注释)"})
		return
	}

	rules, next, err := natList()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "读 ROS NAT 失败: " + err.Error()})
		return
	}
	for _, ex := range rules {
		if ex.Kind == q.Kind && ex.Protocol == q.Protocol && ex.DstPort == strconv.Itoa(q.ExtPort) && !ex.Disabled {
			writeJSON(w, 409, map[string]string{"error": fmt.Sprintf("已有同类规则占用 %s/%d: %s", q.Protocol, q.ExtPort, ex.Comment)})
			return
		}
	}

	today := time.Now().Format("2006-01-02")
	var comment string
	body := map[string]any{
		"chain": "dstnat", "action": "dst-nat", "protocol": q.Protocol,
		"dst-port": strconv.Itoa(q.ExtPort), "to-addresses": ip.String(),
		"to-ports": strconv.Itoa(q.ToPort),
	}
	if q.Kind == "wan" {
		body["in-interface-list"] = "WAN"
		comment = fmt.Sprintf("【NAT】%02d %s/%d %s → %s:%d（面板添加 %s）",
			next, strings.ToUpper(q.Protocol), q.ExtPort, q.Note, ip.String(), q.ToPort, today)
	} else {
		body["dst-address"] = cfg.ROSHost
		comment = fmt.Sprintf("【NAT】%02d %s → %s:%d（转 %s:%d，面板添加 %s）",
			next, q.Note, cfg.ROSHost, q.ExtPort, ip.String(), q.ToPort, today)
	}
	body["comment"] = comment

	if _, code, err := ros.do("PUT", "/rest/ip/firewall/nat", body); err != nil || code >= 300 {
		writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("ROS 新增失败(code %d): %v", code, err)})
		return
	}
	// 回读校验
	after, _, err := natList()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "已提交但回读失败: " + err.Error()})
		return
	}
	for _, nr := range after {
		if nr.Comment == comment {
			writeJSON(w, 200, map[string]any{"added": nr, "rules": after})
			return
		}
	}
	writeJSON(w, 502, map[string]string{"error": "已提交但回读未找到新规则, 请刷新列表确认"})
}

type natIDReq struct {
	ID       string `json:"id"`
	Disabled bool   `json:"disabled"`
}

func handleNatToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var q natIDReq
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil || q.ID == "" {
		writeJSON(w, 400, map[string]string{"error": "bad json / missing id"})
		return
	}
	dis := "false"
	if q.Disabled {
		dis = "true"
	}
	if _, code, err := ros.do("POST", "/rest/ip/firewall/nat/set", map[string]any{".id": q.ID, "disabled": dis}); err != nil || code >= 300 {
		writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("ROS 设置失败(code %d): %v", code, err)})
		return
	}
	rules, _, err := natList()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "已提交但回读失败: " + err.Error()})
		return
	}
	for _, nr := range rules {
		if nr.ID == q.ID && nr.Disabled == q.Disabled {
			writeJSON(w, 200, map[string]any{"rules": rules})
			return
		}
	}
	writeJSON(w, 502, map[string]string{"error": "已提交但回读状态不一致, 请刷新确认"})
}

func handleNatRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var q natIDReq
	if err := json.NewDecoder(r.Body).Decode(&q); err != nil || q.ID == "" {
		writeJSON(w, 400, map[string]string{"error": "bad json / missing id"})
		return
	}
	if _, code, err := ros.do("POST", "/rest/ip/firewall/nat/remove", map[string]any{".id": q.ID}); err != nil || code >= 300 {
		writeJSON(w, 502, map[string]string{"error": fmt.Sprintf("ROS 删除失败(code %d): %v", code, err)})
		return
	}
	rules, _, err := natList()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "已提交但回读失败: " + err.Error()})
		return
	}
	for _, nr := range rules {
		if nr.ID == q.ID {
			writeJSON(w, 502, map[string]string{"error": "已提交但规则仍在, 请刷新确认"})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"rules": rules})
}
