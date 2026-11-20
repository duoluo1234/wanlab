package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Mac 直连开关：把某台设备(下称 Mac)的 DHCP 静态租约在
//   mac_proxy_addr  (走旁路由代理)
//   mac_direct_addr (直连专用 IP，mangle 里需有一条对应的豁免规则，不做代理判定)
// 之间来回切换，用于注册某些云服务等需要干净本地出口的场合。
// 三个配置项(mac_lease_mac / mac_proxy_addr / mac_direct_addr)配齐才启用，
// 缺任一项 handleMacDirect 直接返回未启用，前端据此隐藏入口。

func macDirectEnabled() bool {
	return cfg.MacLeaseMAC != "" && cfg.MacProxyAddr != "" && cfg.MacDirectAddr != ""
}

type MacDirectStatus struct {
	MAC      string `json:"mac"`
	Hostname string `json:"hostname"`
	DNSOpt   string `json:"dns_option"` // 租约上挂的 DHCP option 名(dns-direct=公共DNS)
	Address  string `json:"address"` // 租约上写的地址(下次续租生效)
	Active   string `json:"active"`  // 当前实际在用的地址
	Mode     string `json:"mode"`    // direct / proxy
	LeaseID  string `json:"lease_id"`
}

// leaseByMAC 在 DHCP 静态租约里按 MAC 找 Mac 那一条。
func (r *Ros) leaseByMAC(mac string) (map[string]any, error) {
	b, err := r.Get("/rest/ip/dhcp-server/lease")
	if err != nil {
		return nil, err
	}
	var all []map[string]any
	if err := json.Unmarshal(b, &all); err != nil {
		return nil, err
	}
	for _, l := range all {
		if m, _ := l["mac-address"].(string); strings.EqualFold(m, mac) {
			return l, nil
		}
	}
	return nil, nil
}

func macDirectStatus() (*MacDirectStatus, error) {
	l, err := ros.leaseByMAC(cfg.MacLeaseMAC)
	if err != nil {
		return nil, err
	}
	if l == nil {
		return &MacDirectStatus{MAC: cfg.MacLeaseMAC, Mode: "unknown"}, nil
	}
	st := &MacDirectStatus{MAC: cfg.MacLeaseMAC}
	st.LeaseID, _ = l[".id"].(string)
	st.Address, _ = l["address"].(string)
	st.Active, _ = l["active-address"].(string)
	st.Hostname, _ = l["host-name"].(string)
	st.DNSOpt, _ = l["dhcp-option"].(string)
	if st.Active == "" {
		st.Active = st.Address
	}
	if st.Address == cfg.MacDirectAddr || st.Active == cfg.MacDirectAddr {
		st.Mode = "direct"
	} else {
		st.Mode = "proxy"
	}
	return st, nil
}

// GET  /api/macdirect          查当前状态
// POST /api/macdirect {"on":true}  切到直连(mac_direct_addr)；{"on":false} 切回代理(mac_proxy_addr)
func handleMacDirect(w http.ResponseWriter, r *http.Request) {
	if !macDirectEnabled() {
		writeJSON(w, 501, map[string]any{"ok": false, "disabled": true,
			"error": "Mac 直连未启用: 需在配置里填 mac_lease_mac / mac_proxy_addr / mac_direct_addr"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		st, err := macDirectStatus()
		if err != nil {
			writeJSON(w, 502, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "status": st})
	case http.MethodPost:
		var body struct {
			On bool `json:"on"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		l, err := ros.leaseByMAC(cfg.MacLeaseMAC)
		if err != nil {
			writeJSON(w, 502, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if l == nil {
			writeJSON(w, 404, map[string]any{"ok": false, "error": "找不到 Mac 的 DHCP 租约"})
			return
		}
		id, _ := l[".id"].(string)
		target := cfg.MacProxyAddr
		if body.On {
			target = cfg.MacDirectAddr
		}
		// 直连时同时把租约上的 DNS 选项切成公共解析器(dns-direct), 切回代理时清空恢复 DHCP 默认
		dnsOpt := ""
		if body.On {
			dnsOpt = "dns-direct"
		}
		if _, _, err := ros.do("PATCH", "/rest/ip/dhcp-server/lease/"+id, map[string]any{"address": target, "dhcp-option": dnsOpt}); err != nil {
			writeJSON(w, 502, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		st, err := macDirectStatus()
		if err != nil {
			writeJSON(w, 200, map[string]any{"ok": true})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "status": st})
	default:
		writeJSON(w, 405, map[string]any{"ok": false, "error": "只支持 GET / POST"})
	}
}
