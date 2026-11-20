package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ASNInfo 是逐跳 IP 的归属信息(AS 号 + 中文机构 + 中文国家)。
type ASNInfo struct {
	IP        string `json:"ip"`
	AS        string `json:"as"`         // "AS9929"
	Org       string `json:"org"`        // 原始 AS 描述(英文)
	AsCN      string `json:"as_cn"`      // 中文机构名(已知映射)
	ISP       string `json:"isp"`
	Country   string `json:"country"`    // 英文国名
	CountryCN string `json:"country_cn"` // 中文国名
	Display   string `json:"display"`    // 前端直接显示: "AS9929 中国联通 · 中国"
	Private   bool   `json:"private"`
	Error     string `json:"error,omitempty"`
}

type asnCacheEntry struct {
	info ASNInfo
	at   time.Time
}

var (
	asnMu    sync.Mutex
	asnCache = map[string]asnCacheEntry{}

	// 共享 client: 强制 IPv4 + 复用连接(每次新建 Transport 会在 ip-api 侧踩到 EOF)
	asnHC = &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(c, "tcp4", addr)
			},
			TLSHandshakeTimeout:   5 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConnsPerHost:   4,
			ResponseHeaderTimeout: 6 * time.Second,
		},
	}
)

// 常见 AS 的中文名(不追求全量, 覆盖本网会出现的中港美日韩运营商与云)。
var asCN = map[string]string{
	"4134": "中国电信", "4809": "中国电信 CN2", "4812": "中国电信 上海", "4811": "中国电信 广东",
	"4816": "中国电信 北京", "23764": "中国电信国际", "23910": "中国电信",
	"4837": "中国联通", "9929": "中国联通 9929", "10099": "中国联通国际", "4808": "中国联通 北京",
	"17621": "中国联通 上海", "17816": "中国联通 广东",
	"9808": "中国移动", "56048": "中国移动", "56040": "中国移动 福建", "24400": "上海移动",
	"58453": "中国移动国际 CMI", "58807": "中国移动国际",
	"4538": "中国教育网 CERNET",
	"13335": "Cloudflare", "15169": "Google", "16509": "Amazon AWS", "14618": "Amazon AWS",
	"8075": "Microsoft", "32934": "Meta", "13414": "X/Twitter", "714": "Apple", "22822": "Limelight",
	"2914": "NTT", "17676": "SoftBank", "2516": "KDDI", "4713": "NTT OCN", "3258": "xTom 日本",
	"3462": "中华电信 HiNet", "4780": "台湾 SEEDNet", "9674": "台湾 中嘉",
	"4766": "韩国电信 KT", "3786": "LG U+", "9318": "SK Broadband",
	"3491": "PCCW 香港电讯", "4760": "和记电讯 香港", "9269": "香港宽频 HKBN", "4515": "香港 PCCW",
	"7473": "新加坡电信 Singtel", "4657": "StarHub 新加坡", "152918": "wawo 香港",
	"1299": "Arelion", "3356": "Lumen", "174": "Cogent", "6939": "Hurricane Electric",
	"6461": "Zayo", "2914 ": "NTT", "9002": "RETN", "9009": "M247", "205016": "wawo?",
}

var countryCN = map[string]string{
	"CN": "中国", "HK": "中国香港", "TW": "中国台湾", "MO": "中国澳门",
	"JP": "日本", "KR": "韩国", "SG": "新加坡", "MY": "马来西亚", "TH": "泰国", "VN": "越南",
	"PH": "菲律宾", "ID": "印度尼西亚", "IN": "印度", "AE": "阿联酋", "SA": "沙特", "IL": "以色列",
	"TR": "土耳其", "KZ": "哈萨克斯坦",
	"US": "美国", "CA": "加拿大", "MX": "墨西哥", "BR": "巴西", "AR": "阿根廷", "CL": "智利",
	"GB": "英国", "DE": "德国", "FR": "法国", "NL": "荷兰", "BE": "比利时", "LU": "卢森堡",
	"IE": "爱尔兰", "CH": "瑞士", "AT": "奥地利", "IT": "意大利", "ES": "葡萄牙/西班牙", "PT": "葡萄牙",
	"SE": "瑞典", "NO": "挪威", "DK": "丹麦", "FI": "芬兰", "IS": "冰岛", "PL": "波兰",
	"CZ": "捷克", "SK": "斯洛伐克", "HU": "匈牙利", "RO": "罗马尼亚", "BG": "保加利亚",
	"GR": "希腊", "UA": "乌克兰", "RU": "俄罗斯", "LT": "立陶宛", "LV": "拉脱维亚", "EE": "爱沙尼亚",
	"AU": "澳大利亚", "NZ": "新西兰", "ZA": "南非", "EG": "埃及",
}

// 100.64.0.0/10 是运营商 CGNAT 段, 归属库查不到, 单独标出来
var cgnatNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

func isPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	return p.IsPrivate() || p.IsLoopback() || p.IsLinkLocalUnicast() || cgnatNet.Contains(p)
}

func asDisplay(asn, org, countryCode string) string {
	first := ""
	if f := strings.Fields(asn); len(f) > 0 {
		first = f[0]
	}
	num := strings.TrimPrefix(strings.ToUpper(first), "AS")
	parts := []string{}
	if num != "" && num != "AS" {
		name := asCN[num]
		if name == "" {
			// 没有中文映射时退回 ISP/AS 描述里 AS 号后面的部分, 截断避免太长
			rest := strings.TrimSpace(strings.TrimPrefix(org, "AS"+num))
			if rest == "" {
				rest = org
			}
			if len(rest) > 34 {
				rest = rest[:34]
			}
			name = rest
		}
		if name != "" {
			parts = append(parts, "AS"+num+" "+name)
		} else {
			parts = append(parts, "AS"+num)
		}
	}
	if c := countryCN[countryCode]; c != "" {
		parts = append(parts, c)
	} else if countryCode != "" {
		parts = append(parts, countryCode)
	}
	if len(parts) == 0 {
		return "未知"
	}
	return strings.Join(parts, " · ")
}

// LookupASN 批量查归属(ip-api.com/batch, 100 个/次), 带 6h 内存缓存。
func LookupASN(ctx context.Context, ips []string) []ASNInfo {
	out := make([]ASNInfo, 0, len(ips))
	need := []string{}
	asnMu.Lock()
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if isPrivateIP(ip) {
			label := "内网"
			if cgnatNet.Contains(net.ParseIP(ip)) {
				label = "内网/CGNAT"
			}
			out = append(out, ASNInfo{IP: ip, Private: true, CountryCN: "局域网", Display: label})
			continue
		}
		if e, ok := asnCache[ip]; ok && time.Since(e.at) < cacheTTL(e.info) {
			out = append(out, e.info)
			continue
		}
		need = append(need, ip)
	}
	asnMu.Unlock()
	if len(need) == 0 {
		return out
	}
	fetched := fetchASNBatch(ctx, need)
	// 没拿到 AS 的(含 ip-api 报错的)用 ipwho.is 补一轮, 并发上限 4
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i := range fetched {
		if fetched[i].AS != "" || isPrivateIP(fetched[i].IP) {
			continue
		}
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if info, ok := fetchWhois(ctx, fetched[idx].IP); ok {
				info.Error = ""
				fetched[idx] = info
			}
		}(i)
	}
	wg.Wait()
	asnMu.Lock()
	for _, info := range fetched {
		asnCache[info.IP] = asnCacheEntry{info: info, at: time.Now()}
	}
	asnMu.Unlock()
	return append(out, fetched...)
}

func cacheTTL(i ASNInfo) time.Duration {
	if i.AS == "" {
		return 10 * time.Minute
	}
	return 6 * time.Hour
}

func fetchASNBatch(ctx context.Context, ips []string) []ASNInfo {
	body, _ := json.Marshal(ips)
	url := "http://ip-api.com/batch?fields=query,as,asname,isp,country,countryCode,status,message&lang=en"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return failed(ips, err)
	}
	req.Header.Set("content-type", "application/json")
	resp, err := asnHC.Do(req)
	if err != nil {
		// ip-api 偶尔在复用连接上直接 EOF: 稍等重试一次
		time.Sleep(300 * time.Millisecond)
		if req2, e2 := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body)); e2 == nil {
			req2.Header.Set("content-type", "application/json")
			resp, err = asnHC.Do(req2)
		}
	}
	if err != nil {
		return failed(ips, err)
	}
	defer resp.Body.Close()
	var rows []struct {
		Query       string `json:"query"`
		AS          string `json:"as"`
		AsName      string `json:"asname"`
		ISP         string `json:"isp"`
		Country     string `json:"country"`
		CountryCode string `json:"countryCode"`
		Status      string `json:"status"`
		Message     string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return failed(ips, err)
	}
	out := make([]ASNInfo, 0, len(rows))
	for _, r := range rows {
		info := ASNInfo{IP: r.Query, AS: r.AS, Org: r.AsName, ISP: r.ISP, Country: r.Country, CountryCN: countryCN[r.CountryCode]}
		if info.AS == "" {
			info.AS = r.ISP
		}
		info.Display = asDisplay(r.AS, r.AS, r.CountryCode)
		if r.Status == "fail" || (r.AS == "" && r.CountryCode == "") {
			info.Error = r.Message
			info.Display = "归属库未收录"
		}
		out = append(out, info)
	}
	return out
}

// fetchWhois 用 ipwho.is 兜底(https, 免费无 key), 补 ip-api 查不到的跳。
func fetchWhois(ctx context.Context, ip string) (ASNInfo, bool) {
	info := ASNInfo{IP: ip}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://ipwho.is/"+ip, nil)
	if err != nil {
		return info, false
	}
	resp, err := asnHC.Do(req)
	if err != nil {
		return info, false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var j struct {
		Success     bool   `json:"success"`
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		Connection  struct {
			ASN int    `json:"asn"`
			Org string `json:"org"`
			ISP string `json:"isp"`
		} `json:"connection"`
	}
	if json.Unmarshal(b, &j) != nil || !j.Success {
		return info, false
	}
	info.Country, info.CountryCN = j.Country, countryCN[j.CountryCode]
	info.ISP = j.Connection.ISP
	if j.Connection.ASN > 0 {
		info.AS = fmt.Sprintf("AS%d %s", j.Connection.ASN, j.Connection.Org)
		info.Org = j.Connection.Org
	}
	info.Display = asDisplay(info.AS, info.Org, j.CountryCode)
	if info.AS == "" {
		info.Display = strings.TrimSpace(info.CountryCN + " · 归属库未收录")
	}
	return info, true
}

func failed(ips []string, err error) []ASNInfo {
	out := make([]ASNInfo, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ASNInfo{IP: ip, Error: err.Error(), Display: "查询失败"})
	}
	return out
}

func handleASN(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("ips")
	if raw == "" {
		raw = r.URL.Query().Get("ip")
	}
	var ips []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" && net.ParseIP(s) != nil {
			ips = append(ips, s)
		}
	}
	if len(ips) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "缺少合法 ip/ips"})
		return
	}
	if len(ips) > 100 {
		ips = ips[:100]
	}
	res := LookupASN(r.Context(), ips)
	writeJSON(w, http.StatusOK, map[string]any{"results": res, "count": len(res), "src": "ip-api.com"})
}
