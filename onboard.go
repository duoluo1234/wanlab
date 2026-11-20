package main

// 添加节点(机队入队): 在面板填 VPS 地址/账号/密码, 一键完成新节点装机 ——
//  1) 密码 SSH 登录, 把机队公钥 (fleet_key.pub) 装进 root 的 authorized_keys;
//  2) apt 装 iperf3 / nftables (勾选时加 nginx), 按节点现有 nft 表家族
//     (inet hermes_fw / inet filter, 都没有则建 hermes_fw 骨架) 写 fw-iperf v2
//     (TCP+UDP 5201 双放行) 与 fw-http (TCP 8899) 两个联动脚本;
//  3) 勾选 HTTP 时建 /srv/2gtest/2g.bin (2GiB) + nginx :8899 配置;
//  4) 面板侧用机队 key 复验 SSH / iperf3 放行 / HTTP 文件;
//  5) 写入 /etc/wanlab/config.json 并热加入 cfg.Nodes (面板各页即刻可用);
//  6) ROS 联动: 公网节点逐线钉线 ping 验证 (v4 三线 / v6 双线), 测完恢复出口。
// 密码只在本请求内存里用 (经 SSH_ASKPASS 传给 ssh 子进程的环境变量),
// 不落盘、不进日志、不写配置。

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

type onboardReq struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	HTTP     bool   `json:"http"`
}

type onboardJob struct {
	Running bool     `json:"running"`
	Done    bool     `json:"done"`
	OK      bool     `json:"ok"`
	Log     []string `json:"log"`
}

var (
	obMu  sync.Mutex
	obCur = onboardJob{Log: []string{}}
)

func obLogf(format string, a ...any) {
	obMu.Lock()
	defer obMu.Unlock()
	obCur.Log = append(obCur.Log, time.Now().Format("15:04:05")+" "+fmt.Sprintf(format, a...))
}

func obSnapshot() onboardJob {
	obMu.Lock()
	defer obMu.Unlock()
	out := obCur
	out.Log = append([]string{}, obCur.Log...)
	return out
}

func obFail(format string, a ...any) {
	obLogf("✗ "+format, a...)
	obMu.Lock()
	obCur.Running = false
	obCur.Done = true
	obCur.OK = false
	obMu.Unlock()
}

// ---- 节点侧脚本模板 ----

const fwIperfHermes = `#!/bin/bash
# fw-iperf on|off : allow/deny inbound TCP+UDP 5201 (iperf3 server; UDP for loss/jitter check)
P=5201
case "$1" in
  on)
    nft -a list chain inet hermes_fw input 2>/dev/null | grep -q "tcp dport $P" || nft insert rule inet hermes_fw input tcp dport $P counter accept
    nft -a list chain inet hermes_fw input 2>/dev/null | grep -q "udp dport $P" || nft insert rule inet hermes_fw input udp dport $P counter accept
    echo "inbound $P open (tcp+udp)";;
  off)
    while h=$(nft -a list chain inet hermes_fw input 2>/dev/null | awk "/dport $P/ {print \$NF; exit}"); [ -n "$h" ]; do
      nft delete rule inet hermes_fw input handle "$h" || break
    done
    echo "inbound $P closed";;
  *) echo "usage: fw-iperf on|off"; exit 1;;
esac
`

const fwIperfFilter = `#!/bin/bash
# fw-iperf on|off : TCP+UDP 5201 open/close (iperf3 server; UDP for loss/jitter check)
# supports two nft tables: inet hermes_fw (old fleet template) and inet filter (2026-11 template)
P=5201
pick() {
  for t in hermes_fw filter; do
    if nft list chain inet "$t" input >/dev/null 2>&1; then echo "$t"; return 0; fi
  done
  return 1
}
T=$(pick) || { echo "no nft input chain found"; exit 1; }
case "$1" in
  on)
    nft -a list chain inet "$T" input 2>/dev/null | grep -q "tcp dport $P" || nft insert rule inet "$T" input tcp dport $P counter accept
    nft -a list chain inet "$T" input 2>/dev/null | grep -q "udp dport $P" || nft insert rule inet "$T" input udp dport $P counter accept
    echo "inbound $P open (tcp+udp, $T)"
    ;;
  off)
    while h=$(nft -a list chain inet "$T" input 2>/dev/null | awk "/dport $P/ {print \$NF; exit}"); [ -n "$h" ]; do
      nft delete rule inet "$T" input handle "$h" || break
    done
    echo "inbound $P closed ($T)"
    ;;
  *) echo "usage: fw-iperf on|off"; exit 1;;
esac
`

const fwHTTPHermes = `#!/bin/bash
# fw-http on|off : allow/deny inbound TCP 8899 (nginx speedtest file 2g.bin)
P=8899
case "$1" in
  on)
    nft -a list chain inet hermes_fw input 2>/dev/null | grep -q "tcp dport $P" || nft insert rule inet hermes_fw input tcp dport $P counter accept
    echo "inbound $P open";;
  off)
    while h=$(nft -a list chain inet hermes_fw input 2>/dev/null | awk "/dport $P/ {print \$NF; exit}"); [ -n "$h" ]; do
      nft delete rule inet hermes_fw input handle "$h" || break
    done
    echo "inbound $P closed";;
  *) echo "usage: fw-http on|off"; exit 1;;
esac
`

const fwHTTPFilter = `#!/bin/bash
# fw-http on|off : TCP 8899 open/close (nginx speedtest file 2g.bin)
P=8899
pick() {
  for t in hermes_fw filter; do
    if nft list chain inet "$t" input >/dev/null 2>&1; then echo "$t"; return 0; fi
  done
  return 1
}
T=$(pick) || { echo "no nft input chain found"; exit 1; }
case "$1" in
  on)
    nft -a list chain inet "$T" input 2>/dev/null | grep -q "tcp dport $P" || nft insert rule inet "$T" input tcp dport $P counter accept
    echo "inbound $P open ($T)";;
  off)
    while h=$(nft -a list chain inet "$T" input 2>/dev/null | awk "/dport $P/ {print \$NF; exit}"); [ -n "$h" ]; do
      nft delete rule inet "$T" input handle "$h" || break
    done
    echo "inbound $P closed ($T)";;
  *) echo "usage: fw-http on|off"; exit 1;;
esac
`

const nginxTestConf = `# wanlab download speedtest (panel fleet node); disable: remove this file + reload nginx + fw-http off
server {
    listen 8899 default_server;
    listen [::]:8899 default_server;
    server_name _;
    root /srv/2gtest;
    access_log off;
    sendfile on;
    tcp_nopush on;
    location / { }
}
`

// remoteInstallScript 在节点上以 root 执行的装机脚本。
// __PUBKEY__ / __WITH_HTTP__(0/1) / 四个脚本与 nginx 配置以占位符注入。
func remoteInstallScript(pub string, withHTTP bool) string {
	httpFlag := "0"
	if withHTTP {
		httpFlag = "1"
	}
	s := `set -e
echo "STEP os: $(. /etc/os-release; echo $PRETTY_NAME)"
install -d -m 700 ~/.ssh
touch ~/.ssh/authorized_keys
grep -qxF '__PUBKEY__' ~/.ssh/authorized_keys || echo '__PUBKEY__' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo "STEP key installed"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq iperf3 nftables curl__NGINXPKG__ >/dev/null
echo "STEP packages installed: $(iperf3 -v 2>&1 | head -1)"
if nft list chain inet hermes_fw input >/dev/null 2>&1; then FAM=hermes
elif nft list chain inet filter input >/dev/null 2>&1; then FAM=filter
else
  nft add table inet hermes_fw
  nft 'add chain inet hermes_fw input { type filter hook input priority 0; policy accept; }'
  FAM=hermes
fi
echo "STEP nft family: $FAM"
if [ "$FAM" = filter ]; then
  cat > /usr/local/bin/fw-iperf <<'EOF_IPERF_F'
__FWIPERF_F__
EOF_IPERF_F
  cat > /usr/local/bin/fw-http <<'EOF_HTTP_F'
__FWHTTP_F__
EOF_HTTP_F
else
  cat > /usr/local/bin/fw-iperf <<'EOF_IPERF_H'
__FWIPERF_H__
EOF_IPERF_H
  cat > /usr/local/bin/fw-http <<'EOF_HTTP_H'
__FWHTTP_H__
EOF_HTTP_H
fi
chmod +x /usr/local/bin/fw-iperf /usr/local/bin/fw-http
fw-iperf off >/dev/null 2>&1 || true
fw-http off >/dev/null 2>&1 || true
echo "STEP gate scripts installed"
if [ "__WITH_HTTP__" = "1" ]; then
  mkdir -p /srv/2gtest
  if [ ! -f /srv/2gtest/2g.bin ]; then
    fallocate -l 2147483648 /srv/2gtest/2g.bin 2>/dev/null || dd if=/dev/zero of=/srv/2gtest/2g.bin bs=1M count=2048 status=none
  fi
  cat > /etc/nginx/conf.d/99-http-test.conf <<'EOF_NGINX'
__NGINXCONF__
EOF_NGINX
  nginx -t
  systemctl enable --now nginx >/dev/null 2>&1 || true
  systemctl reload nginx 2>/dev/null || systemctl restart nginx
  echo "STEP http ready: $(ls -l /srv/2gtest/2g.bin | awk '{print $5}') bytes"
fi
echo "ONBOARD-REMOTE-DONE"
`
	nginxPkg := ""
	if withHTTP {
		nginxPkg = " nginx"
	}
	s = strings.ReplaceAll(s, "__PUBKEY__", pub)
	s = strings.ReplaceAll(s, "__NGINXPKG__", nginxPkg)
	s = strings.ReplaceAll(s, "__WITH_HTTP__", httpFlag)
	s = strings.ReplaceAll(s, "__FWIPERF_H__", strings.TrimSpace(fwIperfHermes))
	s = strings.ReplaceAll(s, "__FWIPERF_F__", strings.TrimSpace(fwIperfFilter))
	s = strings.ReplaceAll(s, "__FWHTTP_H__", strings.TrimSpace(fwHTTPHermes))
	s = strings.ReplaceAll(s, "__FWHTTP_F__", strings.TrimSpace(fwHTTPFilter))
	s = strings.ReplaceAll(s, "__NGINXCONF__", strings.TrimSpace(nginxTestConf))
	return s
}

// sshPasswordRun 用密码跑一次远程命令 (SSH_ASKPASS_REQUIRE=force, 密码走环境变量)。
func sshPasswordRun(ctx context.Context, ip string, port int, user, password, script string) (string, error) {
	dir, err := os.MkdirTemp("", "obask")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	helper := dir + "/askpass.sh"
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf '%s' \"$WANLAB_NODE_PW\"\n"), 0700); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	args := []string{"-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=12", "-o", "LogLevel=ERROR",
		"-p", fmt.Sprint(port), user + "@" + ip, script}
	cmd := exec.CommandContext(cctx, "ssh", args...)
	cmd.Env = append(os.Environ(),
		"SSH_ASKPASS="+helper, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=wanlab",
		"WANLAB_NODE_PW="+password)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// obSSH 用机队 key 跑远程命令, 超时比 exec.go 的共享版宽 (首次接触慢节点用)。
func obSSH(ctx context.Context, node Node, remote string, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return runCmd(cctx, "ssh", sshArgs(node, remote)...)
}

var keyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func runOnboard(rq onboardReq) {
	ctx := context.Background()
	node := Node{Key: rq.Key, Label: rq.Label, IP: rq.IP}
	obLogf("开始入队: %s (%s)", rq.Label, rq.IP)

	// 1) 机队公钥
	pub, err := runCmd(ctx, "ssh-keygen", "-y", "-f", cfg.FleetKey)
	if err != nil {
		obFail("读取机队公钥失败: %v", err)
		return
	}
	pub = strings.TrimSpace(pub)
	obLogf("机队公钥已就绪")

	// 2) 密码登录装机
	script := remoteInstallScript(pub, rq.HTTP)
	out, err := sshPasswordRun(ctx, rq.IP, rq.Port, rq.User, rq.Password, script)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(line, "STEP ") {
			obLogf("节点: %s", strings.TrimPrefix(line, "STEP "))
		}
	}
	if err != nil {
		obFail("密码登录/装机失败: %v (输出尾: %s)", err, tailLine(out))
		return
	}
	if !strings.Contains(out, "ONBOARD-REMOTE-DONE") {
		obFail("装机未完成 (输出尾: %s)", tailLine(out))
		return
	}
	obLogf("节点侧装机完成 (key/iperf3/联动脚本%s)", map[bool]string{true: "/nginx+2g.bin", false: ""}[rq.HTTP])

	// 3) 面板侧 key 复验。用加长超时的本地 SSH 辅助 (不复用 exec.go 的短超时版):
	// 新节点首次接触可能很慢 (个别环境 sshd 会话建立要等 20+ 秒), 入队验证要给足耐心。
	if out, err := obSSH(ctx, node, "hostname", 90*time.Second); err == nil {
		obLogf("机队 key 登录验证 OK: %s", strings.TrimSpace(out))
	} else {
		obFail("装机后机队 key 仍登不进: %v", err)
		return
	}
	prep, perr := obSSH(ctx, node, `fw-iperf on >/dev/null 2>&1 || true; pkill -x iperf3 2>/dev/null; sleep 0.3; nohup iperf3 -s -p 5201 >/tmp/iperf3srv.log 2>&1 & sleep 0.6; (ss -lnt 2>/dev/null | grep -q ':5201') && echo IPERF_UP || echo IPERF_DOWN`, 90*time.Second)
	if perr != nil || !strings.Contains(prep, "IPERF_UP") {
		obSSH(ctx, node, `pkill -x iperf3; fw-iperf off >/dev/null 2>&1 || true; echo stopped`, 60*time.Second)
		obFail("iperf3 放行验证失败: %v", perr)
		return
	}
	dialIP := rq.IP
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, derr := dialer.DialContext(ctx, "tcp", net.JoinHostPort(dialIP, "5201"))
	if derr != nil {
		obSSH(ctx, node, `pkill -x iperf3; fw-iperf off >/dev/null 2>&1 || true; echo stopped`, 60*time.Second)
		obFail("5201 连通验证失败: %v", derr)
		return
	}
	conn.Close()
	obSSH(ctx, node, `pkill -x iperf3; fw-iperf off >/dev/null 2>&1 || true; echo stopped`, 60*time.Second)
	obLogf("iperf3 放行+连通验证 OK")
	if rq.HTTP {
		hout, herr := obSSH(ctx, node, `fw-http on 2>/dev/null || true; ls -l /srv/2gtest/2g.bin 2>/dev/null | awk '{print "FILE=" $5}'`, 90*time.Second)
		obSSH(ctx, node, `fw-http off >/dev/null 2>&1 || true; echo closed`, 60*time.Second)
		if herr != nil || !strings.Contains(hout, "FILE=2147483648") {
			obFail("HTTP 测速文件验证失败: %v (%s)", herr, strings.TrimSpace(hout))
			return
		}
		obLogf("HTTP 2g.bin 验证 OK")
	}

	// 4) 落盘 + 热加入
	if err := persistNode(node); err != nil {
		obFail("写入 config.json 失败: %v", err)
		return
	}
	cfg.Nodes = append(cfg.Nodes, node)
	obLogf("已写入 config.json 并加入机队 (当前共 %d 台)", len(cfg.Nodes))

	// 5) ROS 联动: 逐线 ping 验证 (仅公网地址)
	if ip := net.ParseIP(rq.IP); ip != nil && !ip.IsPrivate() && !ip.IsLoopback() {
		validateNodeLines(ctx, node)
	} else {
		obLogf("内网地址, 跳过 ROS 逐线验证")
	}

	obMu.Lock()
	obCur.Running = false
	obCur.Done = true
	obCur.OK = true
	obMu.Unlock()
	obLogf("✓ 入队完成: %s 已可在面板各页使用 (机队体检/聚合源站/iperf)", rq.Label)
}

func tailLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		return ""
	}
	return lines[len(lines)-1]
}

// validateNodeLines 把面板出口逐条钉到各线路 ping 新节点, 测完恢复原出口。
func validateNodeLines(ctx context.Context, node Node) {
	if !tryExitGate("新节点逐线验证") {
		holder, _ := exitGateBusy()
		obLogf("线路正被「%s」占用, 跳过 ROS 逐线验证 (不影响入队)", holder)
		return
	}
	defer releaseExitGate()
	fam := 4
	lines := []string{"1", "2", "3"}
	if strings.Contains(node.IP, ":") {
		fam = 6
		lines = []string{"v6", "v6u"}
	}
	prev := getExit()
	obLogf("ROS 联动验证: 逐线 ping (原出口 %s, 测完恢复)", exitLabel(prev))
	defer func() {
		if err := setExit(prev); err != nil {
			obLogf("恢复出口失败: %v", err)
		}
	}()
	for _, ln := range lines {
		if err := setExit(ln); err != nil {
			obLogf("  %s: 钉线失败 %v", exitLabel(ln), err)
			continue
		}
		time.Sleep(1200 * time.Millisecond)
		if sm, _, err := Ping(ctx, node.IP, 5, 200, fam); err == nil {
			obLogf("  %s: 平均 %.1fms 丢包 %.0f%%", exitLabel(ln), sm.Avg, sm.LossPct)
		} else {
			obLogf("  %s: ping 失败 %v", exitLabel(ln), err)
		}
	}
	obLogf("ROS 联动验证完成, 出口已恢复 %s", exitLabel(prev))
}

// persistNode 把新节点追加进 /etc/wanlab/config.json (先备份, 原子替换)。
func persistNode(n Node) error {
	const path = "/etc/wanlab/config.json"
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		return err
	}
	nodes, _ := root["nodes"].([]any)
	nodes = append(nodes, map[string]any{"key": n.Key, "label": n.Label, "ip": n.IP})
	root["nodes"] = nodes
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	bak := path + ".bak-" + time.Now().Format("20060102-150405") + "-pre-add-" + n.Key
	if err := os.WriteFile(bak, b, 0600); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func handleFleetAddStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST only"})
		return
	}
	var rq onboardReq
	if err := json.NewDecoder(r.Body).Decode(&rq); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式不对"})
		return
	}
	rq.Key = strings.TrimSpace(rq.Key)
	rq.Label = strings.TrimSpace(rq.Label)
	rq.IP = strings.TrimSpace(rq.IP)
	if rq.Port == 0 {
		rq.Port = 22
	}
	if rq.User == "" {
		rq.User = "root"
	}
	switch {
	case !keyRe.MatchString(rq.Key):
		writeJSON(w, 400, map[string]string{"error": "标识只能用小写字母/数字/-, 如 hk8"})
		return
	case rq.Label == "":
		writeJSON(w, 400, map[string]string{"error": "名称必填"})
		return
	case net.ParseIP(rq.IP) == nil:
		writeJSON(w, 400, map[string]string{"error": "IP 地址格式不对"})
		return
	case rq.Port != 22:
		writeJSON(w, 400, map[string]string{"error": "机队统一走 SSH 22 端口, 请用 22 端口的 VPS"})
		return
	case rq.User != "root":
		writeJSON(w, 400, map[string]string{"error": "机队节点统一用 root 账号"})
		return
	case rq.Password == "":
		writeJSON(w, 400, map[string]string{"error": "密码必填 (只用于首次装 key, 不保存)"})
		return
	}
	for _, n := range cfg.Nodes {
		if n.Key == rq.Key {
			writeJSON(w, 400, map[string]string{"error": "标识已存在: " + rq.Key})
			return
		}
		if n.IP == rq.IP {
			writeJSON(w, 400, map[string]string{"error": "该 IP 已在机队: " + n.Label})
			return
		}
	}
	if fleetSnapshot().Running {
		writeJSON(w, 409, map[string]string{"error": "机队体检进行中, 等它结束再添加"})
		return
	}
	obMu.Lock()
	if obCur.Running {
		obMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "已有入队任务在跑"})
		return
	}
	obCur = onboardJob{Running: true, Log: []string{}}
	obMu.Unlock()
	go runOnboard(rq)
	writeJSON(w, 200, map[string]any{"started": true})
}

func handleFleetAdd(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, obSnapshot())
}
