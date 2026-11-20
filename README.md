# wanlab · 家庭多线测试台

一个网页面板，把「Ping / 路由追踪 / iperf3 / 真实下载测速 / DNS 真 IP / 出口信息」集中到一页，
**每条测试都可以选走哪条 WAN，并彻底绕过旁路由与 fake-ip。**
线路名、PPPoE 接口名、节点名单全部走配置（见 `config.example.json`），默认三条线（WAN1/WAN2/WAN3）。

- 代码：Go + 单文件前端（`static/index.html`，embed 进二进制），零第三方依赖
- 部署：一台独立 LXC/VM（网关直指 RouterOS，不经过旁路由），systemd `wanlab.service`，开机自启
- 联动对象：RouterOS 7 的 REST API（钉线 mangle、PPPoE 状态、NAT、DHCP 租约等）

## 为什么这么做

家里若有旁路由做分流（境外目标 → 旁路由 fake-ip），直接在旁路由后面的机器上测速，
测到的是代理出口而不是线路本身；本地 DNS 把域名解析成 `198.18.x` fake-ip 后，
去 ping「真 IP」也无从谈起。

所以面板放在一台**独立的 LXC/VM** 里，网关直接指向 RouterOS：

```
面板主机               gateway = ROS（默认 192.168.0.1）   ← 不经过旁路由
/etc/resolv.conf       = 公共 DNS                          ← 不用本地 fake-ip 解析
ROS mangle(prerouting) = src <面板主机IP> + dst !<lan_cidr>
                         action=mark-routing, new-routing-mark=to-wanN, passthrough=no
```

`mark-routing` 规则追加在 prerouting 链**尾部**，前面的 `to-proxy` 标记会被它覆盖，
所以面板自身的全部流量（ping/traceroute/iperf3/curl/ssh）都从**选中的那条物理线**进出；
换成 `不钉线` 则规则 disabled，恢复走旁路由，正好用来做「代理 vs 直连」对照。

## 安装

一键安装（编译 + 装二进制 + 写示例配置 + 注册 systemd 并启动）：

```bash
sudo ./install.sh
```

手动步骤等价于：

```bash
# 1) 编译（纯标准库，linux/amd64 单二进制）
make build            # 或: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o wanlab-linux .

# 2) 安装到部署主机
install -m 755 wanlab-linux /opt/wanlab/wanlab
cp systemd/wanlab.service /etc/systemd/system/
systemctl enable --now wanlab

# 3) 配置
mkdir -p /etc/wanlab
cp config.example.json /etc/wanlab/config.json   # 按自己的环境改，权限 600
systemctl restart wanlab
```

运行依赖（Debian 系）：`iputils-ping traceroute dnsutils curl iperf3 openssh-client snmp`。
面板启动时从 `/etc/wanlab/config.json` 读配置；文件不存在时用内置默认值
（ROS 默认 `https://192.168.0.1`、通用三线、两个文档段示例节点）。

## 配置要点

| 字段 | 说明 |
|---|---|
| `ros_base` / `ros_host` / `ros_user` / `ros_pass` | RouterOS REST 地址、SNMP 目标与账号 |
| `snmp_community` | SNMPv2c 只读团体名（建议在 ROS 上限定仅面板主机可读） |
| `if_index` | wan1/wan2/wan3 → ROS 接口的 SNMP ifIndex（`snmpwalk 1.3.6.1.2.1.2.2.1.2` 实测） |
| `lines` | 线路定义数组：`id`（wan1/wan2/wan3）、`label`（显示名，自定）、`pppoe_iface`（ROS 上的 pppoe-client 名）、`bandwidth_mbps`（理论带宽，聚合分担与限速按各线带宽占比派生；不填按 1000） |
| `nodes` | 机队节点数组：`key` / `label` / `ip`，可选 `group`（同组节点共享同一出口上限，聚合分配时同组只算一个源）；iperf/HTTP 测速经 SSH（`fleet_key`）到节点上拉起服务。数组顺序即聚合选源的优先级 |
| `fleet_key` | 机队 SSH 私钥路径 |
| `lan_cidr` | 局域网段（默认 `192.168.0.0/24`）；钉线/聚合规则用它排除内网目标，NAT 新增用它校验目标 IP |
| `fleet_domain_suffix` | 可选。机队域名后缀（如 `.example.com`）：node-sync 页用它把域名条目关联到节点（key = 去后缀的主机名）；空 = 不启用 |
| `mihomo_api` / `mihomo_secret` | 可选。OpenClash/mihomo 控制 API（如 `http://192.168.0.2:9090`），分流页读它拿真实链路；空 = 不启用 |
| `mac_lease_mac` / `mac_proxy_addr` / `mac_direct_addr` | 可选。「设备直连开关」：把某台设备的 DHCP 静态租约在代理地址与直连地址之间切换（直连地址需在 mangle 里另有豁免规则）；三项配齐才启用 |

## 功能

| 功能 | 说明 |
|---|---|
| 出口切换 | 各条 v4 线路卡片显示**实时下行/上行**(SNMP 每秒采样) + 在线状态灯；另有第一/第二线 IPv6 直连与"不钉线(旁路由)"对照 |
| Ping / TCP 握手 | 先解析真 IP（默认 DoH），再逐包显示 RTT/TTL + 丢包/抖动；ICMP 不通时可用 TCP 握手模式 |
| 路由追踪 | 逐跳流式 + 每跳 AS/国家；协议可选 ICMP(默认)/UDP/TCP:443 |
| 三线对比 | 依次切三条线，各测出口 IP + ping，最后自动恢复原出口 |
| iperf3 / 下载测速 | 自动 SSH 到机队节点放行端口并拉起 `iperf3 -s`；或拉节点上的大文件做真实线速测试；测完自动收回 |
| 三线聚合 | 同一个大文件多连接，用 ROS 的 PCC(源端口分桶)把本机流量同时摊到三条线，给出每条线实际分担 |
| DNS 真 IP | 多种解析方式对照展示 TTL/CNAME；`198.18/15` 直接标 fake-ip |
| 出口信息 | Cloudflare trace 取真实出口 IP + 落点，查 AS 与归属 |
| 线路钉线 | 直接编辑 ROS node-sync 脚本的 MAP 表（写前自动备份旧脚本），网页改线、后台应用 |
| NAT 管理 | ROS dstnat 规则查看/新增/启停/删除，新增按注释规范拼序号并回读校验 |
| PPPoE 重拨 | 三条线状态（IP/网关/在线时长）与逐线/全线重拨，过程带日志 |
| 机队体检 / Ping 趋势 | 节点 × 线路矩阵体检；每小时自动采样一轮 ping，保留多日趋势 |
| 设备直连开关 | （可选，需配 `mac_*`）一键把某台设备的租约在代理/直连之间切换 |

## API（节选）

```
GET  /api/status                      # 当前出口/线路状态/节点名单
POST /api/exit            {"wan":"1|2|3|v6|v6u|off"}
POST /api/resolve         {"name","type","resolver"}      # resolver 可为 doh.pub / alidns / IP
GET  /api/ping?target=&count=&resolver=                   # SSE: note/resolve/packet/summary
GET  /api/tcping?target=&port=&count=&resolver=           # SSE: TCP 握手
GET  /api/trace?target=&max=&q=&resolver=                 # SSE: hop/raw/done
GET  /api/compare?target=&count=                          # SSE: line(三线各一条)
GET  /api/exitinfo
POST /api/iperf           {"node","dir":"up|down","secs","streams"}
POST /api/iperf/ctl       {"node","on":false}             # 停服务端 + 关端口
POST /api/http            {"node","threads","secs","mode":"fleet|cf"}
POST /api/agg             {"node","threads","secs"}   # 三线聚合同拉一个文件
GET  /api/pppoe                                       # 线路状态
POST /api/pppoe/redial/start {"line":"wan1|wan2|wan3|all"}
GET  /api/nat  /  POST /api/nat/add|toggle|remove
GET|POST /api/macdirect                               # 设备直连开关(未配置返回 disabled)
```

## 验证

```bash
make test     # 纯函数单测: 跳解析 / IP 归一化 / fake-ip / AS 显示 / CGNAT / 速率换算等
make vet
make build
make smoke    # 本机 /api/status + /api/wanrate
```
测试只测纯函数，不联网、不碰 ROS，可随时跑。

## extras/（示例脚本，按自己的环境改）

- `extras/fleet_sync.py`：定时把 ROS node-sync 名册里的机队节点自动补进面板节点名单（只增不删）。
  域名后缀从环境变量 `FLEET_DOMAIN_SUFFIX` 或配置 `fleet_domain_suffix` 读，未配置则跳过。
- `extras/ros_nodepin_ensure.py`：钉线联动守护示例——确保 prerouting 末尾三条「节点表联动」
  规则存在且参数正确（地址表名/路由标记/注释前缀都在文件顶部常量里，按自己的 ROS 方案改）。

`tools/add-cn-notes.py`：给端点目录（`static/endpoints.json`）补中文备注字段的维护工具。

## 坑（都踩过）

1. **只钉前向不钉 DNS** → 本地 DNS 返回 fake-ip，连接打到 198.18.x 永远不通。面板必须直接问公共 DNS / DoH。
2. **明文 DNS 对境外域名可能不可信**（污染/回程被污染都有过）。要真 IP 优先用 DoH。
3. **必须强制 IPv4**：主机若有 v6 地址，`curl`/Go 默认 Happy Eyeballs 走 v6，绕开 v4 钉线规则。DoH 客户端强制 `tcp4`，其余命令全部 `-4`。
4. **REST 新建用 PUT**（返回 `{".id":"*xx"}`），改字段用 PATCH，删用 DELETE；`POST /ip/firewall/mangle` 会报 no such command。
5. **不要手改 mangle**：钉线规则注释带 `WANLAB` 标记，由面板独占维护；换 IP/重建容器后按注释+src 自动认领。中文注释必须走 REST 写入（SSH 会吞成空串）。
6. **iperf3 需要节点放行 5201**：节点上备一个 `fw-iperf on|off` 之类的开关脚本，面板测完自动关；HTTP 测速同理。
7. **iperf3 会低估线速**：判线速以「大文件 × 多线程」为准；判单文件体验看单线程。
8. 更新二进制前先 `systemctl stop`，否则覆盖写入报 `Text file busy`。
9. 容器/主机若采纳 ICMP redirect，会绕过 ROS 钉线（三线读数完全一致 = 包没走 ROS）；测速主机设 `accept_redirects=0`。
10. **追踪默认用 ICMP，不要只用 UDP**：骨干/对端常不回 UDP 的 TTL 超时，末尾一片 `*` 不代表链路坏。面板把协议做成可选并对"未到达"给出提示。
11. **别用 REST 做 1 秒轮询**：RouterOS 的 REST 每建一条新连接开销不小，高频轮询会被拖慢。实时速率改走 **SNMP**（`snmpget -v2c` 读 ifHCIn/OutOctets），单次毫秒级。
12. **AS 查询要有兜底**：公共 AS 接口偶发断连、小 AS 可能未收录 ⇒ 共享 client + 失败重试 + 备用接口；查不到的结果短时缓存，避免每次追踪都打接口。展示区分「归属库未收录」与「查询失败」；空字符串取字段前先判空，防 panic（另有 recover 兜底）。
13. **IPv6 的"链尾覆盖"不生效**：v4 可以靠 prerouting 链尾 mark-routing 覆盖前面的 to-proxy，但 v6 必须把规则**插到代理检查链的 jump 规则之前**并 `passthrough=no`（REST 里用 `"place-before":"*<jump-id>"`），否则出口仍是旁路由。
14. **Cloudflare 快速测速单次上限**：`speed.cloudflare.com/__down` 大尺寸会直接返 403，代码里用受限尺寸 + 唯一参数，并把非 200 当错误上报。

## 图标（可选）

仓库内只带 `static/icon.svg`（发布通道只接受文本文件）。如需 iOS 主屏幕图标与
PWA 的 PNG 图标，自行从 icon.svg 导出 180×180 / 192×192 / 512×512 三张 PNG
放回 `static/`，并恢复 `static/index.html` 中的 apple-touch-icon / icon-192
引用与 `static/manifest.webmanifest` 的 icons 列表即可。
