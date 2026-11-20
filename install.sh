#!/bin/sh
# wanlab 一键安装: 编译 -> 装二进制 -> 写示例配置 -> 注册 systemd 并启动。
# 幂等: 重复运行只更新二进制与单元文件, 已存在的 /etc/wanlab/config.json 不覆盖。
set -eu

if [ "$(id -u)" != "0" ]; then
  echo "请用 root 运行: sudo ./install.sh" >&2
  exit 1
fi

cd "$(dirname "$0")"

# 1) 编译(纯 Go 标准库)。已有预编译二进制时可 SKIP_BUILD=1 跳过。
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  [ -f wanlab-linux ] || { echo "SKIP_BUILD=1 但当前目录没有 wanlab-linux" >&2; exit 1; }
else
  command -v go >/dev/null 2>&1 || { echo "未找到 go, 请先安装 Go 1.21+ 或用 SKIP_BUILD=1 配预编译二进制" >&2; exit 1; }
  echo "== 编译 wanlab-linux =="
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o wanlab-linux .
fi

# 2) 二进制与目录
echo "== 安装二进制到 /opt/wanlab/wanlab =="
install -d /opt/wanlab /etc/wanlab
install -m 755 wanlab-linux /opt/wanlab/wanlab

# 3) 配置: 只在不存在时写示例, 避免覆盖线上配置
if [ -f /etc/wanlab/config.json ]; then
  echo "== /etc/wanlab/config.json 已存在, 保持不动 =="
else
  install -m 600 config.example.json /etc/wanlab/config.json
  echo "== 已写入示例配置 /etc/wanlab/config.json (权限 600), 请按自己的环境修改 ros_*/lines/nodes =="
fi

# 4) systemd
echo "== 注册 systemd 单元 =="
install -m 644 systemd/wanlab.service /etc/systemd/system/wanlab.service
systemctl daemon-reload
systemctl enable --now wanlab

echo
echo "完成。面板地址见 config.json 的 listen 字段(默认 :8688)。"
echo "运行依赖(Debian 系): iputils-ping traceroute dnsutils curl iperf3 openssh-client snmp"
echo "状态查看: systemctl status wanlab / journalctl -u wanlab -f"
