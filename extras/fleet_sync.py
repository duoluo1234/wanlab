#!/usr/bin/env python3
# fleet_sync(示例脚本): 把 ROS node-sync 里的机队节点自动补进 wanlab 测试台名单(只增不删)。
# 来源: node-sync 脚本源(机队钉线名单即机队名册)。范围: *.<机队域名后缀> 主机条目,
# 以及备注里标注了该域名的裸 IP 条目。段条目(/48、/64)与第三方落地不入。
# 去重: 解析出的 IP 已在名单里、或 key 已存在, 都跳过。名单有变化才写回+重启 wanlab。
# 机队域名后缀从环境变量 FLEET_DOMAIN_SUFFIX 或配置 fleet_domain_suffix 读
# (示例: ".example.com"); 未配置则不启用域名派生, 脚本直接退出。
import json, os, re, ssl, sys, socket, shutil, time, urllib.request, base64, subprocess

CFG_PATH = "/etc/wanlab/config.json"
DRY = "--dry-run" in sys.argv

cfg = json.load(open(CFG_PATH))
DOMAIN_SUFFIX = os.environ.get("FLEET_DOMAIN_SUFFIX") or cfg.get("fleet_domain_suffix") or ""
if not DOMAIN_SUFFIX:
    print("fleet-sync: 未配置域名后缀(FLEET_DOMAIN_SUFFIX 或 config.fleet_domain_suffix), 跳过")
    sys.exit(0)
if not DOMAIN_SUFFIX.startswith("."):
    DOMAIN_SUFFIX = "." + DOMAIN_SUFFIX
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

def ros(path):
    req = urllib.request.Request(cfg["ros_base"] + path,
        headers={"Authorization": "Basic " + base64.b64encode((cfg["ros_user"] + ":" + cfg["ros_pass"]).encode()).decode()})
    with urllib.request.urlopen(req, context=ctx, timeout=25) as r:
        return json.loads(r.read() or b"[]")

ns = [s for s in ros("/rest/system/script") if s["name"] == "node-sync"]
if not ns:
    print("fleet-sync: ROS 上找不到 node-sync, 跳过"); sys.exit(0)
src = ns[0]["source"]

def resolve(name):
    """返回 (ipv4, ipv6) — 各取第一条, 没有的为 None"""
    v4 = v6 = None
    try:
        for fam, _, _, _, addr in socket.getaddrinfo(name, None, 0, socket.SOCK_STREAM):
            if fam == socket.AF_INET and not v4: v4 = addr[0]
            if fam == socket.AF_INET6 and not v6: v6 = addr[0]
    except Exception as e:
        print(f"fleet-sync: 解析 {name} 失败: {e}")
    return v4, v6

existing_ips = {n["ip"] for n in cfg["nodes"]}
existing_keys = {n["key"] for n in cfg["nodes"]}
added = []

for ln in src.splitlines():
    m = re.match(r'\s*"([^"|]+)\|([^"|]+)(?:\|([^"]*))?"\s*;', ln)
    if not m:
        continue
    host, _wan, label = m.group(1), m.group(2), (m.group(3) or "")
    if "/" in host:  # 段条目
        continue
    if host.endswith(DOMAIN_SUFFIX):
        key = host.split(".")[0]
        domain = host
    elif re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        dm = re.search(r"([a-z0-9-]+)" + re.escape(DOMAIN_SUFFIX), label)
        if not dm:  # 裸 IP 且没标注自家域名 — 不是机队节点
            continue
        key = dm.group(1)
        domain = dm.group(0)
    else:  # 第三方落地
        continue
    v4, v6 = resolve(domain)
    ip = v4 or v6
    if not ip:
        continue
    if ip in existing_ips or key in existing_keys:
        continue
    cfg["nodes"].append({"ip": ip, "key": key, "label": key, "auto": True})
    existing_ips.add(ip); existing_keys.add(key)
    added.append(f"{key} {ip}")

if not added:
    print("fleet-sync: 无新增(机队已全在册)")
    sys.exit(0)

print("fleet-sync: 新增节点: " + ", ".join(added))
if DRY:
    print("fleet-sync: dry-run, 不写回")
    sys.exit(0)
shutil.copy(CFG_PATH, CFG_PATH + ".bak-autosync-" + time.strftime("%Y%m%d%H%M%S"))
with open(CFG_PATH, "w") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=1)
subprocess.run(["systemctl", "restart", "wanlab"], check=False)
print("fleet-sync: 已写回名单并重启 wanlab")
