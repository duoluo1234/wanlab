#!/usr/bin/env python3
# 【示例脚本】节点钉线联动守护: 确保 prerouting 末尾三条「节点表联动」规则存在且参数正确。
# 这是针对一套特定 RouterOS 钉线方案的示例: 规则按 node-v4-wan1/2/3 地址表匹配
# (名单由节点同步维护), 压在 PCC mark-routing 之后, 防止节点 IP 落入其它
# 地址表(如 geo-cn)时被 PCC 覆盖钉线。你的地址表名/路由标记/注释规范不同的话,
# 改下面「可配置常量」一节即可。
# 幂等: 缺失则补建(--fix), 参数漂移则报告。用法: python3 ros_nodepin_ensure.py [--fix]
import json, os, urllib.request, base64, sys

# ==== 可配置常量(按自己的 RouterOS 方案改) ====
CONFIG_PATH = os.environ.get("WANLAB_CONFIG", "/etc/wanlab/config.json")
ROS_BASE = os.environ.get("ROS_BASE", "")   # 空 = 用 config.json 的 ros_base; 例: "http://192.168.0.1"
COMMENT_PREFIX = "【钉线】"                  # 这类规则的注释前缀, 靠它在 mangle 表里认规则
# (地址表, 目标路由标记, 新建时的注释)
RULES = [
    ("node-v4-wan1", "to-wan1", "【钉线】节点表联动: node-v4-wan1 -> to-wan1 (示例注释, 按你的注释规范改)"),
    ("node-v4-wan2", "to-wan2", "【钉线】节点表联动: node-v4-wan2 -> to-wan2 (示例注释, 按你的注释规范改)"),
    ("node-v4-wan3", "to-wan3", "【钉线】节点表联动: node-v4-wan3 -> to-wan3 (示例注释, 按你的注释规范改)"),
]

cfg = json.load(open(CONFIG_PATH))
def find_creds(root):
    stack = [root]
    while stack:
        o = stack.pop()
        if isinstance(o, dict):
            ks = {}
            for k in o: ks[k.lower()] = k
            uk = None; pk = None
            for cand in ("user", "username", "ros_user", "api_user"):
                if cand in ks: uk = ks[cand]; break
            for cand in ("pass", "password", "ros_pass", "api_pass"):
                if cand in ks: pk = ks[cand]; break
            if uk and pk: return o[uk], o[pk]
            for v in o.values(): stack.append(v)
        elif isinstance(o, list):
            for v in o: stack.append(v)
u, pw = find_creds(cfg)
AUTH = "Basic " + base64.b64encode(f"{u}:{pw}".encode()).decode()
BASE = (ROS_BASE or cfg.get("ros_base") or "http://192.168.0.1").rstrip("/") + "/rest"
def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
                               headers={"Authorization": AUTH, "Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=30) as resp:
        t = resp.read().decode()
        return json.loads(t) if t.strip() else {}
fix = "--fix" in sys.argv
mangle = req("GET", "/ip/firewall/mangle")
rc = 0
for lst, mark, comment in RULES:
    found = [r for r in mangle if r.get("chain") == "prerouting" and r.get("dst-address-list") == lst
             and r.get("action") == "mark-routing" and (r.get("comment") or "").startswith(COMMENT_PREFIX)]
    good = [r for r in found if r.get("new-routing-mark") == mark and r.get("passthrough") == "false" and r.get("disabled") in (None, "false")]
    if good:
        print(f"OK   {lst} -> {mark} ({good[0].get('.id')}, packets={good[0].get('packets')})")
    elif found:
        print(f"DRIFT {lst}: rule exists but params off: {found[0].get('.id')} mark={found[0].get('new-routing-mark')} pt={found[0].get('passthrough')} disabled={found[0].get('disabled')}")
        rc = 1
    else:
        print(f"MISSING {lst} -> {mark}")
        rc = 1
        if fix:
            res = req("PUT", "/ip/firewall/mangle", {"chain": "prerouting", "dst-address-list": lst,
                      "action": "mark-routing", "new-routing-mark": mark, "passthrough": "false", "comment": comment})
            print(f"CREATED {lst} -> {mark} ({res.get('.id')})")
            rc = 0
sys.exit(rc)
