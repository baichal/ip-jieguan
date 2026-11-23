#!/usr/bin/env python3.12
# -*- coding: utf-8 -*-
"""隧道模式出站本地 mock 验证：src_ip 进入 A 侧路由命令、非法 src_ip 拒绝、status 显示。
不连真实服务器、不改生产配置。"""
import sys, os, tempfile
sys.path.insert(0, "/workspace/ip-takeover-tool")
import takeover

PASS, FAIL = [], []
def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"{'通过' if cond else '失败'} | {name}" + (f" | {detail}" if detail else ""))

APP_IP = "198.51.100.10"
REL_IP = "203.0.113.20"
TUN_VIA = "10.9.0.1"

class MockEx:
    CMDS = []
    RULE_DB = []
    def __init__(self, role): self.role = role
    def run(self, argv, timeout=30):
        a = list(map(str, argv))
        MockEx.CMDS.append((self.role, a))
        if a[:3] == ["ip", "rule", "add"]:
            pref = a[a.index("pref") + 1] if "pref" in a else "0"
            tbl = a[a.index("lookup") + 1] if "lookup" in a else ""
            MockEx.RULE_DB.append(f"{pref}:\tfrom all lookup {tbl}")
            return 0, "", ""
        if a[:3] == ["ip", "rule", "del"] and "pref" in a:
            p = a[a.index("pref") + 1]
            MockEx.RULE_DB = [l for l in MockEx.RULE_DB if not l.startswith(p + ":")]
            return 0, "", ""
        if a[:2] == ["ip", "route"] and len(a) >= 3 and a[2] == "get":
            return 0, f"{a[3]} dev wg0 src {APP_IP}", ""
        if a[:1] == ["iptables-save"]:
            return 0, "# Generated\n*nat\nCOMMIT\n", ""
        if a[:2] == ["ip", "rule"] and a[2:3] == ["show"]:
            return 0, "\n".join(MockEx.RULE_DB), ""
        if a[:2] == ["ip", "route"] and a[2:4] == ["show", "table"]:
            return 0, "", ""
        return 0, "", ""
    def run_shell(self, cmd, timeout=30):
        MockEx.CMDS.append((self.role, ["SHELL", cmd])); return 0, "", ""
    def write_file(self, path, content, mode=0o600): return None
    def read_file(self, path): return "{}"
    def close(self): pass

def mk_tk():
    d = tempfile.mkdtemp(prefix="tk-tun-")
    sp = os.path.join(d, "state.json")
    init = {
        "version": "1.0", "role": "controller", "controller": {"host": APP_IP},
        "servers": [
            {"id": "app1", "role": "app", "ip": APP_IP, "ssh_port": 22, "user": "root", "enabled": True},
            {"id": "relay1", "role": "relay", "ip": REL_IP, "ssh_port": 22, "user": "root", "enabled": True,
             "exclude_ports": [22], "auto_exclude_enabled": False},
        ],
        "rules": [], "egress": None,
    }
    import json
    with open(sp, "w") as f: json.dump(init, f)
    store = takeover.StateStore(path=sp)
    tk = takeover.Takeover(store=store)
    tk.executor_for = lambda srv, pw: MockEx("app" if srv.get("role") == "app" else "relay")
    return tk

# 1) 正常：带 src_ip 的隧道配置能保存
tk = mk_tk()
MockEx.CMDS.clear()
ok, msg = tk.egress_config("app1", "relay1", "targets", ["198.51.100.80/32"],
                           lambda s: "pw", via=TUN_VIA, src_ip=APP_IP,
                           mgmt_nets=["198.51.100.0/24"])
check("隧道配置(src_ip=合法IP)保存成功", ok, msg)
cfg = tk.store.load().get("egress", {})
check("state 保存 via=隧道地址", cfg.get("via") == TUN_VIA)
check("state 保存 src_ip", cfg.get("src_ip") == APP_IP)

# 2) A 侧策略路由下发：default via <隧道地址> src <A公网IP> table 105
ok2, msg2 = tk.egress_enable(lambda s: "pw", assume_yes=True)
check("egress enable 成功", ok2, msg2)
app_route = [a for r, a in MockEx.CMDS if r == "app" and a[:3] == ["ip", "route", "add"]]
# 形如 ip route add default via 10.9.0.1 src 198.51.100.10 table 105
hit = [a for a in app_route if "src" in a and a[a.index("src") + 1] == APP_IP
       and "default" in a and a[a.index("via") + 1] == TUN_VIA]
check("A侧路由含 default via 隧道地址 + src=A公网IP", bool(hit), " ".join(app_route[0]) if app_route else "无路由命令")
check("src 参数位置在 table 之前", bool(hit) and hit[0].index("src") < hit[0].index("table"))

# 3) B 侧 SNAT 仍用 app_ip 匹配（未受影响）
relay_snat = [a for r, a in MockEx.CMDS if r == "relay" and a[:2] == ["iptables", "-t"]
              and "SNAT" in a]
check("B侧SNAT规则仍生成", bool(relay_snat))
if relay_snat:
    check("B侧SNAT源仍为A公网IP(逻辑未变)", APP_IP in relay_snat[0])

# 4) 非法 src_ip 被拒
tk3 = mk_tk()
bad_ok, bad_msg = tk3.egress_config("app1", "relay1", "targets", ["1.2.3.4/32"],
                                    lambda s: "pw", via=TUN_VIA, src_ip="not-an-ip")
check("非法 src_ip 被拒绝", not bad_ok, bad_msg)

# 5) status 显示 src_ip
tk5 = mk_tk()
tk5.egress_config("app1", "relay1", "targets", ["198.51.100.80/32"],
                  lambda s: "pw", via=TUN_VIA, src_ip=APP_IP)
sok, report = tk5.egress_status()
check("status 显示出站源IP", "出站源IP" in report and APP_IP in report)
check("status 显示隧道下一跳", TUN_VIA in report)

print(f"\n汇总：通过 {len(PASS)} / 失败 {len(FAIL)}")
if FAIL:
    print("失败项：", FAIL)
    sys.exit(1)
