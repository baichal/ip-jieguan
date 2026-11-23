#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 接管配置工具 v1.0  ——  命令行脚本版

合规声明：本工具仅用于你拥有合法管理权限的服务器。首次运行即表示你已确认
对目标服务器及 IP 拥有合法授权。请将本脚本部署在内网/可信环境，勿放置公网。

设计依据：DESIGN.md / SECURITY.md / server-ip-takeover-plan.md
"""

import os
import sys
import json
import time
import uuid
import shlex
import shutil
import getpass
import ipaddress
import hashlib
import base64
import resource
import argparse
import http.client
import re
import datetime
import importlib.util
import subprocess

# ---------------------------------------------------------------------------
# 0x. 自举引导：在新机器上运行时自动检测并安装所需依赖
#     仅使用标准库，因此可在 paramiko 可用之前执行。
#     若已是完整环境，全程静默、零额外开销。
# ---------------------------------------------------------------------------

_BOOT_DIR = os.path.dirname(os.path.abspath(__file__))
_BOOT_LOG = os.path.join(_BOOT_DIR, "bootstrap.log")

def _boot_log(msg):
    try:
        with open(_BOOT_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}\n")
        os.chmod(_BOOT_LOG, 0o600)
    except Exception:
        pass

def _have(mod):
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False

def _run(cmd, timeout=300):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except Exception as e:
        return 1, "", str(e)

def _ensure_pip():
    if _run([sys.executable, "-m", "pip", "--version"])[0] == 0:
        return True
    print("检测到系统缺少 pip，正在自动安装 pip ...")
    _boot_log("pip 缺失，尝试安装")
    # 优先用标准库自带 ensurepip
    if _run([sys.executable, "-m", "ensurepip", "--upgrade"])[0] == 0:
        if _run([sys.executable, "-m", "pip", "--version"])[0] == 0:
            _boot_log("通过 ensurepip 安装 pip 成功")
            return True
    # 退而求其次：系统包管理器
    for mgr in ("apt-get", "dnf", "yum"):
        if shutil.which(mgr):
            if mgr == "apt-get":
                _run(["apt-get", "update", "-qq"], timeout=300)
                _run(["apt-get", "install", "-y", "-qq", "python3-pip"], timeout=300)
            else:
                _run([mgr, "install", "-y", "python3-pip"], timeout=300)
            if _run([sys.executable, "-m", "pip", "--version"])[0] == 0:
                _boot_log(f"通过 {mgr} 安装 pip 成功")
                return True
    # 最后兜底：下载官方 get-pip.py 自举（镜像优先，下载后校验完整性）
    print("系统包管理器未能提供 pip，尝试通过 get-pip.py 自举 ...")
    for url in ("https://mirrors.aliyun.com/pypi/get-pip.py",
                "https://bootstrap.pypa.io/get-pip.py"):
        gp = "/tmp/tkv_getpip.py"
        try:
            if os.path.exists(gp):
                os.remove(gp)
        except Exception:
            pass
        rc, out, err = _run(["curl", "-fsSL", "--max-time", "180", "-o", gp, url], timeout=200)
        if rc != 0:
            rc, out, err = _run(["wget", "-q", "-T", "180", "-O", gp, url], timeout=200)
        if rc != 0 or not os.path.exists(gp) or os.path.getsize(gp) < 100000:
            _boot_log(f"get-pip 下载失败或不完整：{url}")
            continue  # 下载不完整，换下一个源
        # 语法校验，确保文件完整
        if _run([sys.executable, "-c",
                 "import ast,sys; ast.parse(open(sys.argv[1],encoding='utf-8').read())", gp])[0] != 0:
            _boot_log(f"get-pip 文件校验失败：{url}")
            continue
        rc, out, err = _run([sys.executable, gp, "--break-system-packages"], timeout=300)
        if rc != 0:
            rc, out, err = _run([sys.executable, gp], timeout=300)
        if rc == 0 and _run([sys.executable, "-m", "pip", "--version"])[0] == 0:
            _boot_log(f"通过 get-pip.py ({url}) 安装 pip 成功")
            try:
                os.remove(gp)
            except Exception:
                pass
            return True
    return False

def _pip_install(spec, required=True):
    """安装单个 Python 包；兼容 PEP 668（externally-managed）环境。"""
    attempts = [
        [sys.executable, "-m", "pip", "install", "--break-system-packages", "-q", spec],
        [sys.executable, "-m", "pip", "install", "-q", spec],
    ]
    last = ""
    for cmd in attempts:
        rc, out, err = _run(cmd)
        if rc == 0:
            _boot_log(f"已安装 {spec}")
            return True
        last = (err or out)
        low = last.lower()
        if "no module named pip" in low:
            break
        if "no such option" in low or "unrecognized arguments" in low:
            continue  # 老 pip 不认 --break-system-packages，换下一种
    if required:
        print(f"依赖安装失败：{spec}；{last}")
        _boot_log(f"安装失败 {spec}: {last[:300]}")
    return False

def _ensure_python_deps():
    """按需安装 Python 依赖。paramiko 必需；questionary 可选（缺失则文本菜单降级）。"""
    if not _ensure_pip():
        print("警告：无法自动安装 pip，依赖安装可能失败。请手动安装 python3-pip。")
    if not _have("paramiko"):
        print("检测到缺少依赖 paramiko，正在自动安装 ...")
        if not _pip_install("paramiko==5.1.0", required=True):
            print("错误：paramiko 安装失败，程序无法继续。请手动执行：pip install paramiko==5.1.0")
            sys.exit(1)
    if not _have("cryptography"):
        print("检测到缺少依赖 cryptography，正在自动安装（用于本地加密凭据） ...")
        if not _pip_install("cryptography", required=True):
            print("错误：cryptography 安装失败，加密凭据功能不可用。请手动执行：pip install cryptography")
            sys.exit(1)
    if not _have("questionary"):
        # 图形菜单为增强项：安装失败不阻断，TUI 会自动降级为文本菜单
        _pip_install("questionary==2.1.1", required=False)

def _ensure_system_tools():
    """确保底层 iptables 可用（转发功能的核心依赖）。"""
    if shutil.which("iptables") is None:
        print("检测到缺少 iptables，正在自动安装 ...")
        _boot_log("iptables 缺失，尝试安装")
        for mgr in ("apt-get", "dnf", "yum"):
            if shutil.which(mgr):
                if mgr == "apt-get":
                    _run(["apt-get", "update", "-qq"], timeout=300)
                    _run(["apt-get", "install", "-y", "-qq", "iptables"], timeout=300)
                else:
                    _run([mgr, "install", "-y", "iptables"], timeout=300)
                if shutil.which("iptables"):
                    _boot_log(f"通过 {mgr} 安装 iptables 成功")
                    return True
        print("警告：iptables 自动安装失败，转发功能不可用。请手动安装 iptables。")
        return False
    return True

_ensure_python_deps()
_ensure_system_tools()

import paramiko  # noqa: E402  （由自举层保证可用）
from cryptography.fernet import Fernet, InvalidToken  # noqa: E402

# ---------------------------------------------------------------------------
# 0. 常量与中文文案（所有用户可见文字集中定义）
# ---------------------------------------------------------------------------

VERSION = "1.0"
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(TOOL_DIR, "state.json")
KNOWN_HOSTS_PATH = os.path.join(TOOL_DIR, "known_hosts")
AUDIT_PATH = os.path.join(TOOL_DIR, "audit.log")
CRED_KEY_PATH = os.path.join(TOOL_DIR, "credential.key")
CRED_STORE_PATH = os.path.join(TOOL_DIR, "credentials.enc")
TAG_PREFIX = "TAKEOVER:"
# 对端脚本统一部署目录；状态同步只写只读镜像，主控端 state.json 仍是唯一真相源。
PEER_STATE_DIR = "/root/ip-takeover-tool"
PEER_STATE_PATH = PEER_STATE_DIR + "/state.json"
# V2.0 出站：A 侧用独立策略路由表，避免改动主表默认路由（disable 可完整恢复）
EGRESS_TABLE_ID = 105                 # 独立路由表号；不与系统常用表冲突
EGRESS_PREF_BASE = 10300              # ip rule 优先级基数；异常规则占用 10290-10299
EGRESS_SNAPSHOT = "/root/egress.iprule.TAKEOVER.snapshot"  # A 侧 ip rule 备份

S = {
    "banner": f"IP 接管配置工具 v{VERSION} —— 请确认对目标服务器拥有合法管理权限",
    "role_prompt": "请选择本机角色：",
    "role_relay": "1) relay  转发端（持有对外 IP，转发流量）",
    "role_app": "2) app    应用端（实际跑业务）",
    "role_ctrl": "3) controller  主控端（管理两端，推荐在其中一台上选此项）",
    "role_set": "本机角色已设置为：{role}",
    "ask_ip": "请输入 IP 地址：",
    "ask_ssh_port": "请输入 SSH 端口（默认 22）：",
    "ask_user": "请输入 SSH 用户名：",
    "ask_pass": "请输入密码（输入不显示）：",
    "ask_app_port": "请输入应用端业务端口：",
    "ask_relay_port": "请输入转发端监听端口：",
    "bad_ip": "IP 格式不正确，请重新输入",
    "bad_port": "端口必须是 1-65535 的数字",
    "same_ip": "转发端与应用端不能是同一 IP",
    "required": "该项为必填",
    "connecting": "正在检测连通性...",
    "conn_ok": "连接成功",
    "conn_fail": "连接失败：{reason}",
    "fingerprint": "首次连接，服务器指纹：{fp}\n类型：{kt}",
    "ask_trust": "请核对指纹是否可信，确认继续？[y/N]",
    "fp_changed": "警告：服务器指纹与记录不一致，可能遭遇中间人攻击，已中止！",
    "backing_up": "正在备份转发端规则...",
    "applying": "正在下发转发规则...",
    "verifying": "正在验证...",
    "success": "配置成功",
    "failed": "配置失败：{reason}",
    "confirm_remove": "即将删除{role} {ip}，将影响 {n} 条转发规则，是否继续？[y/N]",
    "confirm_disable": "即将关闭{role} {ip}，相关规则将失效，是否继续？[y/N]",
    "confirm_rollback": "即将把转发端 {ip} 全量恢复到首次备份，是否继续？[y/N]",
    "cancelled": "已取消",
    "no_server": "未找到指定服务器",
    "no_rule": "未找到指定规则",
    "need_controller": "该命令需在主控端执行（先运行 init 选择 controller）",
    "need_relay": "该操作仅适用于转发端服务器",
    "disabled": "已关闭",
    "enabled": "已开启",
    "effective": "生效中",
    "ineffective": "未生效（关联服务器或规则已关闭）",
    "ssh_excluded": "SSH 端口强制在排除列表中，不可移除",
    "exclude_ok": "排除端口已更新并重新下发规则",
    # 自动排除转发端已用端口
    "auto_exclude_on": "已开启自动排除转发端已用端口",
    "auto_exclude_off": "已关闭自动排除（注意：转发端已监听端口将不再被自动保护）",
    "auto_exclude_scanned": "已检测转发端监听端口并重新下发规则",
    "auto_exclude_detect_fail": "无法检测转发端监听端口（ss/netstat/proc 均不可用），为保证原有业务安全已中止下发",
    "auto_exclude_mapped_conflict": "映射端口 {ports} 已被转发端占用，继续将破坏原有业务，已拒绝下发",
    "restored": "已回滚到首次备份",
    "state_bad": "状态文件损坏或格式错误，已中止以避免误操作",
    "keep_session": "请保持当前 SSH 会话不要断开，并确保有带外访问（VNC）兜底。",
    # V2.0 出站身份
    "need_app": "该操作仅适用于应用端服务器",
    "egress_not_config": "尚未配置出站，请先 egress setup 选择应用端与转发端",
    "egress_bad_target": "目标必须是合法 IP 或 CIDR（如 1.2.3.4 或 10.0.0.0/8）",
    "egress_scope_empty": "scope 模式至少需要一个目标网段",
    "egress_confirm": (
        "即将开启出站身份接管，影响如下：\n"
        "  应用端 {app} 主动对外流量 → 经转发端 {relay} 出去，源 IP 显示为 {relay}\n"
        "  范围：{scope}\n"
        "  应用端将新增独立策略路由表（表号 {table}）与 ip rule，不改主表默认路由\n"
        "  前置条件：应用端与转发端需二层可达（同网段/VPC，或已建立隧道）\n"
        "  注意：出站流量全部经过转发端，转发端为单点且成为带宽瓶颈；\n"
        "        SSH 管理流量建议保留直连路由，勿把管理网段纳入范围。\n"
        "是否继续？[y/N]"),
    "egress_confirm_disable": "即将关闭出站接管：撤销转发端 SNAT 与应用端策略路由，恢复原出口。是否继续？[y/N]",
    "egress_enabled": "出站接管已开启并下发",
    "egress_disabled": "出站接管已关闭并恢复原出口",
    "egress_l2_warn": "警告：应用端与转发端可能非二层可达（{detail}）。直接把网关指向转发端公网 IP 可能不通；请先建立隧道（如 WireGuard）或以二层地址作为 egress.via，否则出站不生效。",
}

# ---------------------------------------------------------------------------
# 1. 基础加固：禁用 core dump；凭据用后清零
# ---------------------------------------------------------------------------

def disable_core_dump():
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass

class Secret:
    """内存中的密码，bytearray 存储，用后清零，禁止明文出现在 repr/日志。"""
    __slots__ = ("_buf",)
    def __init__(self, value):
        if isinstance(value, Secret):
            self._buf = bytearray(value._buf)
        else:
            self._buf = bytearray(str(value).encode("utf-8"))
    def value(self):
        return self._buf.decode("utf-8")
    def clear(self):
        for i in range(len(self._buf)):
            self._buf[i] = 0
    def __repr__(self):
        return "***"
    def __str__(self):
        return "***"
    def __del__(self):
        try:
            self.clear()
        except Exception:
            pass

def credential_aliases(server):
    """服务器在加密凭据库中的多个索引名，兼容 id / ip / ip:port / user@ip。"""
    ip = str(server.get("ip") or "").strip()
    port = str(server.get("ssh_port") or 22).strip()
    user = str(server.get("user") or "root").strip()
    sid = str(server.get("id") or "").strip()
    vals = []
    for v in (sid, ip, f"{ip}:{port}", f"{user}@{ip}", f"{user}@{ip}:{port}"):
        if v and v not in vals:
            vals.append(v)
    return vals

class EncryptedCredentialStore:
    """本地加密凭据库：Fernet(AES-128-CBC+HMAC-SHA256)，密钥与密文均为 600。

    安全边界：这是用户明确要求“加密保存、免输入”后的折中方案。密码不再仅存内存，
    而是以密文落盘；密钥与密文分开保存在工具目录，权限 600，不进入 state/audit/log。
    """
    def __init__(self, key_path=CRED_KEY_PATH, store_path=CRED_STORE_PATH):
        self.key_path = key_path
        self.store_path = store_path

    def _read_key(self):
        with open(self.key_path, "rb") as f:
            key = f.read().strip()
        Fernet(key)  # 校验格式
        return key

    def _ensure_key(self):
        if os.path.exists(self.key_path):
            return self._read_key()
        key = Fernet.generate_key()
        try:
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
                f.flush()
                os.fsync(f.fileno())
        except FileExistsError:
            key = self._read_key()
        os.chmod(self.key_path, 0o600)
        return key

    def _fernet(self):
        return Fernet(self._ensure_key())

    def load(self):
        if not os.path.exists(self.store_path):
            return {}
        with open(self.store_path, "rb") as f:
            raw = f.read()
        if not raw.strip():
            return {}
        try:
            plain = self._fernet().decrypt(raw)
        except InvalidToken:
            raise RuntimeError("加密凭据库解密失败：密钥不匹配或文件已损坏")
        try:
            obj = json.loads(plain.decode("utf-8"))
        except Exception:
            raise RuntimeError("加密凭据库格式异常")
        entries = obj.get("entries", {}) if isinstance(obj, dict) else {}
        return entries if isinstance(entries, dict) else {}

    def save(self, entries):
        payload = {"version": 1, "entries": entries}
        raw = self._fernet().encrypt(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        tmp = self.store_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.store_path)
        os.chmod(self.store_path, 0o600)

    def put(self, server, password):
        pw = password.value() if isinstance(password, Secret) else str(password)
        if not pw:
            return False
        entries = self.load()
        for alias in credential_aliases(server):
            entries[alias] = pw
        self.save(entries)
        return True

    def get(self, server):
        entries = self.load()
        for alias in credential_aliases(server):
            if alias in entries:
                return str(entries[alias])
        return None

    def keys(self):
        return sorted(self.load().keys())

    def delete(self, key):
        entries = self.load()
        if key not in entries:
            return False
        del entries[key]
        self.save(entries)
        return True

    def clear(self):
        self.save({})
        return True

# ---------------------------------------------------------------------------
# 2. 输入校验
# ---------------------------------------------------------------------------

def valid_ip(text):
    try:
        ipaddress.ip_address(str(text).strip())
        return True
    except Exception:
        return False

def valid_cidr(text):
    """校验 IP 或 CIDR 网段；纯 IP 视为 /32。返回规范化字符串，非法返回 None。"""
    s = str(text).strip()
    if not s:
        return None
    try:
        if "/" in s:
            net = ipaddress.ip_network(s, strict=False)
            return str(net)
        ip = ipaddress.ip_address(s)
        return str(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False))
    except Exception:
        return None

def valid_port(text):
    s = str(text).strip()
    if not s.isdigit():
        return False
    return 1 <= int(s) <= 65535

def parse_ports(text):
    """解析 '80,443,8000-9000' -> [80,443,8000..9000]；非法返回 None。"""
    result = set()
    for part in str(text).replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            bits = part.split("-")
            if len(bits) != 2 or not all(b.isdigit() for b in bits):
                return None
            a, b = int(bits[0]), int(bits[1])
            if not (1 <= a <= b <= 65535):
                return None
            result.update(range(a, b + 1))
        else:
            if not part.isdigit() or not (1 <= int(part) <= 65535):
                return None
            result.add(int(part))
    return sorted(result) if result else None

def build_ports_expr(exclude_ports, ssh_port=22):
    """
    生成转发端口表达式：全集 [1,65535] - (排除集 ∪ {ssh_port})，合并为连续区间。
    返回 (expr, ranges_count)；若区间过多，expr 为 None（调用方改用 RETURN 降级方案）。
    """
    ex = set(int(p) for p in exclude_ports)
    ex.add(int(ssh_port))
    ex = sorted(p for p in ex if 1 <= p <= 65535)
    ranges = []
    start = 1
    for p in ex:
        if p > start:
            ranges.append((start, p - 1))
        start = max(start, p + 1)
    if start <= 65535:
        ranges.append((start, 65535))
    parts = [f"{a}" if a == b else f"{a}:{b}" for a, b in ranges]
    # multiport 真实限制：最多 15 个端口"槽位"，单端口算 1、range 算 2。
    # 仅按段数判断会在 nf_tables 后端触发 "too many ports specified"。
    slots = sum(1 if a == b else 2 for a, b in ranges)
    if slots > 15:
        return None, len(ranges)
    return ",".join(parts), len(ranges)


# ---- 转发端已用端口检测（保护原有业务不被 DNAT 劫持） ----
_SS_STATES = {"listen", "unconn", "estab", "time-wait", "close-wait", "syn-sent",
              "syn-recv", "fin-wait-1", "fin-wait-2", "last-ack", "closing"}

def _port_from_addr(token):
    """从 addr:port 中提取端口，兼容 IPv4/IPv6（[::]:80、:::80、0.0.0.0:80）。"""
    token = (token or "").strip()
    if token.startswith("["):               # IPv6 带方括号：[::]:80
        idx = token.find("]:")
        if idx < 0:
            return None
        port = token[idx + 2:]
    else:
        if ":" not in token:
            return None
        port = token.rsplit(":", 1)[-1]
    return int(port) if port.isdigit() and 1 <= int(port) <= 65535 else None

def parse_ss_ports(out):
    """解析 ss -lntu / ss -H -lntu 的监听端口。
    兼容两种列格式：
      - 无 Netid 列：state recv-q send-q local peer
      - 带 Netid 列（部分发行版）：netid state recv-q send-q local peer
    做法是定位 state 关键字，再取其后的 local address（state 后第 3 列）。
    """
    ports = set()
    for line in (out or "").splitlines():
        parts = line.split()
        # 定位 state 关键字（兼容前面是否带 netid 列）
        idx = None
        for i, tok in enumerate(parts):
            if tok.lower() in _SS_STATES:
                idx = i
                break
        if idx is None or len(parts) < idx + 4:
            continue
        p = _port_from_addr(parts[idx + 3])
        if p:
            ports.add(p)
    return ports

def parse_netstat_ports(out):
    """解析 netstat -lntu：proto recv-q send-q local foreign state。"""
    ports = set()
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0].lower().startswith(("tcp", "udp")):
            p = _port_from_addr(parts[3])
            if p:
                ports.add(p)
    return ports

def parse_proc_ports(out, is_tcp=True):
    """解析 /proc/net/tcp{,6}、udp{,6}：端口为十六进制；TCP 仅取 LISTEN(0A)。"""
    ports = set()
    for line in (out or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        if is_tcp and parts[3].upper() != "0A":
            continue
        try:
            port = int(parts[1].rsplit(":", 1)[-1], 16)
        except (ValueError, IndexError):
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return ports

def detect_used_ports(ex):
    """检测转发端正在监听的 TCP/UDP 端口，返回 (端口集合, 检测来源)。
    依次尝试 ss、netstat、/proc/net/tcp*；全部失败返回 (空集, '')。
    """
    for argv in (["ss", "-H", "-lntu"], ["ss", "-lntu"]):
        rc, out, err = ex.run(argv)
        if rc == 0 and out.strip():
            ports = parse_ss_ports(out)
            if ports:
                return ports, "ss"
    rc, out, err = ex.run(["netstat", "-lntu"])
    if rc == 0 and out.strip():
        ports = parse_netstat_ports(out)
        if ports:
            return ports, "netstat"
    ports = set()
    proc_ok = False
    for path in ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"):
        rc, out, err = ex.run(["cat", path])
        if rc == 0 and out.strip():
            proc_ok = True
            ports |= parse_proc_ports(out, is_tcp=("/tcp" in path))
    return ports, ("/proc" if proc_ok else "")

def effective_excludes(relay):
    """转发端实际生效的排除端口 = 手动 + 自动检测(若启用) + SSH 强制。"""
    ex = set(int(p) for p in relay.get("exclude_ports", []))
    if relay.get("auto_exclude_enabled", True):
        ex |= set(int(p) for p in relay.get("auto_excluded_ports", []))
    ex.add(int(relay.get("ssh_port", 22)))
    return sorted(p for p in ex if 1 <= p <= 65535)

def http_probe_headers(host, port, timeout=5):
    """轻量 HTTP GET 探测，只取少量响应头用于对比，不读取响应体。"""
    conn = None
    try:
        conn = http.client.HTTPConnection(str(host), int(port), timeout=timeout)
        conn.request("GET", "/", headers={"User-Agent": "tk-verify/1.0"})
        resp = conn.getresponse()
        keys = ("etag", "server", "location", "content-type")
        headers = {k.lower(): v for k, v in resp.getheaders() if k.lower() in keys}
        resp.read(0)
        return True, headers, f"HTTP {resp.status}"
    except Exception as e:
        return False, {}, str(e)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

def new_id(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"

# ---------------------------------------------------------------------------
# 3. SSH 主机密钥 TOFU 校验
# ---------------------------------------------------------------------------

def _fingerprint(key):
    raw = key.asbytes()
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode()

class TOFUKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected=None, auto_accept=False, confirm_cb=None):
        self.expected = expected or {}       # {host: fingerprint}
        self.auto_accept = auto_accept
        self.confirm_cb = confirm_cb
    def missing_host_key(self, client, hostname, key):
        fp = _fingerprint(key)
        wanted = self.expected.get(hostname)
        if wanted is not None:
            if wanted != fp:
                raise paramiko.SSHException(S["fp_changed"])
            self._accept(hostname, key)
            return
        if self.auto_accept:
            self._accept(hostname, key)
            return
        print(S["fingerprint"].format(fp=fp, kt=key.get_name()))
        ok = self.confirm_cb() if self.confirm_cb else (input(S["ask_trust"]).strip().lower() == "y")
        if ok:
            self._accept(hostname, key)
        else:
            raise paramiko.SSHException("用户拒绝信任该主机密钥，已中止")
    def _accept(self, hostname, key):
        # 写入当前客户端的 host_keys，使本次及后续校验生效
        hk = getattr(self, "_hk", None)
        if hk is not None:
            hk.add(hostname, key.get_name(), key)
            try:
                line = f"{hostname} {key.get_name()} {key.get_base64()}\n"
                with open(KNOWN_HOSTS_PATH, "a", encoding="utf-8") as f:
                    f.write(line)
                os.chmod(KNOWN_HOSTS_PATH, 0o600)
            except Exception:
                pass

# ---------------------------------------------------------------------------
# 4. 执行器（本机 / SSH）——统一 run(argv) 接口，杜绝 shell 注入
# ---------------------------------------------------------------------------

class LocalExecutor:
    kind = "local"
    def __init__(self):
        import subprocess
        self.subprocess = subprocess
    def run(self, argv, timeout=30):
        cmd = " ".join(shlex.quote(str(a)) for a in argv)
        try:
            p = self.subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout.strip(), p.stderr.strip()
        except Exception as e:
            return 1, "", str(e)
    def write_file(self, path, content, mode=0o600):
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(path, mode)
    def close(self):
        pass

class SSHExecutor:
    kind = "ssh"
    def __init__(self, host, port, user, secret, expected=None, auto_accept=False,
                 confirm_cb=None, key_path=None):
        self.host = host
        self.client = paramiko.SSHClient()
        if os.path.exists(KNOWN_HOSTS_PATH):
            try:
                self.client.load_host_keys(KNOWN_HOSTS_PATH)
            except Exception:
                pass
        policy = TOFUKeyPolicy(expected=expected, auto_accept=auto_accept, confirm_cb=confirm_cb)
        # 让 TOFU 写入当前客户端的 host_keys
        policy._hk = self.client._host_keys
        self.client.set_missing_host_key_policy(policy)
        # paramiko SSHClient.connect 首参为 hostname（不是 host），否则真实环境 TypeError
        kwargs = dict(hostname=host, port=int(port), username=user, timeout=20,
                      allow_agent=False, look_for_keys=False)
        pkey = None
        if key_path:
            path = os.path.expanduser(str(key_path))
            if not os.path.exists(path):
                raise RuntimeError(f"SSH 私钥不存在：{path}")
            try:
                pkey = paramiko.PKey.from_path(path)
                kwargs["pkey"] = pkey
            except Exception as e:
                raise RuntimeError(f"SSH 私钥加载失败：{path}（{e}）")
        elif secret is not None:
            kwargs["password"] = secret.value()
        elif secret is None:
            raise RuntimeError("未提供 SSH 凭据（密码或私钥）")
        try:
            self.client.connect(**kwargs)
        except Exception as e:
            # 私钥优先；若私钥认证失败且提供了密码，回退到密码认证。
            if pkey is not None and secret is not None and secret.value():
                kwargs.pop("pkey", None)
                kwargs["password"] = secret.value()
                self.client.connect(**kwargs)
            else:
                raise
    def run(self, argv, timeout=30):
        cmd = " ".join(shlex.quote(str(a)) for a in argv)
        try:
            stdin, stdout, stderr = self.client.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            rc = stdout.channel.recv_exit_status()
            return rc, out, err
        except Exception as e:
            return 1, "", str(e)
    def run_shell(self, shell_cmd, timeout=30):
        """仅用于内部生成的、已 quote 的重定向命令（备份/回滚）。"""
        try:
            stdin, stdout, stderr = self.client.exec_command(shell_cmd, timeout=timeout)
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            rc = stdout.channel.recv_exit_status()
            return rc, out, err
        except Exception as e:
            return 1, "", str(e)
    def write_file(self, path, content, mode=0o600):
        d = os.path.dirname(path)
        if d:
            rc, o, e = self.run(["mkdir", "-p", d])
            if rc != 0:
                raise RuntimeError(e)
        sftp = self.client.open_sftp()
        try:
            with sftp.file(path, "w") as f:
                f.write(content)
        finally:
            sftp.close()
        rc, o, e = self.run(["chmod", oct(mode)[2:], path])
        if rc != 0:
            raise RuntimeError(e)
    def read_file(self, path):
        sftp = self.client.open_sftp()
        try:
            with sftp.file(path, "r") as f:
                return f.read().decode("utf-8")
        finally:
            sftp.close()
    def close(self):
        try:
            self.client.close()
        except Exception:
            pass

# ---------------------------------------------------------------------------
# 5. 状态管理与审计（600 权限、不含密码、格式校验）
# ---------------------------------------------------------------------------

class StateStore:
    def __init__(self, path=STATE_PATH):
        self.path = path
    def load(self):
        if not os.path.exists(self.path):
            return {"version": VERSION, "role": None, "controller": {}, "servers": [], "rules": []}
        with open(self.path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k in ("servers", "rules"):
            if not isinstance(data.get(k), list):
                raise ValueError(S["state_bad"])
        return data
    def save(self, data):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
    def get_server(self, data, sid):
        return next((s for s in data["servers"] if s["id"] == sid), None)
    def gen_server_id(self, data, role):
        n = sum(1 for s in data["servers"] if s["role"] == role) + 1
        return f"srv-{role}-{n}"

class AuditLog:
    def __init__(self, path=AUDIT_PATH):
        self.path = path
    def log(self, action, target="", result="成功", detail=""):
        line = json.dumps({
            "time": datetime.datetime.now().isoformat(timespec="seconds"),
            "action": action, "target": target, "result": result, "detail": detail,
        }, ensure_ascii=False)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        os.chmod(self.path, 0o600)

# ---------------------------------------------------------------------------
# 6. iptables 规则生成与操作
# ---------------------------------------------------------------------------

class IptablesOps:
    def __init__(self, audit=None):
        self.audit = audit or AuditLog()

    def ensure_ip_forward(self, ex):
        rc, out, err = ex.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        return rc == 0

    def backup(self, ex, backup_path):
        rc, out, err = ex.run_shell("iptables-save > " + shlex.quote(backup_path))
        if rc != 0:
            raise RuntimeError(f"备份失败：{err}")
        ex.run_shell("chmod 600 " + shlex.quote(backup_path))
        return backup_path

    def rule_specs(self, relay, app, rule):
        """返回该规则需要下发的 iptables 命令（argv 列表）。"""
        app_ip = app["ip"]
        tag = TAG_PREFIX + rule["id"]
        specs = []
        mode = rule.get("mode", "transparent")
        pm = rule.get("port_map", {}) or {}
        if mode == "mapped" and pm:
            for sport, dport in pm.items():
                specs.append(["iptables", "-t", "nat", "-A", "PREROUTING",
                              "-p", "tcp", "-m", "tcp", "--dport", str(sport),
                              "-m", "comment", "--comment", tag,
                              "-j", "DNAT", "--to-destination", f"{app_ip}:{dport}"])
            specs.append(["iptables", "-t", "nat", "-A", "POSTROUTING",
                          "-d", app_ip, "-m", "comment", "--comment", tag,
                          "-j", "MASQUERADE"])
        else:
            # 使用合并排除集：手动 + 自动检测的转发端已用端口 + SSH 强制排除
            excludes = effective_excludes(relay)
            ssh_port = relay.get("ssh_port", 22)
            expr, ranges = build_ports_expr(excludes, ssh_port)
            if expr is not None:
                for proto in ("tcp", "udp"):
                    specs.append(["iptables", "-t", "nat", "-A", "PREROUTING",
                                  "-p", proto, "-m", "multiport", "--dports", expr,
                                  "-m", "comment", "--comment", tag,
                                  "-j", "DNAT", "--to-destination", app_ip])
            else:
                # 降级方案：排除端口 RETURN 前置 + 一条通用 DNAT
                for p in sorted(set(int(x) for x in excludes) | {int(ssh_port)}):
                    for proto in ("tcp", "udp"):
                        specs.append(["iptables", "-t", "nat", "-I", "PREROUTING", "2",
                                      "-p", proto, "-m", "tcp" if proto == "tcp" else "udp",
                                      "--dport", str(p), "-m", "comment",
                                      "--comment", tag + ":excl", "-j", "RETURN"])
                for proto in ("tcp", "udp"):
                    specs.append(["iptables", "-t", "nat", "-A", "PREROUTING",
                                  "-p", proto, "-m", "comment", "--comment", tag,
                                  "-j", "DNAT", "--to-destination", app_ip])
            specs.append(["iptables", "-t", "nat", "-A", "POSTROUTING",
                          "-d", app_ip, "-m", "comment", "--comment", tag,
                          "-j", "MASQUERADE"])
        # FORWARD：仅放行到目标应用端的相关流量（按标记）
        for proto in ("tcp", "udp"):
            specs.append(["iptables", "-A", "FORWARD", "-d", app_ip, "-p", proto,
                          "-m", "comment", "--comment", tag, "-j", "ACCEPT"])
        specs.append(["iptables", "-A", "FORWARD", "-m", "conntrack",
                      "--ctstate", "RELATED,ESTABLISHED", "-m", "comment",
                      "--comment", tag, "-j", "ACCEPT"])
        return specs

    def delete_by_tag(self, ex, tag):
        """按 comment 标记精确删除所有规则（跨表），幂等。"""
        rc, out, err = ex.run(["iptables-save"])
        if rc != 0:
            return False, err
        table = None
        dels = []
        for line in out.splitlines():
            if line.startswith("*"):
                table = line[1:].strip()
            elif line.startswith("-A "):
                parts = line.split()
                # 解析 comment 值（iptables-save 输出带引号），按 tag 精确归属：
                # 匹配 tag 本身及其子标记（如 tag:excl、tag:appAllow），
                # 但不误删 tag2 这种前缀相同的其他规则。
                raw_comment = None
                for j in range(len(parts) - 1):
                    if parts[j] == "--comment":
                        raw_comment = parts[j + 1]
                        break
                if raw_comment is None:
                    continue
                comment = raw_comment[1:-1] if (len(raw_comment) >= 2 and
                          raw_comment[0] == '"' and raw_comment[-1] == '"') else raw_comment
                if not (comment == tag or comment.startswith(tag + ":")):
                    continue
                # parts[0]=-A parts[1]=chain parts[2:]=规则体
                # iptables-save 的 --comment "值" 带引号；作为 argv 传入需去掉引号，
                # 否则 iptables 匹配到的是带引号的字面量，删除报 "Bad rule"。
                body = []
                i = 2
                while i < len(parts):
                    tok = parts[i]
                    if tok == "--comment" and i + 1 < len(parts):
                        val = parts[i + 1]
                        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
                            val = val[1:-1]
                        body.extend(["--comment", val])
                        i += 2
                        continue
                    body.append(tok)
                    i += 1
                cmd = ["iptables", "-t", table, "-D", parts[1]] + body
                dels.append(cmd)
        ok = True
        msgs = []
        for cmd in dels:
            r, o, e = ex.run(cmd)
            if r != 0:
                ok = False
                msgs.append(e)
        return ok, "; ".join(msgs)

    def push_rule(self, ex, relay, app, rule):
        tag = TAG_PREFIX + rule["id"]
        # 下发前刷新转发端已用端口（自动排除，保护原有业务）。
        # 检测失败时中止：宁可不转发，也不能劫持可能承载业务的端口。
        if relay.get("auto_exclude_enabled", True):
            used, source = detect_used_ports(ex)
            if not source:
                return False, S["auto_exclude_detect_fail"]
            relay["auto_excluded_ports"] = sorted(used)
            relay["auto_exclude_source"] = source
        self.delete_by_tag(ex, tag)          # 幂等：先删旧
        specs = self.rule_specs(relay, app, rule)
        for spec in specs:
            rc, out, err = ex.run(spec)
            if rc != 0:
                return False, err
        return True, ""

    def remove_rule(self, ex, rule):
        return self.delete_by_tag(ex, TAG_PREFIX + rule["id"])

    def app_allow_tag(self, rule):
        return TAG_PREFIX + rule["id"] + ":appAllow"

    def push_app_allow(self, ex, relay_ip, rule):
        """应用端放行来自转发端的流量（MASQUERADE 后源 IP 为转发端）。幂等。"""
        tag = self.app_allow_tag(rule)
        self.delete_by_tag(ex, tag)
        rc, out, err = ex.run(["iptables", "-I", "INPUT", "1", "-s", relay_ip,
                               "-m", "comment", "--comment", tag, "-j", "ACCEPT"])
        if rc != 0:
            return False, err
        return True, ""

    def remove_app_allow(self, ex, rule):
        return self.delete_by_tag(ex, self.app_allow_tag(rule))

    def has_rule(self, ex, rule):
        rc, out, err = ex.run(["iptables-save"])
        return rc == 0 and (TAG_PREFIX + rule["id"]) in out

    # ---- V2.0 出站：转发端 B 侧 SNAT + FORWARD ----
    def egress_tag(self, cfg):
        """出站规则标记：TAKEOVER:<cfg_id>:egress。"""
        return TAG_PREFIX + str(cfg.get("id", "egress")) + ":egress"

    def egress_specs(self, cfg, app, relay):
        """生成转发端出站 SNAT/FORWARD 命令（argv）。

        把来自应用端 IP 的流量 SNAT 成转发端公网 IP，使外部看到源 IP 为转发端。
        scope=all：对所有目标生效；scope=targets：仅对指定目标网段生效。
        管理口流量由应用端侧策略路由排除（不进入本转发链路）。
        """
        tag = self.egress_tag(cfg)
        app_ip = app["ip"]
        relay_ip = relay["ip"]
        specs = []
        targets = cfg.get("targets", []) or []
        mode = cfg.get("mode", "all")
        # 目标匹配片段：all 不加 -d；指定目标时逐目标生成 SNAT 规则。
        dst_groups = [[]] if mode == "all" or not targets else [[t] for t in targets]
        for dsts in dst_groups:
            dsrv = []
            for t in dsts:
                dsrv += ["-d", t]
            specs.append([
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-s", app_ip] + dsrv + [
                "-m", "comment", "--comment", tag,
                "-j", "SNAT", "--to-source", relay_ip,
            ])
        # FORWARD：放行来自应用端的出站流量（新连接）+ 回程 established
        fwd_dst = [] if mode == "all" or not targets else ["-d", targets[0]]
        specs.append([
            "iptables", "-A", "FORWARD", "-s", app_ip] + fwd_dst + [
            "-m", "conntrack", "--ctstate", "NEW,RELATED,ESTABLISHED",
            "-m", "comment", "--comment", tag, "-j", "ACCEPT",
        ])
        specs.append([
            "iptables", "-A", "FORWARD", "-d", app_ip,
            "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED",
            "-m", "comment", "--comment", tag, "-j", "ACCEPT",
        ])
        return specs

    def push_egress(self, ex, cfg, app, relay):
        """下发转发端出站规则（幂等：先按标记删旧）。"""
        tag = self.egress_tag(cfg)
        self.delete_by_tag(ex, tag)
        self.ensure_ip_forward(ex)
        for spec in self.egress_specs(cfg, app, relay):
            rc, out, err = ex.run(spec)
            if rc != 0:
                return False, err
        return True, ""

    def remove_egress(self, ex, cfg):
        """撤销转发端出站规则。"""
        return self.delete_by_tag(ex, self.egress_tag(cfg))

    def has_egress(self, ex, cfg):
        rc, out, err = ex.run(["iptables-save"])
        return rc == 0 and self.egress_tag(cfg) in out

    def rollback(self, ex, backup_path):
        rc, out, err = ex.run_shell("iptables-restore < " + shlex.quote(backup_path))
        return rc == 0, err

    def persist(self, ex, rules_text, path="/root/ip-takeover-tool/restore.sh"):
        """无 iptables-persistent 时，写入恢复脚本 + @reboot cron 实现持久化。"""
        d = os.path.dirname(path)
        ex.run_shell("mkdir -p " + shlex.quote(d))
        body = ("#!/bin/sh\n# 由 IP 接管配置工具生成：开机恢复接管规则\n"
                "iptables-restore < /root/ip-takeover-tool/iptables.rules\n")
        ex.write_file(path, body, 0o700)
        ex.write_file(d + "/iptables.rules", rules_text, 0o600)
        cmd = ("grep -Fq 'ip-takeover-tool/restore.sh' /etc/crontab "
               "|| echo '@reboot root /root/ip-takeover-tool/restore.sh' >> /etc/crontab")
        ex.run_shell(cmd)

# ---------------------------------------------------------------------------
# 6b. V2.0 出站：应用端 A 侧策略路由管理
#     用独立路由表 + ip rule，把 A 的指定出站流量引向转发端 B，由 B 做 SNAT。
#     不修改主表默认路由，disable 精确撤销，可完整恢复原出口。
# ---------------------------------------------------------------------------

class EgressRouter:
    """应用端出站策略路由。所有命令 argv 化，无 shell 注入；按专用 pref 段与路由表幂等增删。"""

    def __init__(self, snapshot=EGRESS_SNAPSHOT):
        self.snapshot = snapshot

    def _table(self, cfg):
        return int(cfg.get("table") or EGRESS_TABLE_ID)

    def _pref(self, cfg):
        return int(cfg.get("pref") or EGRESS_PREF_BASE)

    def backup(self, ex, path=None):
        """备份 A 侧当前 ip rule 与全部路由表，供人工回滚参考。"""
        path = path or self.snapshot
        rc, out, err = ex.run(["ip", "rule", "show"])
        if rc != 0:
            return False, err
        rc2, out2, err2 = ex.run(["ip", "route", "show", "table", "all"])
        if rc2 != 0:
            return False, err2
        body = ("# IP 接管 V2.0 出站变更前快照\n"
                "# 生成时间见审计日志；本文件仅用于人工参考，disable 会精确撤销我方规则\n"
                "## ip rule show\n" + out + "\n\n## ip route show table all\n" + out2 + "\n")
        try:
            ex.write_file(path, body, 0o600)
        except Exception as e:
            return False, str(e)
        return True, path

    def detect_l2(self, ex, via_ip):
        """探测 A 到 via 是否二层可达（同网段/隧道）。返回 (ok, on_link, detail)。"""
        rc, out, err = ex.run(["ip", "route", "get", str(via_ip)])
        if rc != 0:
            return False, False, err or out
        on_link = not re.search(r"\bvia\s+\S+", out)
        return True, on_link, out.strip()

    def _clear_all(self, ex, cfg):
        """清除我方所有出站规则（专用 pref 段 + 独立路由表），幂等。"""
        table = self._table(cfg)
        pref = self._pref(cfg)
        lo, hi = pref - 20, pref + 200
        rc, out, err = ex.run(["ip", "rule", "show"])
        if rc == 0:
            for line in out.splitlines():
                m = re.match(r"\s*(\d+):", line)
                if not m:
                    continue
                p = int(m.group(1))
                own = (lo <= p <= hi)
                if own or re.search(r"\blookup\s+%d\b" % table, line):
                    ex.run(["ip", "rule", "del", "pref", str(p)])
        ex.run(["ip", "route", "flush", "table", str(table)])
        return True, ""

    def push(self, ex, cfg, app, relay):
        """下发 A 侧策略路由（幂等）。via 缺省用转发端 IP。"""
        table = self._table(cfg)
        pref = self._pref(cfg)
        via = (cfg.get("via") or "").strip() or relay["ip"]
        app_ip = app["ip"]
        self._clear_all(ex, cfg)
        # 独立路由表默认路由 → 转发端（B 收到后做 SNAT）
        # src_ip 可选：隧道模式下让 A 发出的包保持该源 IP（通常为 A 公网 IP），
        # 从而命中 B 侧现有 SNAT 规则 -s app_ip，无需改动转发端匹配逻辑。
        route_cmd = ["ip", "route", "add", "default", "via", via]
        src_ip = (cfg.get("src_ip") or "").strip()
        if src_ip:
            route_cmd += ["src", src_ip]
        route_cmd += ["table", str(table)]
        rc, out, err = ex.run(route_cmd)
        if rc != 0:
            return False, err
        # 管理网段排除：更高优先级走主表，避免管理流量绕行转发端
        for net in cfg.get("mgmt_nets", []) or []:
            c = valid_cidr(net)
            if c:
                ex.run(["ip", "rule", "add", "from", f"{app_ip}/32", "to", c,
                        "lookup", "main", "pref", str(pref - 10)])
        # 主出站规则：all=所有出站经 B；targets=仅指定目标经 B
        mode = cfg.get("mode", "all")
        targets = cfg.get("targets", []) or []
        if mode == "all" or not targets:
            rc, out, err = ex.run(["ip", "rule", "add", "from", f"{app_ip}/32",
                                   "lookup", str(table), "pref", str(pref)])
            if rc != 0:
                return False, err
        else:
            for i, t in enumerate(targets):
                c = valid_cidr(t)
                if not c:
                    return False, S["egress_bad_target"]
                rc, out, err = ex.run(["ip", "rule", "add", "from", f"{app_ip}/32",
                                       "to", c, "lookup", str(table), "pref", str(pref + i)])
                if rc != 0:
                    return False, err
        return True, ""

    def remove(self, ex, cfg):
        """撤销 A 侧策略路由，恢复原出口。"""
        return self._clear_all(ex, cfg)

    def has(self, ex, cfg):
        table = self._table(cfg)
        rc, out, err = ex.run(["ip", "rule", "show"])
        has_rule = rc == 0 and re.search(r"\blookup\s+%d\b" % table, out) is not None
        rc2, out2, err2 = ex.run(["ip", "route", "show", "table", str(table)])
        has_route = rc2 == 0 and "default via" in out2
        return has_rule and has_route

    def status(self, ex, cfg):
        """返回 A 侧出站路由现状文本。"""
        lines = []
        table = self._table(cfg)
        rc, out, err = ex.run(["ip", "route", "show", "table", str(table)])
        lines.append(f"应用端策略路由表 {table}：" + (out.strip() if rc == 0 and out.strip() else "无"))
        rc2, out2, err2 = ex.run(["ip", "rule", "show"])
        rules = [l.strip() for l in out2.splitlines() if re.search(r"\blookup\s+%d\b" % table, l)] if rc2 == 0 else []
        lines.append("相关 ip rule：" + ("; ".join(rules) if rules else "无"))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 7. 核心业务：服务器 / 规则 / 排除端口 管理
# ---------------------------------------------------------------------------

class Takeover:
    def __init__(self, store=None, audit=None, expected=None, auto_accept=False, confirm_cb=None):
        self.store = store or StateStore()
        self.audit = audit or AuditLog()
        self.ops = IptablesOps(self.audit)
        self.router = EgressRouter()
        self.expected = expected or {}
        self.auto_accept = auto_accept
        self.confirm_cb = confirm_cb
        self._executors = {}
        self.auto_sync_cb = None   # 自动广播用的凭据回调（仅缓存、不提示由上层注入）

    def executor_for(self, server, secret):
        ex = SSHExecutor(server["ip"], server.get("ssh_port", 22), server.get("user", "root"),
                         secret, expected=self.expected,
                         auto_accept=self.auto_accept, confirm_cb=self.confirm_cb,
                         key_path=server.get("key_path"))
        return ex

    def is_controller(self, data=None):
        data = data or self.store.load()
        return data.get("role") == "controller"

    def _save_state(self, data, secret_cb=None):
        """保存状态。主控端保存后立即把权威状态广播到各节点（只读镜像）。

        主控端 state.json 是唯一真相源；对端镜像由本方法维护，不参与决策。
        广播失败不影响本地操作结果，但会记录告警并返回给调用方展示。
        """
        self.store.save(data)
        if self.is_controller(data):
            try:
                sync_cb = self.auto_sync_cb or secret_cb
                ok, report = self.broadcast_state(data, sync_cb)
                if not ok:
                    print(f"\n警告：本地状态已保存，但同步到对端失败：\n{report}")
            except Exception as e:
                print(f"\n警告：本地状态已保存，但同步到对端异常：{e}")

    def _mirror_for(self, data, srv):
        """为某节点生成状态镜像：role 改为该节点角色，其余权威数据一致。"""
        m = json.loads(json.dumps(data))
        m["role"] = srv.get("role", "app")
        m["_mirror"] = {
            "source": (data.get("controller") or {}).get("host", "unknown"),
            "note": "只读镜像，由主控端自动同步，请勿手工修改",
        }
        return m

    def broadcast_state(self, data, secret_cb=None, targets=None):
        """主控端把权威 state 推送到各服务器节点。返回 (全部成功, 报告)。"""
        if not self.is_controller(data):
            return False, "本机不是主控端，无法广播状态"
        servers = data.get("servers", [])
        if targets is not None:
            servers = [s for s in servers if s["id"] in targets or s["ip"] in targets]
        if not servers:
            return True, "无其他节点需要同步"
        controller_host = (data.get("controller") or {}).get("host", "")
        lines = []
        all_ok = True
        for srv in servers:
            ip = srv["ip"]
            if ip == controller_host:
                lines.append(f"  {srv['role']} {ip}：主控端自身，保留权威状态（不写镜像）")
                continue
            try:
                secret = secret_cb(srv) if secret_cb else None
                if secret is None:
                    all_ok = False
                    lines.append(f"  {srv['role']} {ip}：未提供凭据，跳过")
                    continue
                ex = self.executor_for(srv, secret)
                try:
                    content = json.dumps(self._mirror_for(data, srv), ensure_ascii=False, indent=2)
                    ex.write_file(PEER_STATE_PATH, content, 0o600)
                    lines.append(f"  {srv['role']} {ip}：已同步")
                finally:
                    ex.close()
            except Exception as e:
                all_ok = False
                lines.append(f"  {srv['role']} {ip}：失败（{e}）")
        return all_ok, "\n".join(lines)

    def pull_state(self, secret_cb=None):
        """非主控端从主控端拉取权威 state 镜像。返回 (成功, 消息)。"""
        data = self.store.load()
        if self.is_controller(data):
            return True, "本机即主控端，无需拉取"
        host = (data.get("controller") or {}).get("host")
        ctrl_srv = next((s for s in data.get("servers", []) if s["ip"] == host), None)
        if not host or not ctrl_srv:
            return False, "状态中未记录主控端地址，无法拉取"
        try:
            secret = secret_cb(ctrl_srv) if secret_cb else None
            if secret is None:
                return False, "未提供主控端凭据，无法拉取"
            ex = self.executor_for(ctrl_srv, secret)
            try:
                raw = ex.read_file(PEER_STATE_PATH)
                remote = json.loads(raw)
            finally:
                ex.close()
            if remote.get("role") != "controller":
                return False, "主控端状态角色异常，拒绝覆盖本地镜像"
            mirror = self._mirror_for(remote, {"role": data.get("role") or "app"})
            self.store.save(mirror)
            return True, f"已从主控端 {host} 拉取最新状态"
        except Exception as e:
            return False, f"拉取失败：{e}"

    def set_role(self, role):
        data = self.store.load()
        old_role = data.get("role")
        data["role"] = role
        # 提升为主控端时，把权威主机地址切到本机，避免仍指向旧主控端。
        if role == "controller":
            own = None
            if old_role in ("app", "relay"):
                matches = [s for s in data.get("servers", []) if s.get("role") == old_role]
                if len(matches) == 1:
                    own = matches[0]
            if own is None:
                host = (data.get("controller") or {}).get("host")
                own = next((s for s in data.get("servers", []) if s.get("ip") == host), None)
            if own:
                c = data.setdefault("controller", {})
                c["host"] = own["ip"]
                c.setdefault("ssh_port", own.get("ssh_port", 22))
                c.setdefault("user", own.get("user", "root"))
        self.store.save(data)
        self.audit.log("设置本机角色", role)
        return role

    def precheck(self, server, secret):
        ex = self.executor_for(server, secret)
        try:
            rc, out, err = ex.run(["uname", "-s"])
            ok = rc == 0
            return ok, (err or out), ex
        except Exception as e:
            return False, str(e), None

    def add_server(self, role, ip, ssh_port, user, secret, secret_cb=None, key_path=None):
        data = self.store.load()
        if not valid_ip(ip):
            return False, S["bad_ip"], None
        if not valid_port(ssh_port):
            return False, S["bad_port"], None
        if not user:
            return False, S["required"], None
        if any(s["ip"] == ip for s in data["servers"]):
            return False, "该服务器已存在", None
        srv = {
            "id": self.store.gen_server_id(data, role),
            "role": role, "ip": ip, "ssh_port": int(ssh_port), "user": user,
            "enabled": True,
        }
        if key_path:
            srv["key_path"] = os.path.expanduser(str(key_path))
        if role == "relay":
            srv["exclude_ports"] = []
            srv["backup_path"] = ""
            # 自动排除转发端已监听端口：默认开启，保护原有业务不被 DNAT 劫持
            srv["auto_exclude_enabled"] = True
            srv["auto_excluded_ports"] = []
            srv["auto_exclude_source"] = ""
        ok, msg, ex = self.precheck(srv, secret)
        if not ok:
            return False, S["conn_fail"].format(reason=msg), None
        if role == "relay":
            # 首次添加转发端：全量备份
            ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            path = f"/root/iptables.backup.TAKEOVER-{ts}"
            try:
                self.ops.backup(ex, path)
                srv["backup_path"] = path
            except Exception as e:
                return False, str(e), None
        data["servers"].append(srv)
        self._save_state(data, secret_cb)
        self.audit.log("添加服务器", f"{role}:{ip}")
        return True, f"已添加 {role} 服务器 {ip}（id={srv['id']}）", srv

    def list_servers(self):
        return self.store.load()["servers"]

    def list_rules(self):
        data = self.store.load()
        out = []
        for r in data["rules"]:
            app = self.store.get_server(data, r["app_id"])
            relay = self.store.get_server(data, r["relay_id"])
            eff = r["enabled"] and app and relay and app["enabled"] and relay["enabled"]
            item = dict(r)
            item["effective"] = bool(eff)
            out.append(item)
        return out

    def _rule_impact_text(self, app, relay, mode, port_map):
        """生成规则影响清单，供添加规则前二次确认。"""
        lines = [f"转发端 {relay['ip']}  →  应用端 {app['ip']}"]
        if mode == "mapped":
            pairs = ", ".join(f"{a}->{b}" for a, b in (port_map or {}).items())
            lines.append(f"端口映射：{pairs}")
        else:
            excludes = sorted(set(int(p) for p in relay.get("exclude_ports", [])) |
                              {int(relay.get("ssh_port", 22))})
            expr, ranges = build_ports_expr(excludes, relay.get("ssh_port", 22))
            if expr:
                lines.append(f"将转发端口：{expr}（共 {ranges} 段）")
            else:
                lines.append("排除端口超过 15 段，将使用 RETURN 前置规则转发 1:65535 中除排除端口外的所有端口")
            lines.append(f"排除端口（不转发，手动+已用）：{excludes}；SSH 端口 {relay.get('ssh_port', 22)} 强制排除")
            if relay.get("auto_exclude_enabled", True):
                auto = sorted(set(int(p) for p in relay.get("auto_excluded_ports", [])))
                src = relay.get("auto_exclude_source", "") or "下发时检测"
                lines.append(f"自动排除已开启：转发端已监听端口自动不转发（最近检测 {src}，端口 {auto or '待检测'}）")
            else:
                lines.append("警告：自动排除已关闭，转发端已监听端口可能被转发并破坏其原有业务")
            lines.append("注意：未排除的服务端口也会被转发；如只转指定端口，请改用端口映射模式。")
        return "\n".join("  " + line for line in lines)

    def _confirm_action(self, title, detail):
        print(title)
        print(detail)
        if self.confirm_cb:
            return bool(self.confirm_cb())
        return input("是否继续？[y/N]：").strip().lower() == "y"

    def add_rule(self, app_id, relay_id, mode, port_map, secret_cb):
        data = self.store.load()
        app = self.store.get_server(data, app_id)
        relay = self.store.get_server(data, relay_id)
        if not app or not relay:
            return False, S["no_server"], None
        if app["role"] != "app" or relay["role"] != "relay":
            return False, "请选择正确类型的应用端/转发端", None
        if app["ip"] == relay["ip"]:
            return False, S["same_ip"], None
        if mode == "mapped":
            if not port_map:
                return False, "端口映射不能为空", None
            for a, b in port_map.items():
                if not valid_port(a) or not valid_port(b):
                    return False, S["bad_port"], None
        detail = self._rule_impact_text(app, relay, mode, port_map)
        if not self._confirm_action("即将添加转发规则，请确认影响范围：", detail):
            return False, S["cancelled"], None
        rule = {
            "id": new_id("tk"), "app_id": app_id, "relay_id": relay_id,
            "mode": mode, "port_map": port_map, "enabled": True,
            "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        # 生成规则前强校验 SSH 端口在排除列表
        ssh_port = relay.get("ssh_port", 22)
        if ssh_port not in relay.get("exclude_ports", []):
            relay.setdefault("exclude_ports", []).append(ssh_port)
        # 转发端开启 IP 转发
        secret = secret_cb(relay)
        ex = self.executor_for(relay, secret)
        try:
            self.ops.ensure_ip_forward(ex)
        finally:
            ex.close()
        # 统一下发：转发端 DNAT + 应用端放行
        ok, err = self.apply_rule(rule, data, secret_cb, enable=True)
        if not ok:
            return False, err, None
        data["rules"].append(rule)
        self._save_state(data, secret_cb)
        self.audit.log("添加转发规则", rule["id"])
        return True, f"已添加规则 {rule['id']} 并下发", rule

    def apply_rule(self, rule, data, secret_cb, enable=True):
        app = self.store.get_server(data, rule["app_id"])
        relay = self.store.get_server(data, rule["relay_id"])
        if not app or not relay:
            return False, S["no_server"]
        # 1) 转发端：下发 / 撤销 DNAT 规则
        secret = secret_cb(relay)
        ex = self.executor_for(relay, secret)
        try:
            if enable:
                ok, err = self.ops.push_rule(ex, relay, app, rule)
            else:
                ok, err = self.ops.remove_rule(ex, rule)
            if not ok:
                return False, err
        finally:
            ex.close()
        # 2) 应用端：放行 / 撤销来自转发端的流量（设计 Must）
        try:
            app_secret = secret_cb(app)
            exa = self.executor_for(app, app_secret)
            try:
                if enable:
                    ok, err = self.ops.push_app_allow(exa, relay["ip"], rule)
                else:
                    ok, err = self.ops.remove_app_allow(exa, rule)
                if not ok:
                    return False, f"应用端放行失败：{err}"
            finally:
                exa.close()
        except Exception as e:
            return False, f"应用端放行失败：{e}"
        return True, ""

    def rule_enable(self, rid, secret_cb):
        data = self.store.load()
        rule = next((r for r in data["rules"] if r["id"] == rid), None)
        if not rule:
            return False, S["no_rule"]
        ok, err = self.apply_rule(rule, data, secret_cb, enable=True)
        if not ok:
            return False, err
        rule["enabled"] = True
        self._save_state(data, secret_cb)
        self.audit.log("启用规则", rid)
        return True, f"规则 {rid} 已启用"

    def rule_disable(self, rid, secret_cb):
        data = self.store.load()
        rule = next((r for r in data["rules"] if r["id"] == rid), None)
        if not rule:
            return False, S["no_rule"]
        ok, err = self.apply_rule(rule, data, secret_cb, enable=False)
        if not ok:
            return False, err
        rule["enabled"] = False
        self._save_state(data, secret_cb)
        self.audit.log("关闭规则", rid)
        return True, f"规则 {rid} 已关闭"

    def rule_remove(self, rid, secret_cb):
        data = self.store.load()
        rule = next((r for r in data["rules"] if r["id"] == rid), None)
        if not rule:
            return False, S["no_rule"]
        self.rule_disable(rid, secret_cb)
        data = self.store.load()
        data["rules"] = [r for r in data["rules"] if r["id"] != rid]
        self._save_state(data, secret_cb)
        self.audit.log("删除规则", rid)
        return True, f"规则 {rid} 已删除"

    def _secret_cb_from_map(self, passwords):
        def cb(server):
            v = passwords.get(server["id"]) or passwords.get(server["ip"])
            if v is None:
                raise RuntimeError(f"缺少 {server['ip']} 的凭据")
            return Secret(v)
        return cb

    def server_disable(self, sid, secret_cb):
        data = self.store.load()
        srv = self.store.get_server(data, sid)
        if not srv:
            return False, S["no_server"]
        rel = [r for r in data["rules"] if r["app_id"] == sid or r["relay_id"] == sid]
        for r in rel:
            if r["enabled"]:
                ok, err = self.apply_rule(r, data, secret_cb, enable=False)
                if not ok:
                    return False, err
                r["enabled"] = False
        srv["enabled"] = False
        self._save_state(data, secret_cb)
        self.audit.log("关闭服务器", f"{srv['role']}:{srv['ip']}", detail=f"影响{len(rel)}条规则")
        return True, f"已关闭 {srv['ip']}，影响 {len(rel)} 条规则"

    def server_enable(self, sid, secret_cb):
        data = self.store.load()
        srv = self.store.get_server(data, sid)
        if not srv:
            return False, S["no_server"]
        rel = [r for r in data["rules"] if r["app_id"] == sid or r["relay_id"] == sid]
        for r in rel:
            other = self.store.get_server(data, r["relay_id"] if r["app_id"] == sid else r["app_id"])
            if r["enabled"] and other and other["enabled"]:
                ok, err = self.apply_rule(r, data, secret_cb, enable=True)
                if not ok:
                    return False, err
        srv["enabled"] = True
        self._save_state(data, secret_cb)
        self.audit.log("开启服务器", f"{srv['role']}:{srv['ip']}")
        return True, f"已开启 {srv['ip']}"

    def server_remove(self, sid, secret_cb):
        """删除双向联动：撤销规则 + 从两端同步清理关联，状态一致。"""
        data = self.store.load()
        srv = self.store.get_server(data, sid)
        if not srv:
            return False, S["no_server"]
        rel = [r for r in data["rules"] if r["app_id"] == sid or r["relay_id"] == sid]
        # 撤销所有相关规则
        for r in rel:
            if r["enabled"]:
                self.apply_rule(r, data, secret_cb, enable=False)
        # 清理本端：移除服务器及关联规则
        data["servers"] = [s for s in data["servers"] if s["id"] != sid]
        data["rules"] = [r for r in data["rules"] if r["app_id"] != sid and r["relay_id"] != sid]
        # 对端清理：应用端侧无落盘配置，联动体现在状态同步；转发端侧规则已撤销，IP 流量回到本地
        self._save_state(data, secret_cb)
        self.audit.log("删除服务器", f"{srv['role']}:{srv['ip']}", detail=f"双向联动清理{len(rel)}条规则")
        return True, f"已删除 {srv['ip']}，双向联动清理 {len(rel)} 条规则"

    def remove_server_anywhere(self, sid, secret_cb):
        """任一节点都可删除对端：镜像端把删除请求提交给权威主控端执行。

        主控端仍保持唯一状态写入权，避免 A/B 各自直接改 state 造成分叉。
        """
        data = self.store.load()
        srv = self.store.get_server(data, sid)
        if not srv:
            return False, S["no_server"]
        if self.is_controller(data):
            return self.server_remove(sid, secret_cb)

        host = (data.get("controller") or {}).get("host", "")
        ctrl = next((s for s in data.get("servers", []) if s.get("ip") == host), None)
        if not ctrl:
            return False, f"状态中未找到主控端 {host} 的服务器实体，无法提交删除"
        secret = secret_cb(ctrl) if secret_cb else None
        if secret is None:
            return False, f"缺少主控端 {host} 的凭据，无法提交删除"
        ex = self.executor_for(ctrl, secret)
        try:
            remote_script = os.path.join(PEER_STATE_DIR, "takeover.py")
            rc, out, err = ex.run(["python3", remote_script, "server", "remove", sid,
                                   "--yes", "--remote"], timeout=180)
            if rc != 0:
                return False, f"主控端执行失败（rc={rc}）：{err or out}"
            marker = f"SERVER_REMOVED:{sid}"
            if marker not in out:
                return False, f"主控端未确认删除：{out or err}"
            ok2, msg2 = self.pull_state(secret_cb)
            if not ok2:
                return True, f"已通过主控端删除 {srv['ip']}，但本地镜像刷新失败：{msg2}"
            return True, f"已通过主控端删除 {srv['ip']}，双向联动完成，本地镜像已刷新"
        finally:
            ex.close()

    def exclude_list(self, relay_id):
        data = self.store.load()
        r = self.store.get_server(data, relay_id)
        if not r or r["role"] != "relay":
            return False, S["need_relay"], None
        ex = [int(p) for p in r.get("exclude_ports", [])]
        auto_ex = [int(p) for p in r.get("auto_excluded_ports", [])]
        return True, "", {
            "ssh_port": r.get("ssh_port", 22),
            "exclude_ports": ex,
            "auto_exclude_enabled": r.get("auto_exclude_enabled", True),
            "auto_excluded_ports": auto_ex,
            "auto_exclude_source": r.get("auto_exclude_source", ""),
            "effective": effective_excludes(r),
        }

    def _recompute_relay(self, relay, data, secret_cb):
        rules = [r for r in data["rules"] if r["relay_id"] == relay["id"]]
        secret = secret_cb(relay)
        ex = self.executor_for(relay, secret)
        try:
            self.ops.ensure_ip_forward(ex)
            for r in rules:
                if r["enabled"]:
                    app = self.store.get_server(data, r["app_id"])
                    ok, err = self.ops.push_rule(ex, relay, app, r)
                    if not ok:
                        return False, err
        finally:
            ex.close()
        return True, ""

    def exclude_add(self, relay_id, ports, secret_cb):
        data = self.store.load()
        r = self.store.get_server(data, relay_id)
        if not r or r["role"] != "relay":
            return False, S["need_relay"]
        cur = set(int(p) for p in r.get("exclude_ports", []))
        cur.update(int(p) for p in ports)
        r["exclude_ports"] = sorted(cur)
        ok, err = self._recompute_relay(r, data, secret_cb)
        if not ok:
            return False, err
        self._save_state(data, secret_cb)
        self.audit.log("添加排除端口", relay_id, detail=str(ports))
        return True, S["exclude_ok"]

    def exclude_remove(self, relay_id, ports, secret_cb):
        data = self.store.load()
        r = self.store.get_server(data, relay_id)
        if not r or r["role"] != "relay":
            return False, S["need_relay"]
        ssh_port = r.get("ssh_port", 22)
        if ssh_port in ports:
            return False, S["ssh_excluded"]
        cur = set(int(p) for p in r.get("exclude_ports", []))
        for p in ports:
            cur.discard(int(p))
        r["exclude_ports"] = sorted(cur)
        ok, err = self._recompute_relay(r, data, secret_cb)
        if not ok:
            return False, err
        self._save_state(data, secret_cb)
        self.audit.log("移除排除端口", relay_id, detail=str(ports))
        return True, S["exclude_ok"]

    def _submit_to_controller(self, argv, marker, secret_cb):
        """镜像端把本机管理请求提交给主控端执行，再拉回最新状态。"""
        data = self.store.load()
        host = (data.get("controller") or {}).get("host", "")
        ctrl = next((s for s in data.get("servers", []) if s.get("ip") == host), None)
        if not ctrl:
            return False, f"状态中未找到主控端 {host} 的服务器实体，无法提交"
        secret = secret_cb(ctrl) if secret_cb else None
        if secret is None:
            return False, f"缺少主控端 {host} 的凭据，无法提交"
        ex = self.executor_for(ctrl, secret)
        try:
            remote_argv = ["python3", os.path.join(PEER_STATE_DIR, "takeover.py")] + argv + ["--yes", "--remote"]
            rc, out, err = ex.run(remote_argv, timeout=180)
            if rc != 0:
                return False, f"主控端执行失败（rc={rc}）：{err or out}"
            if marker not in out:
                return False, f"主控端未确认执行：{out or err}"
            ok2, msg2 = self.pull_state(secret_cb)
            if not ok2:
                return True, f"已提交主控端执行，但本地镜像刷新失败：{msg2}"
            return True, "已提交主控端执行，本地镜像已刷新"
        finally:
            ex.close()

    def exclude_add_anywhere(self, relay_id, ports, secret_cb):
        data = self.store.load()
        srv = self.store.get_server(data, relay_id)
        if not srv or srv.get("role") != "relay":
            return False, S["need_relay"]
        if self.is_controller(data):
            return self.exclude_add(relay_id, ports, secret_cb)
        return self._submit_to_controller(
            ["exclude", "add", relay_id] + [str(p) for p in ports],
            f"EXCLUDE_ADDED:{relay_id}", secret_cb)

    def exclude_remove_anywhere(self, relay_id, ports, secret_cb):
        data = self.store.load()
        srv = self.store.get_server(data, relay_id)
        if not srv or srv.get("role") != "relay":
            return False, S["need_relay"]
        if self.is_controller(data):
            return self.exclude_remove(relay_id, ports, secret_cb)
        return self._submit_to_controller(
            ["exclude", "remove", relay_id] + [str(p) for p in ports],
            f"EXCLUDE_REMOVED:{relay_id}", secret_cb)

    # ---- 自动排除转发端已用端口（保护原有业务） ----
    def auto_exclude_scan(self, relay_id, secret_cb):
        """立即检测转发端监听端口，写入状态并重下发所有启用规则。"""
        data = self.store.load()
        r = self.store.get_server(data, relay_id)
        if not r or r["role"] != "relay":
            return False, S["need_relay"]
        secret = secret_cb(r)
        ex = self.executor_for(r, secret)
        try:
            used, source = detect_used_ports(ex)
            if not source:
                return False, S["auto_exclude_detect_fail"]
        finally:
            ex.close()
        r["auto_excluded_ports"] = sorted(used)
        r["auto_exclude_source"] = source
        ok, err = self._recompute_relay(r, data, secret_cb)
        if not ok:
            return False, err
        self._save_state(data, secret_cb)
        self.audit.log("扫描自动排除端口", relay_id,
                       detail=f"source={source}, ports={sorted(used)}")
        return True, (f"检测来源={source}，已用端口={sorted(used)}；"
                      f"当前生效排除集={effective_excludes(r)}")

    def auto_exclude_set(self, relay_id, enabled, secret_cb):
        """开启/关闭自动排除；关闭时清空已检测端口并重下发。"""
        data = self.store.load()
        r = self.store.get_server(data, relay_id)
        if not r or r["role"] != "relay":
            return False, S["need_relay"]
        r["auto_exclude_enabled"] = bool(enabled)
        if not enabled:
            r["auto_excluded_ports"] = []
            r["auto_exclude_source"] = ""
        ok, err = self._recompute_relay(r, data, secret_cb)
        if not ok:
            return False, err
        self._save_state(data, secret_cb)
        self.audit.log("设置自动排除", relay_id, detail=f"enabled={enabled}")
        return True, S["auto_exclude_on"] if enabled else S["auto_exclude_off"]

    def auto_exclude_scan_anywhere(self, relay_id, secret_cb):
        data = self.store.load()
        srv = self.store.get_server(data, relay_id)
        if not srv or srv.get("role") != "relay":
            return False, S["need_relay"]
        if self.is_controller(data):
            return self.auto_exclude_scan(relay_id, secret_cb)
        return self._submit_to_controller(
            ["exclude", "auto", relay_id, "scan"], "AUTO_EXCLUDE_SCANNED", secret_cb)

    def auto_exclude_set_anywhere(self, relay_id, enabled, secret_cb):
        data = self.store.load()
        srv = self.store.get_server(data, relay_id)
        if not srv or srv.get("role") != "relay":
            return False, S["need_relay"]
        if self.is_controller(data):
            return self.auto_exclude_set(relay_id, enabled, secret_cb)
        flag = "on" if enabled else "off"
        return self._submit_to_controller(
            ["exclude", "auto", relay_id, flag], f"AUTO_EXCLUDE_SET:{relay_id}", secret_cb)

    def rollback(self, relay_id, secret_cb):
        data = self.store.load()
        r = self.store.get_server(data, relay_id)
        if not r or r["role"] != "relay":
            return False, S["need_relay"]
        if not r.get("backup_path"):
            return False, "未找到首次备份，无法回滚"
        secret = secret_cb(r)
        ex = self.executor_for(r, secret)
        try:
            ok, err = self.ops.rollback(ex, r["backup_path"])
        finally:
            ex.close()
        if not ok:
            return False, err
        for rule in data["rules"]:
            if rule["relay_id"] == relay_id:
                rule["enabled"] = False
        self._save_state(data, secret_cb)
        self.audit.log("回滚", f"relay:{r['ip']}")
        return True, S["restored"]

    # ---- V2.0 出站身份编排 ----
    @staticmethod
    def _egress_scope_text(cfg):
        if cfg.get("mode") == "targets" and cfg.get("targets"):
            return "仅指定目标：" + ", ".join(cfg["targets"])
        return "全部出站（all）"

    def egress_config(self, app_id, relay_id, mode, targets, secret_cb,
                      via="", mgmt_nets=None, src_ip=""):
        """配置出站（写权威 state，不下发）。仅主控端可写。
        src_ip：隧道模式下 A 出站包保持的源 IP（通常为 A 公网 IP），用于命中 B 侧 SNAT。
        """
        data = self.store.load()
        if not self.is_controller(data):
            return False, S["need_controller"]
        app = self.store.get_server(data, app_id)
        relay = self.store.get_server(data, relay_id)
        if not app or app.get("role") != "app":
            return False, S["need_app"]
        if not relay or relay.get("role") != "relay":
            return False, S["need_relay"]
        if not app.get("enabled") or not relay.get("enabled"):
            return False, "应用端或转发端处于关闭状态，请先启用"
        if mode not in ("all", "targets"):
            return False, "范围模式必须为 all 或 targets"
        norm = []
        for t in (targets or []):
            c = valid_cidr(t)
            if not c:
                return False, S["egress_bad_target"]
            if c not in norm:
                norm.append(c)
        if mode == "targets" and not norm:
            return False, S["egress_scope_empty"]
        via = (via or "").strip()
        if via and not valid_ip(via):
            return False, S["bad_ip"]
        src_ip = (src_ip or "").strip()
        if src_ip and not valid_ip(src_ip):
            return False, S["bad_ip"]
        old = data.get("egress") or {}
        cfg = {
            "enabled": bool(old.get("enabled", False)),
            "app_id": app_id, "relay_id": relay_id,
            "mode": mode, "targets": norm, "via": via, "src_ip": src_ip,
            "mgmt_nets": [x for x in (mgmt_nets or []) if valid_cidr(x)],
            "table": EGRESS_TABLE_ID, "pref": EGRESS_PREF_BASE,
        }
        data["egress"] = cfg
        self._save_state(data, secret_cb)
        self.audit.log("配置出站", f"{app_id}->{relay_id}", detail=mode)
        return True, f"出站配置已保存（范围：{self._egress_scope_text(cfg)}），请执行 egress enable 下发"

    def egress_enable(self, secret_cb, assume_yes=False):
        """下发出站：转发端 SNAT + 应用端策略路由。含二层可达检测与二次确认。"""
        data = self.store.load()
        if not self.is_controller(data):
            return False, S["need_controller"]
        cfg = data.get("egress")
        if not cfg or not cfg.get("app_id"):
            return False, S["egress_not_config"]
        app = self.store.get_server(data, cfg["app_id"])
        relay = self.store.get_server(data, cfg["relay_id"])
        if not app or not relay:
            return False, S["no_server"]
        scope = self._egress_scope_text(cfg)
        via = (cfg.get("via") or "").strip() or relay["ip"]
        detail = S["egress_confirm"].format(
            app=app["ip"], relay=relay["ip"], scope=scope,
            table=cfg.get("table", EGRESS_TABLE_ID))
        if not assume_yes and not self._confirm_action("出站接管风险确认：", detail):
            return False, S["cancelled"]

        # 前置：A 侧探测到 via 的二层可达性（仅提示，不强制，兼容已建隧道）
        l2_warn = ""
        exa = self.executor_for(app, secret_cb(app))
        try:
            ok2, on_link, detail2 = self.router.detect_l2(exa, via)
            if ok2 and not on_link:
                l2_warn = "\n" + S["egress_l2_warn"].format(detail=detail2)
        finally:
            exa.close()

        # 1) 转发端：SNAT + FORWARD
        exb = self.executor_for(relay, secret_cb(relay))
        try:
            ok, err = self.ops.push_egress(exb, cfg, app, relay)
        finally:
            exb.close()
        if not ok:
            return False, err

        # 2) 应用端：备份 + 策略路由；失败则回滚转发端
        exa = self.executor_for(app, secret_cb(app))
        try:
            self.router.backup(exa)
            ok, err = self.router.push(exa, cfg, app, relay)
        finally:
            exa.close()
        if not ok:
            exb = self.executor_for(relay, secret_cb(relay))
            try:
                self.ops.remove_egress(exb, cfg)
            finally:
                exb.close()
            return False, err

        cfg["enabled"] = True
        cfg["backup_path"] = self.router.snapshot
        self._save_state(data, secret_cb)
        self.audit.log("开启出站接管", f"{app['ip']}->{relay['ip']}", detail=scope)
        return True, S["egress_enabled"] + l2_warn

    def egress_disable(self, secret_cb, assume_yes=False):
        """关闭出站：撤销转发端 SNAT 与应用端策略路由，恢复原出口。"""
        data = self.store.load()
        if not self.is_controller(data):
            return False, S["need_controller"]
        cfg = data.get("egress")
        if not cfg:
            return False, S["egress_not_config"]
        if not assume_yes and not self._confirm_action("关闭出站接管：", S["egress_confirm_disable"]):
            return False, S["cancelled"]
        app = self.store.get_server(data, cfg.get("app_id"))
        relay = self.store.get_server(data, cfg.get("relay_id"))
        errs = []
        if relay:
            exb = self.executor_for(relay, secret_cb(relay))
            try:
                ok, err = self.ops.remove_egress(exb, cfg)
                if not ok:
                    errs.append(err)
            finally:
                exb.close()
        if app:
            exa = self.executor_for(app, secret_cb(app))
            try:
                ok, err = self.router.remove(exa, cfg)
                if not ok:
                    errs.append(err)
            finally:
                exa.close()
        cfg["enabled"] = False
        self._save_state(data, secret_cb)
        self.audit.log("关闭出站接管", f"app={cfg.get('app_id')}")
        msg = S["egress_disabled"]
        if errs:
            msg += "（部分清理失败：" + "；".join(errs) + "）"
        return True, msg

    def egress_status(self, secret_cb=None):
        """返回出站配置与（若可连接）实际下发状态。"""
        data = self.store.load()
        cfg = data.get("egress")
        if not cfg:
            return False, S["egress_not_config"]
        app = self.store.get_server(data, cfg.get("app_id"))
        relay = self.store.get_server(data, cfg.get("relay_id"))
        via = (cfg.get("via") or "").strip() or (relay or {}).get("ip", "")
        lines = [
            f"出站状态：{'已开启' if cfg.get('enabled') else '已关闭'}",
            f"  应用端：{(app or {}).get('ip', cfg.get('app_id'))}",
            f"  转发端：{(relay or {}).get('ip', cfg.get('relay_id'))}",
            f"  下一跳(via)：{via}",
            f"  出站源IP(src_ip)：{(cfg.get('src_ip') or '自动(系统按出接口选择)')}",
            f"  范围：{self._egress_scope_text(cfg)}",
            f"  路由表：{cfg.get('table', EGRESS_TABLE_ID)}；优先级：{cfg.get('pref', EGRESS_PREF_BASE)}",
            f"  管理网段排除：{cfg.get('mgmt_nets', []) or '无'}",
        ]
        if secret_cb and app and relay:
            exa = self.executor_for(app, secret_cb(app))
            try:
                lines.append(self.router.status(exa, cfg))
            finally:
                exa.close()
            exb = self.executor_for(relay, secret_cb(relay))
            try:
                installed = self.ops.has_egress(exb, cfg)
                lines.append(f"转发端 SNAT 规则：{'存在' if installed else '缺失'}")
            finally:
                exb.close()
        return True, "\n".join(lines)

    def egress_set_scope(self, mode, targets, secret_cb, assume_yes=False):
        """修改出站范围；若已启用则自动重新下发。"""
        data = self.store.load()
        if not self.is_controller(data):
            return False, S["need_controller"]
        cfg = data.get("egress")
        if not cfg or not cfg.get("app_id"):
            return False, S["egress_not_config"]
        if mode not in ("all", "targets"):
            return False, "范围模式必须为 all 或 targets"
        norm = []
        for t in (targets or []):
            c = valid_cidr(t)
            if not c:
                return False, S["egress_bad_target"]
            if c not in norm:
                norm.append(c)
        if mode == "targets" and not norm:
            return False, S["egress_scope_empty"]
        cfg["mode"] = mode
        cfg["targets"] = norm
        self._save_state(data, secret_cb)
        self.audit.log("修改出站范围", cfg.get("app_id", ""), detail=self._egress_scope_text(cfg))
        if cfg.get("enabled"):
            return self.egress_enable(secret_cb, assume_yes=assume_yes)
        return True, f"出站范围已更新（未启用，无需下发）：{self._egress_scope_text(cfg)}"

    def verify(self, secret_cb, probe_port=None):
        """验证：两端 SSH 可用；启用规则在转发端存在；可选 HTTP 探测。"""
        data = self.store.load()
        report = []
        all_ok = True
        for srv in data["servers"]:
            secret = secret_cb(srv)
            ex = self.executor_for(srv, secret)
            try:
                rc, out, err = ex.run(["echo", "TKV_OK"])
                ok = rc == 0 and "TKV_OK" in out
            finally:
                ex.close()
            report.append(f"{srv['role']} {srv['ip']} SSH：{'正常' if ok else '异常'}")
            all_ok = all_ok and ok
        for r in data["rules"]:
            if not r["enabled"]:
                continue
            relay = self.store.get_server(data, r["relay_id"])
            if not relay:
                continue
            secret = secret_cb(relay)
            ex = self.executor_for(relay, secret)
            try:
                ok, _ = self.ops.has_rule(ex, r), ""
            finally:
                ex.close()
            report.append(f"规则 {r['id']} 在转发端：{'存在' if ok else '缺失'}")
            all_ok = all_ok and ok

        # 可选 HTTP 命中探测：对比转发端 IP 与应用端 IP 的响应头。
        # 注意：若主控端与转发端同机，本机请求走 OUTPUT 链，不经过 DNAT，仅作参考。
        probe = int(probe_port) if probe_port else None
        if probe is None:
            for r in data["rules"]:
                if not r.get("enabled"):
                    continue
                pm = r.get("port_map") or {}
                if r.get("mode") == "mapped" and pm:
                    probe = int(next(iter(pm.keys())))
                    break
            if probe is None:
                relay0 = next((s for s in data["servers"] if s.get("role") == "relay"), None)
                excluded = set(int(p) for p in (relay0 or {}).get("exclude_ports", []))
                for candidate in (80, 443, 8080):
                    if candidate not in excluded:
                        probe = candidate
                        break
        if probe:
            relay0 = next((s for s in data["servers"] if s.get("role") == "relay"), None)
            app0 = next((s for s in data["servers"] if s.get("role") == "app"), None)
            if relay0 and app0:
                ok_r, h_r, info_r = http_probe_headers(relay0["ip"], probe)
                ok_a, h_a, info_a = http_probe_headers(app0["ip"], probe)
                if ok_r and ok_a:
                    same = h_r == h_a
                    report.append(f"端口 {probe} 命中探测：转发端与应用端响应头{'一致，疑似已命中应用端' if same else '不一致，请人工确认'}")
                else:
                    report.append(f"端口 {probe} 命中探测：转发端={info_r}；应用端={info_a}（非 HTTP 服务时属正常，仅作参考）")
                host = (data.get("controller") or {}).get("host", "")
                if host == relay0["ip"]:
                    report.append("注意：主控端与转发端同机，本机请求走 OUTPUT 链，不经过 PREROUTING DNAT，探测结果仅作参考")
        return all_ok, "\n".join(report)

# ---------------------------------------------------------------------------
# 8. 终端图形菜单 TUI（方向键选择 / 表单填写，无对外监听端口）
#    使用 questionary；若未安装则自动降级为纯文本菜单，保证同一份脚本可用。
# ---------------------------------------------------------------------------

try:
    import questionary
    from questionary import Choice
    HAS_QUESTIONARY = True
except Exception:
    HAS_QUESTIONARY = False

class UISelect:
    """统一选择控件：优先 questionary 方向键，降级为数字菜单。"""
    def __init__(self, prompt, options):
        self.prompt = prompt
        self.options = options  # [(label, value), ...]
    def ask(self):
        labels = [o[0] for o in self.options]
        if HAS_QUESTIONARY:
            try:
                # 数字快捷：按数字键直接定位到对应项，回车确认；方向键仍可用。
                # 超过 9 项时仅前 9 项绑定单键数字，其余用方向键选择。
                choices = [
                    Choice(title=l, value=o[1],
                           shortcut_key=(str(i) if i <= 9 else None))
                    for i, (l, o) in enumerate(zip(labels, self.options), 1)
                ]
                chosen = questionary.select(
                    self.prompt,
                    choices=choices,
                    use_indicator=True,
                    use_shortcuts=True,
                    use_arrow_keys=True,
                    instruction="（输入数字直接选择 / 方向键移动，回车确认）",
                    qmark="→",
                    erase_when_done=True,
                ).ask()
                return chosen
            except Exception:
                pass
        return self._plain()
    def _plain(self):
        print("\n" + self.prompt)
        for i, label in enumerate([o[0] for o in self.options], 1):
            print(f"   {i}) {label}")
        while True:
            raw = input("请输入序号> ").strip()
            if raw.isdigit() and 1 <= int(raw) <= len(self.options):
                return self.options[int(raw) - 1][1]
            print("输入无效，请重新输入")

def ui_text(prompt, default="", validate=None):
    """文本输入。validate: 函数，返回 True 或 错误字符串。"""
    if HAS_QUESTIONARY:
        try:
            kw = {"qmark": "?", "erase_when_done": True}
            if default:
                kw["default"] = default
            if validate:
                kw["validate"] = lambda x: True if validate(x) is True else (validate(x) or "输入无效")
            return questionary.text(prompt, **kw).ask()
        except Exception:
            pass
    while True:
        raw = input(f"{prompt}" + (f"（默认 {default}）" if default else "") + "：").strip() or default
        if validate:
            r = validate(raw)
            if r is not True:
                print(r or "输入无效")
                continue
        return raw

def ui_password(prompt):
    if HAS_QUESTIONARY:
        try:
            return questionary.password(prompt, qmark="?", erase_when_done=True).ask()
        except Exception:
            pass
    return getpass.getpass(prompt + "：")

def ui_confirm(prompt, default=False):
    if HAS_QUESTIONARY:
        try:
            return questionary.confirm(prompt, default=default, qmark="?", erase_when_done=True).ask()
        except Exception:
            pass
    raw = input(prompt + ("[Y/n]" if default else "[y/N]")).strip().lower()
    return (raw == "y") if raw else default

def clear_term():
    """清屏：ANSI 序列，兼容 xterm/linux 终端。仅在交互终端生效。"""
    try:
        if sys.stdout.isatty():
            sys.stdout.write("\033[2J\033[H")
            sys.stdout.flush()
    except Exception:
        pass

def ui_pause(msg="按回车返回..."):
    input("\n" + msg)

class SessionCreds:
    """会话内存缓存 + 本地加密凭据库：已保存的密码自动读取，未保存时才提示输入。"""
    def __init__(self):
        self._cache = {}
        self.store = EncryptedCredentialStore()

    def _key(self, server):
        return server.get("id") or server["ip"]

    def _load_from_store(self, server):
        pw = self.store.get(server)
        if pw is None:
            return None
        secret = Secret(pw)
        self._cache[self._key(server)] = secret
        return secret

    def get(self, server, prompt=True):
        key = self._key(server)
        secret = self._cache.get(key)
        if secret is not None:
            return secret
        secret = self._load_from_store(server)
        if secret is not None:
            return secret
        if not prompt:
            return None
        if server.get("key_path"):
            pw = ui_password(f"请输入 {server['ip']}（{server.get('user','root')}）的备用密码（可留空，仅用私钥）")
        else:
            pw = ui_password(f"请输入 {server['ip']}（{server.get('user','root')}）的密码")
            if not pw:
                return None
        secret = Secret(pw or "")
        self._cache[key] = secret
        if pw and os.environ.get("IP_TAKEOVER_NO_SAVE_CREDS") != "1":
            try:
                self.store.put(server, pw)
                print(f"提示：已加密保存 {server['ip']} 的密码，下次无需输入。")
            except Exception as e:
                print(f"提示：密码已用于本次会话，但加密保存失败：{e}")
        return secret

    def forget(self):
        for s in self._cache.values():
            s.clear()
        self._cache.clear()

    def cb(self):
        def _cb(server):
            s = self.get(server)
            if s is None:
                raise RuntimeError("未提供凭据")
            return s
        return _cb

    def cached_cb(self):
        """返回会话缓存或本地加密库中已保存的凭据，缺失返回 None，绝不弹提示。"""
        def _cb(server):
            key = self._key(server)
            secret = self._cache.get(key)
            if secret is not None:
                return secret
            secret = self._load_from_store(server)
            if secret is not None:
                return secret
            if server.get("key_path"):
                return Secret("")
            return None
        return _cb

class TuiApp:
    def __init__(self, expected=None, auto_accept=False):
        self.tk = Takeover(expected=expected, auto_accept=auto_accept)
        self.tk.confirm_cb = lambda: ui_confirm("是否继续？", False)
        self.creds = SessionCreds()
        self.secret_cb = self.creds.cb()
        self.tk.auto_sync_cb = self.creds.cached_cb()   # 后台自动同步：只用已缓存凭据，不打断用户
        st = self.tk.store.load()
        self.local_role = st.get("role")
        self.controller_host = (st.get("controller") or {}).get("host", "")
        # 非主控端且已有主控配置时，界面只读，避免误改状态造成两端分叉。
        self.readonly = self.local_role not in (None, "controller") and bool(self.controller_host)
        if not HAS_QUESTIONARY:
            print("提示：未安装 questionary，已降级为纯文本菜单（功能一致）。")
            print("      如需方向键图形菜单：pip install questionary")

    def run(self):
        while True:
            clear_term()   # 每次回到主菜单前清屏，避免上一轮输出堆积
            n_srv = len(self.tk.list_servers())
            n_rule = len(self.tk.list_rules())
            banner = f"{S['banner']}  |  服务器 {n_srv} 台 / 规则 {n_rule} 条"
            if self.readonly:
                banner += f"  [只读镜像，管理请到主控端 {self.controller_host}]"
            if self.readonly:
                # 只读镜像端只显示可用功能，避免误选管理项后反复弹出拦截提示
                menu = [
                    ("验证配置", "verify"),
                    ("从主控端拉取最新状态", "sync"),
                    ("本机排除端口管理", "local_exclude"),
                    ("删除对端服务器（提交主控端执行）", "peer_remove"),
                    ("环境自检与依赖安装", "doctor"),
                    ("退出", "exit"),
                ]
            else:
                menu = [
                    ("服务器管理（添加 / 开关 / 删除）", "server"),
                    ("转发规则管理（添加 / 开关 / 删除）", "rule"),
                    ("排除端口管理", "exclude"),
                    ("出站身份管理（A 对外显示 B 的 IP）", "egress"),
                    ("验证配置", "verify"),
                    ("回滚转发端", "rollback"),
                    ("设置本机角色", "role"),
                    ("环境自检与依赖安装", "doctor"),
                    ("同步状态到各节点", "sync"),
                    ("退出", "exit"),
                ]
            choice = UISelect(banner, menu).ask()
            if choice is None or choice == "exit":
                break
            if self.readonly and choice in ("server", "rule", "exclude", "egress", "rollback", "role"):
                print(f"\n当前机器是 {self.local_role} 端，状态为只读镜像。")
                print(f"为避免配置分叉，请到主控端 {self.controller_host} 上执行管理操作。")
                ui_pause()
                continue
            try:
                {"server": self.m_server, "rule": self.m_rule, "exclude": self.m_exclude,
                 "egress": self.m_egress,
                 "verify": self.m_verify, "rollback": self.m_rollback, "role": self.m_role,
                 "doctor": self.m_doctor, "sync": self.m_sync,
                 "local_exclude": self.m_local_exclude,
                 "peer_remove": self.m_peer_remove}[choice]()
            except KeyboardInterrupt:
                print("\n（已取消当前操作）")
            except Exception as e:
                print(f"\n操作出错：{e}")
        self.creds.forget()
        print("已退出，会话凭据已清除。")

    def m_local_exclude(self):
        """转发端在本机管理自己的排除端口；权威状态由主控端保存。"""
        clear_term()
        relays = [s for s in self.tk.list_servers() if s.get("role") == "relay"]
        if not relays:
            print("状态中没有转发端服务器。")
            ui_pause()
            return
        rid = relays[0]["id"]
        ok, msg, info = self.tk.exclude_list(rid)
        if not ok:
            print("读取排除端口失败：" + msg)
            ui_pause()
            return
        print(f"本机转发端：{relays[0]['ip']}")
        print(f"SSH 端口={info['ssh_port']}（强制排除，不可移除）")
        print(f"当前排除端口={info['exclude_ports']}")
        c = UISelect("【本机排除端口管理】", [
            ("查看当前排除端口", "list"),
            ("添加排除端口", "add"),
            ("移除排除端口", "remove"),
            ("返回主菜单", "back"),
        ]).ask()
        if c in (None, "back"):
            return
        if c == "list":
            ui_pause()
            return
        raw = ui_text("请输入端口，多个用逗号，支持范围如 8000-9000",
                      validate=lambda x: True if parse_ports(x) is not None else S["bad_port"])
        ports = parse_ports(raw) or []
        if not ports:
            return
        if c == "add":
            ok2, msg2 = self.tk.exclude_add_anywhere(rid, ports, self.secret_cb)
        else:
            ok2, msg2 = self.tk.exclude_remove_anywhere(rid, ports, self.secret_cb)
        print(("成功：" if ok2 else "失败：") + msg2)
        ok3, _, info3 = self.tk.exclude_list(rid)
        if ok3:
            print(f"当前排除端口={info3['exclude_ports']}")
        ui_pause()

    def m_peer_remove(self):
        """镜像端删除对端：提交主控端执行，避免本地直接改权威状态。"""
        clear_term()
        servers = self.tk.list_servers()
        local_id = None
        if self.local_role:
            same_role = [s for s in servers if s.get("role") == self.local_role]
            if len(same_role) == 1:
                local_id = same_role[0]["id"]
        candidates = [s for s in servers if s["id"] != local_id]
        if not candidates:
            print("没有可删除的对端服务器。")
            ui_pause()
            return
        opts = [(f"[{s['id']}] {s['role']} {s['ip']}:{s['ssh_port']} "
                 f"({'启用' if s['enabled'] else '关闭'})", s["id"]) for s in candidates]
        sid = UISelect("请选择要删除的对端服务器：", opts).ask()
        if not sid:
            return
        srv = next(s for s in candidates if s["id"] == sid)
        n = sum(1 for r in self.tk.list_rules() if r["app_id"] == sid or r["relay_id"] == sid)
        if not ui_confirm(f"确认删除对端 {srv['ip']}？将提交主控端 {self.controller_host} 执行，影响 {n} 条规则", False):
            return
        ok, msg = self.tk.remove_server_anywhere(sid, self.secret_cb)
        print(("成功：" if ok else "失败：") + msg)
        st = self.tk.store.load()
        self.local_role = st.get("role")
        self.controller_host = (st.get("controller") or {}).get("host", "")
        ui_pause()

    def _pick_server(self, role=None, allow_none=False):
        servers = [s for s in self.tk.list_servers() if role is None or s["role"] == role]
        if not servers:
            print("没有可用的服务器，请先添加。")
            return None
        opts = [(f"[{s['id']}] {s['role']} {s['ip']}:{s['ssh_port']} "
                 f"({'启用' if s['enabled'] else '关闭'})", s["id"]) for s in servers]
        if allow_none:
            opts.append(("返回上级", None))
        return UISelect("请选择服务器：", opts).ask()

    def _pick_rule(self, allow_none=True):
        rules = self.tk.list_rules()
        if not rules:
            print("没有可用的规则，请先添加。")
            return None
        opts = []
        for r in rules:
            desc = ",".join(f"{a}->{b}" for a, b in (r.get("port_map") or {}).items()) or "全部端口"
            state = "生效中" if r["effective"] else "未生效"
            opts.append((f"[{r['id']}] {r['relay_id']} → {r['app_id']}  {desc}  {state}", r["id"]))
        if allow_none:
            opts.append(("返回上级", None))
        return UISelect("请选择规则：", opts).ask()

    # ---- 服务器管理 ----
    def m_server(self):
        while True:
            clear_term()
            c = UISelect("【服务器管理】", [
                ("添加服务器", "add"),
                ("列出服务器", "list"),
                ("开启服务器", "enable"),
                ("关闭服务器", "disable"),
                ("删除服务器（双向联动）", "remove"),
                ("返回主菜单", "back"),
            ]).ask()
            if c in (None, "back"):
                break
            if c == "add":
                role = UISelect("选择服务器角色：", [("转发端 relay（持有对外 IP）", "relay"),
                                                  ("应用端 app（实际跑业务）", "app")]).ask()
                if role is None:
                    continue
                ip = ui_text("请输入 IP 地址", validate=lambda x: True if valid_ip(x) else S["bad_ip"])
                port = ui_text("请输入 SSH 端口", default="22", validate=lambda x: True if valid_port(x) else S["bad_port"])
                user = ui_text("请输入 SSH 用户名", default="root", validate=lambda x: True if x.strip() else S["required"])
                key_path = ui_text("请输入 SSH 私钥路径（留空使用密码）")
                if key_path:
                    pw = ui_password(f"请输入 {ip} 的备用密码（可留空，私钥优先）")
                else:
                    pw = ui_password(f"请输入 {ip} 的密码（将加密保存到本机，下次免输入）")
                if not all([ip, port, user]) or (not key_path and not pw):
                    continue
                ok, msg, srv = self.tk.add_server(role, ip, port, user, Secret(pw or ""), key_path=key_path or None)
                print(("成功：" if ok else "失败：") + msg)
                if ok and srv and pw and os.environ.get("IP_TAKEOVER_NO_SAVE_CREDS") != "1":
                    try:
                        self.creds.store.put(srv, pw)
                        print(f"密码已加密保存：{ip}")
                    except Exception as e:
                        print(f"密码已用于本次操作，但加密保存失败：{e}")
            elif c == "list":
                servers = self.tk.list_servers()
                if not servers:
                    print("（暂无服务器）")
                for s in servers:
                    extra = ""
                    if s["role"] == "relay":
                        ae = "开" if s.get("auto_exclude_enabled", True) else "关"
                        extra = (f"  手动排除={s.get('exclude_ports', [])}"
                                 f"  自动排除={ae}({s.get('auto_excluded_ports', [])})")
                    print(f"  [{s['id']}] {s['role']} {s['ip']}:{s['ssh_port']} "
                          f"{'启用' if s['enabled'] else '关闭'}{extra}")
                ui_pause()
            elif c in ("enable", "disable", "remove"):
                sid = self._pick_server()
                if not sid:
                    continue
                srv = next(s for s in self.tk.list_servers() if s["id"] == sid)
                if c == "enable":
                    ok, msg = self.tk.server_enable(sid, self.secret_cb)
                elif c == "disable":
                    if not ui_confirm(f"确认关闭 {srv['ip']}？相关规则将失效", False):
                        continue
                    ok, msg = self.tk.server_disable(sid, self.secret_cb)
                else:
                    n = sum(1 for r in self.tk.list_rules() if r["app_id"] == sid or r["relay_id"] == sid)
                    if not ui_confirm(f"确认删除 {srv['ip']}？将影响 {n} 条规则并双向联动清理", False):
                        continue
                    ok, msg = self.tk.server_remove(sid, self.secret_cb)
                print(("成功：" if ok else "失败：") + msg)
                ui_pause()

    # ---- 规则管理 ----
    def m_rule(self):
        while True:
            clear_term()
            c = UISelect("【转发规则管理】", [
                ("添加转发规则", "add"),
                ("列出规则", "list"),
                ("启用规则", "enable"),
                ("关闭规则", "disable"),
                ("删除规则", "remove"),
                ("返回主菜单", "back"),
            ]).ask()
            if c in (None, "back"):
                break
            if c == "add":
                app = self._pick_server(role="app")
                if not app:
                    continue
                relay = self._pick_server(role="relay")
                if not relay:
                    continue
                mode = UISelect("选择转发模式：", [
                    ("透明转发：除排除端口外全部端口 → 应用端", "transparent"),
                    ("端口映射：指定端口一对一映射", "mapped"),
                ]).ask()
                pm = {}
                if mode == "mapped":
                    raw = ui_text("请输入端口映射，格式 80=8080,443=8443", validate=lambda x: True if x.strip() else "不能为空")
                    try:
                        for kv in raw.split(","):
                            a, b = kv.split("=", 1)
                            if int(a) and int(b):
                                pm[a.strip()] = b.strip()
                    except Exception:
                        print("映射格式错误")
                        continue
                print(S["keep_session"])
                ok, msg, rule = self.tk.add_rule(app, relay, mode or "transparent", pm, self.secret_cb)
                print(("成功：" if ok else "失败：") + msg)
                ui_pause()
            elif c == "list":
                rules = self.tk.list_rules()
                if not rules:
                    print("（暂无规则）")
                for r in rules:
                    desc = ",".join(f"{a}->{b}" for a, b in (r.get("port_map") or {}).items()) or "全部端口"
                    print(f"  [{r['id']}] {r['relay_id']} → {r['app_id']}  {desc}  "
                          f"{'生效中' if r['effective'] else '未生效'}")
                ui_pause()
            elif c in ("enable", "disable", "remove"):
                rid = self._pick_rule()
                if not rid:
                    continue
                fn = {"enable": self.tk.rule_enable, "disable": self.tk.rule_disable,
                      "remove": self.tk.rule_remove}[c]
                ok, msg = fn(rid, self.secret_cb)
                print(("成功：" if ok else "失败：") + msg)
                ui_pause()

    # ---- 排除端口 ----
    def m_exclude(self):
        while True:
            clear_term()
            c = UISelect("【排除端口管理】", [
                ("查看排除端口", "list"),
                ("扫描并排除转发端已用端口（保护原有业务）", "scan"),
                ("开启自动排除", "auto_on"),
                ("关闭自动排除", "auto_off"),
                ("添加排除端口", "add"),
                ("移除排除端口", "remove"),
                ("返回主菜单", "back"),
            ]).ask()
            if c in (None, "back"):
                break
            rid = self._pick_server(role="relay")
            if not rid:
                continue
            if c == "list":
                ok, msg, info = self.tk.exclude_list(rid)
                if ok:
                    auto_flag = "开启" if info["auto_exclude_enabled"] else "关闭"
                    print(f"  SSH 端口={info['ssh_port']}（强制排除，不可移除）")
                    print(f"  手动排除端口={info['exclude_ports']}")
                    print(f"  自动排除={auto_flag}；检测来源={info['auto_exclude_source'] or '未检测'}")
                    print(f"  自动检测的已用端口={info['auto_excluded_ports']}")
                    print(f"  当前生效排除集={info['effective']}")
                else:
                    print(msg)
                ui_pause()
            elif c in ("scan", "auto_on", "auto_off"):
                if c == "scan":
                    print("正在检测转发端已监听端口并重新下发规则...")
                    ok, msg = self.tk.auto_exclude_scan_anywhere(rid, self.secret_cb)
                else:
                    ok, msg = self.tk.auto_exclude_set_anywhere(rid, c == "auto_on", self.secret_cb)
                print(("成功：" if ok else "失败：") + msg)
                ui_pause()
            elif c in ("add", "remove"):
                raw = ui_text("请输入端口，多个用逗号，范围用 -（如 3306,8000-9000）",
                              validate=lambda x: True if parse_ports(x) else "端口格式错误")
                ports = parse_ports(raw) or []
                fn = self.tk.exclude_add if c == "add" else self.tk.exclude_remove
                ok, msg = fn(rid, ports, self.secret_cb)
                print(("成功：" if ok else "失败：") + msg)
                ui_pause()

    # ---- V2.0 出站身份管理 ----
    def m_egress(self):
        while True:
            clear_term()
            c = UISelect("【出站身份管理】让应用端对外显示转发端 IP", [
                ("查看出站状态", "status"),
                ("配置出站（选择应用端/转发端/范围）", "setup"),
                ("开启出站下发", "enable"),
                ("关闭出站并恢复", "disable"),
                ("修改出站范围", "scope"),
                ("返回主菜单", "back"),
            ]).ask()
            if c in (None, "back"):
                break
            if c == "status":
                ok, msg = self.tk.egress_status(self.secret_cb)
                print(msg if ok else ("失败：" + msg))
                ui_pause()
                continue
            if c == "setup":
                app_id = self._pick_server(role="app")
                if not app_id:
                    continue
                relay_id = self._pick_server(role="relay")
                if not relay_id:
                    continue
                mode = UISelect("出站范围：", [
                    ("仅指定目标（推荐，风险低）", "targets"),
                    ("全部出站经转发端（风险高）", "all"),
                ]).ask()
                if mode is None:
                    continue
                targets, via, mgmt = [], "", []
                if mode == "targets":
                    raw = ui_text("目标网段，多个用逗号（如 1.2.3.0/24,10.0.0.0/8）",
                                  validate=lambda x: True if all(valid_cidr(t) for t in x.split(",") if t.strip()) else S["egress_bad_target"])
                    targets = [t.strip() for t in raw.split(",") if t.strip()]
                via = ui_text("应用端侧下一跳地址（留空则用转发端 IP；二层地址或隧道地址）")
                rawm = ui_text("管理网段排除（逗号分隔，这些流量保留直连；可留空）")
                mgmt = [m.strip() for m in rawm.split(",") if m.strip()]
                ok, msg = self.tk.egress_config(app_id, relay_id, mode, targets,
                                                self.secret_cb, via=via, mgmt_nets=mgmt)
                print(("成功：" if ok else "失败：") + msg)
                ui_pause()
            elif c == "enable":
                ok, msg = self.tk.egress_enable(self.secret_cb, assume_yes=False)
                print(("成功：" if ok else "失败：") + msg)
                ui_pause()
            elif c == "disable":
                ok, msg = self.tk.egress_disable(self.secret_cb, assume_yes=False)
                print(("成功：" if ok else "失败：") + msg)
                ui_pause()
            elif c == "scope":
                mode = UISelect("出站范围：", [
                    ("仅指定目标（推荐）", "targets"),
                    ("全部出站经转发端（风险高）", "all"),
                ]).ask()
                if mode is None:
                    continue
                targets = []
                if mode == "targets":
                    raw = ui_text("目标网段，多个用逗号",
                                  validate=lambda x: True if all(valid_cidr(t) for t in x.split(",") if t.strip()) else S["egress_bad_target"])
                    targets = [t.strip() for t in raw.split(",") if t.strip()]
                ok, msg = self.tk.egress_set_scope(mode, targets, self.secret_cb)
                print(("成功：" if ok else "失败：") + msg)
                ui_pause()

    # ---- 验证 / 回滚 / 角色 ----
    def m_verify(self):
        print("正在验证...")
        ok, report = self.tk.verify(self.secret_cb)
        print(report)
        print(S["success"] if ok else "验证未全部通过")
        ui_pause()

    def m_rollback(self):
        rid = self._pick_server(role="relay")
        if not rid:
            return
        srv = next(s for s in self.tk.list_servers() if s["id"] == rid)
        if not ui_confirm(f"确认将转发端 {srv['ip']} 全量恢复到首次备份？将影响所有规则", False):
            return
        ok, msg = self.tk.rollback(rid, self.secret_cb)
        print(("成功：" if ok else "失败：") + msg)
        ui_pause()

    def m_role(self):
        role = UISelect("请选择本机角色：", [
            ("relay 转发端（持有对外 IP，转发流量）", "relay"),
            ("app 应用端（实际跑业务）", "app"),
            ("controller 主控端（管理两端，推荐）", "controller"),
        ]).ask()
        if role:
            self.tk.set_role(role)
            print(S["role_set"].format(role=role))
            ui_pause()

    def m_doctor(self):
        doctor(fix=False)
        ui_pause()

    def m_sync(self):
        data = self.tk.store.load()
        if self.tk.is_controller(data):
            print("主控端 → 广播权威状态到各节点：")
            ok, report = self.tk.broadcast_state(data, self.secret_cb)
            print(report)
            print("结果：" + ("全部同步成功" if ok else "部分失败，详见上方"))
        else:
            print("从主控端拉取最新状态：")
            ok, msg = self.tk.pull_state(self.secret_cb)
            print(("成功：" if ok else "失败：") + msg)
            if ok:
                # 刷新只读视图标记
                st = self.tk.store.load()
                self.local_role = st.get("role")
                self.controller_host = (st.get("controller") or {}).get("host", "")
        ui_pause()


# ---------------------------------------------------------------------------
# 9. CLI 交互层
# ---------------------------------------------------------------------------

def ask(prompt, default=""):
    v = input(prompt).strip()
    return v or default

def ask_secret(prompt):
    return Secret(getpass.getpass(prompt))

def ask_password_for(server):
    return ask_secret(f"请输入 {server['ip']} 的密码（输入不显示）：")

def cred_cli(op, tk, creds):
    """本地加密凭据管理：保存 / 查看索引 / 清空。永不显示密码明文。"""
    store = creds.store
    if op == "save":
        servers = tk.list_servers()
        if not servers:
            print("尚无服务器，请先添加服务器。")
            return
        for i, s in enumerate(servers, 1):
            print(f"{i}) [{s['id']}] {s['role']} {s['ip']}:{s['ssh_port']}")
        raw = ask("选择要保存密码的服务器序号：", "1")
        try:
            idx = int(raw) - 1
        except ValueError:
            idx = -1
        if idx < 0 or idx >= len(servers):
            print("选择无效。")
            return
        srv = servers[idx]
        pw = ask_secret(f"请输入 {srv['ip']} 的密码（输入不显示）：")
        if not pw.value():
            print("密码不能为空。")
            pw.clear()
            return
        try:
            store.put(srv, pw.value())
            print(f"已加密保存 {srv['ip']} 的密码，后续操作无需重复输入。")
        except Exception as e:
            print(f"保存失败：{e}")
        finally:
            pw.clear()
        return

    if op == "list":
        keys = store.keys()
        if not keys:
            print("（暂无已保存的密码）")
            return
        print("已保存的凭据索引（不显示密码）：")
        for k in keys:
            print(f"  - {k}")
        return

    if op == "clear":
        print("将清空本机保存的全部服务器密码。")
        if ask("[y/N]").strip().lower() != "y":
            print(S["cancelled"])
            return
        try:
            store.clear()
            print("已清空加密凭据库。")
        except Exception as e:
            print(f"清空失败：{e}")
        return

def build_cli():
    p = argparse.ArgumentParser(description=S["banner"])
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("init", help="首次运行：选择本机角色")
    sp = sub.add_parser("server", help="服务器管理")
    sps = sp.add_subparsers(dest="op")
    sa = sps.add_parser("add", help="添加服务器"); sa.add_argument("role", choices=["relay", "app"])
    sps.add_parser("list", help="列出服务器")
    for op in ("enable", "disable", "remove"):
        x = sps.add_parser(op, help=f"{op}服务器"); x.add_argument("id")
        if op == "remove":
            x.add_argument("--yes", "-y", action="store_true", help="跳过确认（用于远程自动化）")
            x.add_argument("--remote", action="store_true", help=argparse.SUPPRESS)
    rp = sub.add_parser("rule", help="转发规则管理")
    rps = rp.add_subparsers(dest="op")
    ra = rps.add_parser("add", help="添加规则")
    ra.add_argument("--mode", choices=["transparent", "mapped"], default="transparent")
    ra.add_argument("--map", dest="pmap", default="", help="mapped 模式端口映射，如 80=8080,443=8443")
    rps.add_parser("list", help="列出规则")
    for op in ("enable", "disable", "remove"):
        x = rps.add_parser(op, help=f"{op}规则"); x.add_argument("id")
    ep = sub.add_parser("exclude", help="转发端排除端口")
    eps = ep.add_subparsers(dest="op")
    eps.add_parser("list", help="查看排除端口").add_argument("relay_id")
    for op in ("add", "remove"):
        x = eps.add_parser(op, help=f"{op}排除端口")
        x.add_argument("relay_id"); x.add_argument("ports", nargs="+")
        x.add_argument("--yes", "-y", action="store_true", help="跳过确认（用于远程自动化）")
        x.add_argument("--remote", action="store_true", help=argparse.SUPPRESS)
    # 自动排除转发端已用端口：scan=立即检测并刷新；on/off=开关
    xa = eps.add_parser("auto", help="自动排除转发端已监听端口（保护原有业务）")
    xa.add_argument("relay_id")
    xa.add_argument("action", nargs="?", default="scan", choices=["scan", "on", "off"],
                    help="scan=立即检测并重新下发（默认）；on/off=开启或关闭")
    xa.add_argument("--remote", action="store_true", help=argparse.SUPPRESS)
    rb = sub.add_parser("rollback", help="全量回滚转发端"); rb.add_argument("relay_id")
    # V2.0 出站身份
    eg = sub.add_parser("egress", help="出站身份接管：让应用端对外显示转发端 IP")
    egs = eg.add_subparsers(dest="op")
    egs.add_parser("status", help="查看出站状态")
    es = egs.add_parser("setup", help="配置出站（应用端/转发端/范围），不立即下发")
    es.add_argument("app_id"); es.add_argument("relay_id")
    es.add_argument("--mode", choices=["all", "targets"], default="all",
                    help="all=全部出站经转发端；targets=仅指定目标")
    es.add_argument("--targets", default="", help="targets 模式的目标网段，逗号分隔，如 1.2.3.0/24,10.0.0.0/8")
    es.add_argument("--via", default="", help="可选：应用端侧下一跳地址（二层地址或隧道地址），默认用转发端 IP")
    es.add_argument("--src-ip", default="", help="可选：隧道模式下 A 出站包保持的源 IP（通常为 A 公网 IP），用于命中转发端 SNAT")
    es.add_argument("--mgmt-nets", default="", help="可选：管理网段（逗号分隔），这些流量保留直连不走转发端")
    egs.add_parser("enable", help="下发出站规则（SNAT + 策略路由）").add_argument(
        "--yes", "-y", action="store_true", help="跳过二次确认")
    egs.add_parser("disable", help="关闭出站并恢复原出口").add_argument(
        "--yes", "-y", action="store_true", help="跳过二次确认")
    ess = egs.add_parser("set-scope", help="修改出站范围；已启用时自动重新下发")
    ess.add_argument("--mode", choices=["all", "targets"], required=True)
    ess.add_argument("--targets", default="", help="targets 模式目标网段，逗号分隔")
    ess.add_argument("--yes", "-y", action="store_true", help="跳过二次确认")
    vp = sub.add_parser("verify", help="验证配置")
    vp.add_argument("--probe-port", type=int, default=None,
                    help="指定 HTTP 命中探测端口；不指定则自动从规则/常见端口推断")
    sub.add_parser("sync", help="同步状态：主控端广播到各节点 / 非主控端从主控端拉取")
    sub.add_parser("ui", help="进入终端图形菜单（无参数运行时默认进入）")
    dc = sub.add_parser("doctor", help="环境自检与依赖安装/修复")
    dc.add_argument("--fix", action="store_true", help="强制重新安装依赖（用于修复）")
    cp = sub.add_parser("cred", help="本地加密凭据管理（保存后无需每次输入密码）")
    cps = cp.add_subparsers(dest="op")
    cps.add_parser("save", help="从已配置服务器中选择并加密保存密码")
    cps.add_parser("list", help="列出已保存凭据的索引（不显示密码）")
    cps.add_parser("clear", help="清空本机保存的全部密码")
    return p

def doctor(fix=False):
    """环境自检：报告依赖状态，并在新机器/缺失时安装。"""
    print("=== 环境自检 ===\n")
    print(f"  Python     : {sys.version.split()[0]} ({sys.executable})")
    # pip
    pip_ok = _run([sys.executable, "-m", "pip", "--version"])[0] == 0
    print(f"  pip        : {'已安装' if pip_ok else '缺失'}")
    if fix or not pip_ok:
        _ensure_pip()
    # Python 依赖
    import importlib.metadata as md
    for mod, pkg in (("paramiko", "paramiko"), ("questionary", "questionary")):
        installed = _have(mod)
        ver = ""
        if installed:
            try:
                ver = md.version(pkg)
            except Exception:
                ver = "已安装"
        print(f"  {mod:<11}: {ver if installed else '缺失'}")
        if fix or not installed:
            _pip_install(f"{pkg}=={'5.1.0' if mod=='paramiko' else '2.1.1'}", required=(mod == "paramiko"))
            # 刷新内存模块信息
            if mod == "questionary":
                global HAS_QUESTIONARY
                try:
                    import questionary  # noqa: F401
                    HAS_QUESTIONARY = True
                except Exception:
                    HAS_QUESTIONARY = False
    crypto_installed = _have("cryptography")
    print(f"  cryptography: {'已安装' if crypto_installed else '缺失'}（加密凭据）")
    if fix or not crypto_installed:
        _pip_install("cryptography", required=True)
    # 本地加密凭据库
    try:
        n_cred = len(EncryptedCredentialStore().keys())
        cred_desc = f"已保存 {n_cred} 个索引" if n_cred else "尚无保存的密码"
    except Exception as e:
        cred_desc = f"读取失败（{e}）"
    print(f"  加密凭据   : {CRED_STORE_PATH}（{cred_desc}）")
    print(f"  加密密钥   : {CRED_KEY_PATH}（600）")
    # 系统工具
    print(f"  iptables   : {shutil.which('iptables') or '缺失'}")
    if fix or shutil.which("iptables") is None:
        _ensure_system_tools()
    print(f"  cron       : {shutil.which('crontab') or '缺失'}（缺失时持久化需改用其他方式）")
    print(f"  状态文件   : {STATE_PATH}")
    # 状态概览
    try:
        d = StateStore().load()
        print(f"  已配置服务器: {len(d['servers'])} 台；规则: {len(d['rules'])} 条")
    except Exception as e:
        print(f"  状态文件   : 读取失败（{e}）")
    print(f"\n自检完成。安装日志：{_BOOT_LOG}")

def main():
    disable_core_dump()
    # 无参数 或 ui 子命令 → 进入终端图形菜单
    if len(sys.argv) == 1 or sys.argv[1] == "ui":
        clear_term()   # 启动即清屏，去掉上次退出残留的 Cancelled/提示行
        expected = {}
        try:
            kp = paramiko.hostkeys.HostKeys(KNOWN_HOSTS_PATH)
            for host in kp.keys():
                k = kp.lookup(host)
                if k:
                    for kt, key in k.items():
                        expected[host] = _fingerprint(key)
                        break
        except Exception:
            pass
        TuiApp(expected=expected).run()
        return
    print(S["banner"])
    args = build_cli().parse_args()
    if args.cmd == "doctor":
        doctor(fix=getattr(args, "fix", False))
        return
    tk = Takeover()
    data = tk.store.load()
    _cli_creds = SessionCreds()

    if args.cmd == "cred":
        cred_cli(getattr(args, "op", None), tk, _cli_creds)
        return

    def secret_cb(server):
        return _cli_creds.get(server)

    tk.auto_sync_cb = _cli_creds.cached_cb()   # 自动广播只用已输入过的凭据

    if args.cmd == "init":
        print(S["role_prompt"]); print(S["role_relay"]); print(S["role_app"]); print(S["role_ctrl"])
        choice = ask("> ", "3")
        role = {"1": "relay", "2": "app", "3": "controller"}.get(choice, "controller")
        tk.set_role(role)
        print(S["role_set"].format(role=role))
        return

    if args.cmd == "server":
        if args.op == "add":
            role = args.role
            ip = ask(S["ask_ip"])
            while not valid_ip(ip):
                print(S["bad_ip"]); ip = ask(S["ask_ip"])
            port = ask(S["ask_ssh_port"], "22")
            while not valid_port(port):
                print(S["bad_port"]); port = ask(S["ask_ssh_port"], "22")
            user = ask(S["ask_user"], "root")
            key_path = ask("请输入 SSH 私钥路径（留空使用密码）：")
            if key_path:
                pw = ask_secret("请输入备用密码（可留空，私钥优先，输入不显示）：")
            else:
                pw = ask_secret(S["ask_pass"])
            ok, msg, srv = tk.add_server(role, ip, port, user, pw, key_path=key_path or None)
            print(S["success"] if ok else S["failed"].format(reason=msg))
            if ok:
                print(msg)
                if srv and pw.value() and os.environ.get("IP_TAKEOVER_NO_SAVE_CREDS") != "1":
                    try:
                        _cli_creds.store.put(srv, pw.value())
                        print(f"密码已加密保存：{ip}")
                    except Exception as e:
                        print(f"密码已用于本次操作，但加密保存失败：{e}")
            pw.clear()
        elif args.op == "list":
            for s in tk.list_servers():
                flag = "启用" if s["enabled"] else "关闭"
                line = f"[{s['id']}] {s['role']} {s['ip']}:{s['ssh_port']} {flag}"
                if s["role"] == "relay":
                    ae = "开" if s.get("auto_exclude_enabled", True) else "关"
                    line += (f"  手动排除={s.get('exclude_ports', [])}"
                             f"  自动排除={ae}({s.get('auto_excluded_ports', [])})")
                print(line)
        elif args.op in ("enable", "disable", "remove"):
            srv = tk.store.get_server(data, args.id)
            if not srv:
                print(S["no_server"]); return
            if args.op == "disable":
                print(S["confirm_disable"].format(role=srv["role"], ip=srv["ip"]))
                if ask("[y/N]").lower() != "y": print(S["cancelled"]); return
                ok, msg = tk.server_disable(args.id, secret_cb)
            elif args.op == "enable":
                ok, msg = tk.server_enable(args.id, secret_cb)
            else:
                n = sum(1 for r in data["rules"] if r["app_id"] == args.id or r["relay_id"] == args.id)
                if not getattr(args, "yes", False):
                    print(S["confirm_remove"].format(role=srv["role"], ip=srv["ip"], n=n))
                    if ask("[y/N]").lower() != "y":
                        print(S["cancelled"])
                        return
                if tk.is_controller(data):
                    ok, msg = tk.server_remove(args.id, secret_cb)
                else:
                    ok, msg = tk.remove_server_anywhere(args.id, secret_cb)
            print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
            if ok and getattr(args, "remote", False):
                print(f"SERVER_REMOVED:{args.id}")
        return

    if args.cmd == "rule":
        if args.op == "add":
            servers = tk.list_servers()
            apps = [s for s in servers if s["role"] == "app"]
            relays = [s for s in servers if s["role"] == "relay"]
            if not apps or not relays:
                print("请先添加应用端和转发端服务器"); return
            for i, s in enumerate(apps): print(f"应用端 {i+1}) [{s['id']}] {s['ip']}")
            ai = int(ask("选择应用端序号：", "1")) - 1
            for i, s in enumerate(relays): print(f"转发端 {i+1}) [{s['id']}] {s['ip']}")
            ri = int(ask("选择转发端序号：", "1")) - 1
            pm = {}
            if args.mode == "mapped":
                for kv in args.pmap.split(","):
                    if "=" in kv:
                        a, b = kv.split("=", 1); pm[a.strip()] = b.strip()
            print(S["keep_session"])
            ok, msg, _ = tk.add_rule(apps[ai]["id"], relays[ri]["id"], args.mode, pm, secret_cb)
            print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
        elif args.op == "list":
            for r in tk.list_rules():
                eff = S["effective"] if r["effective"] else S["ineffective"]
                pm = r.get("port_map", {}) or {}
                desc = ",".join(f"{a}->{b}" for a, b in pm.items()) or "全部端口(排除项除外)"
                print(f"[{r['id']}] {r['app_id']} <- {r['relay_id']}  {desc}  {eff}")
        elif args.op in ("enable", "disable", "remove"):
            fn = {"enable": tk.rule_enable, "disable": tk.rule_disable, "remove": tk.rule_remove}[args.op]
            ok, msg = fn(args.id, secret_cb)
            print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
        return

    if args.cmd == "exclude":
        srv = tk.store.get_server(data, args.relay_id)
        if not srv or srv["role"] != "relay":
            print(S["need_relay"]); return
        if args.op == "list":
            ok, msg, info = tk.exclude_list(args.relay_id)
            if ok:
                auto_flag = "开启" if info["auto_exclude_enabled"] else "关闭"
                print(f"SSH 端口={info['ssh_port']}（强制排除，不可移除）")
                print(f"手动排除端口={info['exclude_ports']}")
                print(f"自动排除：{auto_flag}；来源={info['auto_exclude_source'] or '未检测'}")
                print(f"自动检测的已用端口={info['auto_excluded_ports']}")
                print(f"当前生效排除集={info['effective']}")
            else:
                print(msg)
        elif args.op == "auto":
            action = getattr(args, "action", "scan") or "scan"
            if action == "scan":
                ok, msg = tk.auto_exclude_scan_anywhere(args.relay_id, secret_cb)
                print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
                if ok and getattr(args, "remote", False):
                    print(f"AUTO_EXCLUDE_SCANNED:{args.relay_id}")
            else:
                enabled = (action == "on")
                ok, msg = tk.auto_exclude_set_anywhere(args.relay_id, enabled, secret_cb)
                print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
                if ok and getattr(args, "remote", False):
                    print(f"AUTO_EXCLUDE_SET:{args.relay_id}")
        elif args.op == "add":
            ports = []
            for t in args.ports:
                got = parse_ports(t)
                if got is None: print(S["bad_port"]); return
                ports += got
            ok, msg = tk.exclude_add_anywhere(args.relay_id, ports, secret_cb)
            print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
            if ok and getattr(args, "remote", False):
                print(f"EXCLUDE_ADDED:{args.relay_id}")
        elif args.op == "remove":
            ports = []
            for t in args.ports:
                got = parse_ports(t)
                if got is None: print(S["bad_port"]); return
                ports += got
            ok, msg = tk.exclude_remove_anywhere(args.relay_id, ports, secret_cb)
            print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
            if ok and getattr(args, "remote", False):
                print(f"EXCLUDE_REMOVED:{args.relay_id}")
        return

    if args.cmd == "rollback":
        srv = tk.store.get_server(data, args.relay_id)
        if not srv: print(S["no_server"]); return
        print(S["confirm_rollback"].format(ip=srv["ip"]))
        if ask("[y/N]").lower() != "y": print(S["cancelled"]); return
        ok, msg = tk.rollback(args.relay_id, secret_cb)
        print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
        return

    if args.cmd == "egress":
        op = getattr(args, "op", None)
        if op == "status":
            ok, report = tk.egress_status(secret_cb)
            print(report)
        elif op == "setup":
            targets = [t.strip() for t in args.targets.split(",") if t.strip()]
            mgmt = [m.strip() for m in args.mgmt_nets.split(",") if m.strip()]
            ok, msg = tk.egress_config(args.app_id, args.relay_id, args.mode,
                                       targets, secret_cb, via=args.via, mgmt_nets=mgmt,
                                       src_ip=getattr(args, "src_ip", ""))
            print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
        elif op == "enable":
            ok, msg = tk.egress_enable(secret_cb, assume_yes=getattr(args, "yes", False))
            print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
        elif op == "disable":
            ok, msg = tk.egress_disable(secret_cb, assume_yes=getattr(args, "yes", False))
            print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
        elif op == "set-scope":
            targets = [t.strip() for t in args.targets.split(",") if t.strip()]
            ok, msg = tk.egress_set_scope(args.mode, targets, secret_cb,
                                          assume_yes=getattr(args, "yes", False))
            print(S["success"] if ok else S["failed"].format(reason=msg)); print(msg)
        else:
            build_cli().parse_args(["egress", "--help"])
        return

    if args.cmd == "verify":
        ok, report = tk.verify(secret_cb, probe_port=args.probe_port)
        print(report)
        print(S["success"] if ok else "验证未全部通过")
        return

    if args.cmd == "sync":
        data = tk.store.load()
        if tk.is_controller(data):
            print("主控端 → 广播权威状态到各节点：")
            ok, report = tk.broadcast_state(data, secret_cb)
            print(report)
            print("结果：" + ("全部同步成功" if ok else "部分失败，详见上方"))
        else:
            ok, msg = tk.pull_state(secret_cb)
            print(("成功：" if ok else "失败：") + msg)
        return

    build_cli().print_help()

if __name__ == "__main__":
    main()
