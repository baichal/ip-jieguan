# IP 接管配置工具（命令行脚本版）

> 合规声明：本工具仅用于你拥有合法管理权限的服务器。请确保对目标服务器及 IP 拥有合法授权。

## 它解决什么问题

某些场景下一台服务器持有对外 IP（**转发端 / relay**），但业务必须跑在另一台服务器（**应用端 / app**）上，而 IP 本身无法转移。本工具在转发端做透明 DNAT：访问转发端 IP 的流量（除 SSH 与排除端口外）被转发到应用端处理，转发端退化成"IP 壳"。

- **转发端 Relay**：持有对外 IP，负责转发流量。
- **应用端 App**：实际运行业务。
- **主控端 Controller**：运行管理命令的那台，通过 SSH 管理两端。

> 完整目标是让应用端 A **真正使用转发端 B 的 IP**，包含两层：**入站**（别人访问 B 的 IP → A 承接，已实现并真实验证）与 **出站**（A 主动对外 → 源 IP 显示为 B，V2.0 已实现，见「出站身份接管」）。
>
> 固有限制：转发端是单点，一旦宕机该 IP 即失效（DNAT 固有，无法消除）。出站需 A/B 二层可达（同网段/VPC 或已建隧道），否则需先加隧道。

## 环境

- Python 3.8+；依赖：`paramiko==5.1.0`（必需）、`cryptography`（本地加密凭据必需，paramiko 通常已带入）、`questionary==2.1.1`（可选，仅用于图形菜单）。
- **无需预先安装依赖**：脚本首次运行会自动检测并在缺少时安装，详见「新机器自动检测与安装依赖」。
- 如需手动安装：`pip install -r requirements.txt`。

## 部署方式

同一份 `takeover.py` 分别上传到转发端和应用端两台机器（内容完全相同）。在每台机器上首次运行选角色；选一台作主控端集中管理。

```bash
python takeover.py init     # 选本机角色：1 relay / 2 app / 3 controller
```

所有管理命令都在主控端执行。密码首次交互输入（不回显），随后可加密保存到本机，后续操作自动读取，不再每次输入。

## 终端图形配置界面（推荐）

不用记命令，菜单直接显示 `1)`、`2)`… 编号：**输入数字即可定位到对应项，回车确认**，方向键照样可用，表单填写，全程中文：

```bash
python takeover.py ui      # 或直接运行 python takeover.py（无参数默认进入界面）
```

主菜单包含：服务器管理、转发规则管理、排除端口管理、验证配置、回滚转发端、设置本机角色、环境自检与依赖安装、同步状态、退出。密码首次交互输入后加密保存到本机，下次自动读取；如需禁用自动保存，可设置环境变量 `IP_TAKEOVER_NO_SAVE_CREDS=1`。界面无对外监听端口。若服务器未装 `questionary`，会自动降级为同功能的数字菜单。

菜单按角色自动裁剪：**主控端**显示完整管理菜单；**只读镜像端**显示「验证配置 / 从主控端拉取最新状态 / 本机排除端口管理 / 删除对端服务器（提交主控端执行） / 环境自检 / 退出」6 项。镜像端不直接改权威 state，而是把本机排除端口变更或删除请求提交给主控端执行，再刷新只读镜像，避免配置分叉。每次启动和每次返回菜单都会自动清屏，不留上一轮的选择历史。

> 传统命令行子命令仍然保留，二者等价，可按需使用。

## 本地加密保存密码（免重复输入）

按你的要求，密码现在可以加密落盘保存，而不是每次运行时重新输入：

```bash
python takeover.py cred save     # 从已配置服务器中选择，输入一次密码并加密保存
python takeover.py cred list     # 查看已保存的凭据索引，永不显示密码明文
python takeover.py cred clear    # 清空本机保存的全部密码
```

- 密文保存在脚本同目录 `credentials.enc`，随机密钥保存在 `credential.key`，两者权限均为 `600`。
- 加密使用 `cryptography` 的 Fernet（AES-128-CBC + HMAC-SHA256），不是简单编码或明文混淆。
- TUI/CLI 首次输入密码后会自动加密保存；后续启动、后台状态同步都会自动读取，不再弹密码提示。
- 如临时不想保存，可在运行前设置 `IP_TAKEOVER_NO_SAVE_CREDS=1`；此时仍仅内存缓存。
- 安全边界：这是“免输入”带来的明确折中——密码由“完全不落盘”变为“密文落盘”。请保证工具目录只对本机管理员可读，且不要把 `credential.key`、`credentials.enc` 外发或提交到版本库。

## SSH 私钥认证（推荐）

添加服务器时可选择填写 SSH 私钥路径：

```text
请输入 SSH 私钥路径（留空使用密码）：/root/.ssh/id_ed25519
```

- 填写后将优先使用私钥认证；私钥加载或认证失败时，如果提供了备用密码，会自动回退到密码认证。
- 备用密码可以留空；此时表示“仅用私钥”。留空时不会写入加密凭据库。
- `state.json` 只记录 `key_path` 路径，不记录私钥内容，也不记录明文密码。
- 支持 paramiko 可识别的常见私钥格式（RSA / Ed25519 / ECDSA 等）。

## 新机器自动检测与安装依赖

把 `takeover.py` 拷到一台全新的机器即可直接运行，不需要手工准备 Python 环境。脚本在真正加载第三方库之前会先做自举：

1. **pip**：依次尝试 `python -m pip` → `ensurepip` → 系统包管理器（`apt-get`/`dnf`/`yum`）→ 下载 `get-pip.py`（优先阿里云镜像，pypa 官方源兜底，下载后校验文件大小与语法完整性再执行）。
2. **paramiko**（必需）：缺失时自动安装 `paramiko==5.1.0`，安装失败则明确报错退出。
3. **cryptography**（必需）：缺失时自动安装，用于本地加密凭据；不会把密码明文写入任何文件。
4. **questionary**（可选）：缺失时自动安装 `questionary==2.1.1`，安装失败不影响命令行功能，仅降级为数字菜单。
5. **iptables**（转发端需要）：缺失时通过系统包管理器安装；`cron` 缺失时持久化会提示改用其他方式。

自举过程写入脚本同目录的 `bootstrap.log`（仅记录安装动作，不含任何凭据）。

自检与修复命令：

```bash
python takeover.py doctor          # 查看 pip/paramiko/questionary/iptables/cron 状态，缺什么装什么
python takeover.py doctor --fix    # 强制重新安装依赖，用于修复损坏环境
```

图形界面中对应主菜单项「环境自检与依赖安装」。

## 命令一览

```bash
# 服务器管理
python takeover.py server add relay        # 添加转发端（自动全量备份 iptables）
python takeover.py server add app          # 添加应用端
python takeover.py server list             # 列出服务器、启用状态、排除端口
python takeover.py server enable <id>      # 开启服务器：重下发其关联规则
python takeover.py server disable <id>     # 关闭服务器：撤销关联规则，保留配置
python takeover.py server remove <id>      # 删除服务器：撤销规则 + 双向联动清理

# 转发规则
python takeover.py rule add --mode transparent              # 透明转发：除排除端口外全部端口
python takeover.py rule add --mode mapped --map 80=8080,443=8443  # 指定端口映射
python takeover.py rule list
python takeover.py rule enable|disable|remove <id>

# 转发端排除端口（SSH 端口强制在内，不可移除）
python takeover.py exclude list <relay-id>                 # 查看：手动/自动排除、检测来源、当前生效排除集
python takeover.py exclude add <relay-id> 3306 8000-9000
python takeover.py exclude remove <relay-id> 3306
python takeover.py exclude auto <relay-id>                 # 【默认开启】立即检测转发端已监听端口并重新下发规则（保护原有业务）
python takeover.py exclude auto <relay-id> on|off          # 开启/关闭自动排除（默认开启）

# 出站身份接管（A 主动对外显示 B 的 IP）
python takeover.py egress status                                  # 查看出站配置与实际下发状态
python takeover.py egress setup <app-id> <relay-id> --mode all    # 全部出站经转发端（风险高，需确认）
python takeover.py egress setup <app-id> <relay-id> --mode targets --targets 1.2.3.0/24,10.0.0.0/8 \
       --via 10.0.0.2 --mgmt-nets 192.168.0.0/16                 # 推荐：仅指定目标经转发端，管理网段保留直连
python takeover.py egress enable --yes                            # 下发 SNAT + 策略路由（--yes 跳过确认）
python takeover.py egress disable --yes                           # 关闭并恢复原出口
python takeover.py egress set-scope --mode targets --targets 10.0.0.0/8  # 改范围；已启用时自动重新下发

# 回滚与验证
python takeover.py rollback <relay-id>     # 全量恢复到首次备份
python takeover.py verify                  # 验证两端 SSH、规则存在，并自动对命中端口做 HTTP 响应头对比
python takeover.py verify --probe-port 80  # 指定端口探测；不指定则从规则/常见端口自动推断

# 状态同步（主控端权威 → 各节点只读镜像）
python takeover.py sync                    # 主控端：广播状态到各节点；非主控端：从主控端拉取

# 本地加密凭据（保存一次，后续免输入）
python takeover.py cred save               # 选择服务器并保存密码
python takeover.py cred list               # 查看已保存索引，不显示密码
python takeover.py cred clear              # 清空已保存密码
```

规则生效条件：`规则启用 AND 应用端启用 AND 转发端启用`。

## 状态同步架构（两端一致）

遵循设计"状态文件只在主控端保存"：主控端 `state.json` 是**唯一真相源**，其他节点持有**派生的只读镜像**（带 `_mirror.source` 来源标记），不参与决策、不可写。

- **自动广播**：主控端每次状态变更（增删服务器/规则、开关、排除端口、回滚）保存后，立即把权威状态推送到所有节点；对端按自身角色生成镜像，界面标 `[只读镜像]`。
- **启动/手动拉取**：非主控端可用 `sync` 或界面「从主控端拉取最新状态」主动拉取，纠正任何漂移。
- **删除双向联动**：主控端删除服务器时，先撤销该服务器关联的全部规则（转发端 DNAT + 应用端放行），再移除本地实体并广播新状态，两端不留孤儿配置。
- 广播失败不回滚本地操作，但会明确告警；可用 `sync` 重试。

## 双向删除（A 可删 B，B 可删 A）

- **A（主控端）删 B**：在 A 的「服务器管理 → 删除服务器」直接执行，撤销关联规则并同步新状态。
- **B（镜像端）删 A**：在 B 的「删除对端服务器（提交主控端执行）」选择 A，B 通过 SSH 把删除请求提交给主控端 A；**由 A 执行真正的删除和双向联动清理**，再把新状态广播回 B。
- 这样两端都能删对端，但权威状态始终只有主控端一份，不会出现 A/B 各自改状态造成分叉。
- 命令行等价写法：`python takeover.py server remove <id> --yes`；`--yes` 用于跳过确认，便于远程自动化。

## 出站身份接管（V2.0：A 主动对外显示 B 的 IP）

入站接管解决"别人访问 B 的 IP → A 承接"，出站接管补齐目标的另一半："**A 主动对外访问 → 源 IP 显示为 B**"。两者共同构成"A 真正使用 B 的 IP"。

- **原理**：转发端 B 对来自应用端 A 的流量做 **SNAT** 成自己的公网 IP；应用端 A 新增**独立策略路由表 + ip rule**，把指定出站流量引向 B。**不改动主表默认路由**，`disable` 精确撤销、可完整恢复原出口。
- **前置条件（重要）**：A 与 B 需**二层可达**（同网段/VPC）。若两者仅公网互通，需先建隧道（如 WireGuard）并把它作为 `egress.via`。`egress enable` 会自动探测并在可能不通时告警，但**不阻断**（兼容你已手动建好隧道的情况）。
- **两种范围**：
  - `--mode targets`（**推荐**）：仅访问指定目标网段时经 B 出去，其他出站不受影响，风险低。
  - `--mode all`：A 的全部出站都经 B，B 成为单点与带宽瓶颈，需高优先级二次确认。
- **管理网保护**：`--mgmt-nets` 指定的网段（如运维网段）以更高优先级走主表直连，避免 SSH/管理流量被绕行导致失联。
- **下发前备份**：应用端会先把 `ip rule` 与全部路由表快照写到 `/root/egress.iprule.TAKEOVER.snapshot`（600），供人工回滚参考。
- **幂等与回滚**：反复 enable 会先按标记清旧规则再下发；`egress disable --yes` 撤销两端规则并恢复；转发端入站规则与出站 SNAT 分别用 `:egress` 标记独立管理，互不干扰。
- **验收方法**：在 A 上 `curl ifconfig.me`（或任意回显源 IP 的服务）应返回 **B 的 IP**；`egress disable` 后应恢复为 A 的 IP；期间入站访问 B:80 不受影响。
- **隧道模式（V2.0 增强）**：为支持非二层可达场景，`egress setup` 新增 `--src-ip`，让 A 出站包保持 A 公网 IP 作为源，从而命中 B 侧现有 SNAT；A 侧策略路由带 `src` 参数。11 项隧道 mock + 原有 86 项回归全通过。脚本已升至 3175 行（md5 `03ed05d5`）部署到 A/B。

> **真实下发结论（2026-11-23）**：出站代码与规则下发经核对全部正确（ip rule、table 105、B 侧 SNAT/FORWARD 均到位），但**当前云网络环境无法达成出站**。A/B 是两台不同公网网段 VPS（非二层可达），出站在该环境下依赖 WireGuard 隧道；实测该环境 UDP 连通性受限且不对称——A→B 仅 UDP 80 可达，B→A 虽端口探测显示可达但 WireGuard 数据回程始终不通（抓包铁证：A→B 零丢包，B→A 数据全丢，A 仅收到 92B 握手响应）。多端口、对称端口、精确 allowed-ips、隧道路由、rp_filter 等方案均尝试无果，判定为**云厂商网络层 UDP 单向/状态化限制，非脚本可绕过**。`ifconfig.me` 从 A 直连即超时（已换 `api.ipify.org`）。**出站实验已彻底回滚**：WireGuard 隧道删除、ip rule/table 105/B 侧 SNAT 全清、state.egress=None；**入站业务完好**（B 28 条 TAKEOVER 规则、B:80 ETag `etag-B-xxxx` 未受影响）。待云环境提供真正双向 UDP 或内网/VPN 可达后再下发。

## 转发端本机排除端口（B 可自行设置）

这是设计目标明确规定的能力：**转发端可自行决定哪些端口不转发，留在转发端本地处理**。

- B 的图形菜单中有「本机排除端口管理」，可查看、添加、移除排除端口。
- B 也可以直接用命令行：`python takeover.py exclude add|remove srv-relay-1 <端口...>`。
- B 提交后，变更由主控端 A 写入权威 state 并下发给 B 的 iptables，**不会造成 A/B 状态分叉**。
- SSH 端口 `22` 永远强制排除、不可移除；变更会自动重算该转发端所有规则。
- 已端到端验证：B 上添加 `65534` 后 A/B 状态一致包含该端口，移除后两端一致恢复，业务响应未变。

## 自动排除转发端已用端口（保护原有业务，默认开启）

透明转发默认转发"除排除端口外的全部端口"。如果转发端 B 上**已有服务在监听某个端口**（例如 B 自身的 80/443/3306），该端口的流量本应留在 B 本地处理；若被 DNAT 转发到 A，就会**劫持并破坏 B 的原有业务**。为此新增自动排除：

- **默认开启**：每个转发端的 `auto_exclude_enabled=true`。每次下发规则前，工具会 SSH 到 B 实时检测当前正在监听的 TCP/UDP 端口，自动并入排除集，**这些端口不会被转发**，B 的原有业务保持不变。
- **检测四级降级**：`ss -H -lntu` → `ss -lntu` → `netstat -lntu` → 直接读 `/proc/net/tcp{,6}` 与 `udp{,6}`（TCP 仅取 LISTEN，UDP 取所有绑定端口）。全部不可用时**中止下发**，宁可不转发也不误劫持业务端口。
- **实际排除集** = 手动排除端口 ∪ 自动检测端口 ∪ SSH 端口，去重后生成 iptables 表达式；映射模式下若映射端口已被 B 占用则拒绝下发并提示。
- **实测状态持久化与广播**：最近一次检测的端口与来源写入权威 state（`auto_excluded_ports` / `auto_exclude_source`），随自动广播同步到镜像端；`exclude list` 与图形菜单可查看。
- **手动操作**：`python takeover.py exclude auto <relay-id>` 立即重新扫描并重新下发；`exclude auto <relay-id> on|off` 开关（关闭后 B 已监听端口不再受保护，请谨慎）。图形菜单「排除端口管理」中有对应入口。
- **变更联动**：添加/启用规则、改排除端口、开关服务器时都会走实时检测，确保任何下发都不会劫持 B 上正在使用的端口。

> 安全取舍：自动排除优先保证"不破坏原有业务"。若你**确实希望**把 B 上某个已监听端口也转发到 A，请先停止 B 上占用该端口的服务，或改用端口映射模式并确认端口无冲突。

## 当前部署状态

> 主控端 state 为唯一真相源，应用端/转发端是自动同步的只读镜像（见「状态同步架构」）。界面管理操作仅在主控端可写，镜像端会拦截以防配置分叉。**主控端已迁到 A：`198.51.100.10`；日常只需要登录 A 操作，B 基本不用登录。**

已在两台测试服务器上完成配置，详见 `state.json` 与 `verification.json`：

| 项 | 内容 |
|---|---|
| 主控端 Controller | 198.51.100.10（日常操作端，权威 state） |
| 应用端 App | 198.51.100.10（业务端口 80/443，未做任何配置变更） |
| 转发端 Relay | 203.0.113.20（对外 IP，自动接收 A 的状态镜像） |
| 转发规则 | `tk-example01`：除排除端口外全部 TCP/UDP 端口 → 198.51.100.10 |
| 手动排除端口 | 22（SSH）、2096、32465、17817、33272（转发端自身管理面板） |
| 自动排除端口 | B 当前监听的 11 个端口：22、80、323、443、2096、11111、17817、32465、32587、33272、62789（**含 80/443，B 原有业务保留本地，不被转发**） |
| 首次备份 | 转发端 `/root/iptables.backup.TAKEOVER-20261120-152050`；本次部署前另备份 `iptables.backup.deploy-20261123-102857` |
| 持久化 | 转发端 `/root/ip-takeover-tool/restore.sh` 存在，但**两台当前均无 crontab 定时器**（重启后规则会丢失，待 D7 用 systemd 补齐） |
| 脚本版本 | A/B 均为 3160 行（含自动排除、V2.0 出站、3 项真实 bug 修复） |

### 2026-11-23 真实部署测试结果

交付前发现生产 state 曾被历史删除操作清空、iptables 无转发规则、B:80 实际显示 B 自身页面——**接管当时处于失效状态**。经确认后恢复 A 主控权威状态并下发规则，实测结果：

| 验证项 | 结果 |
|---|---|
| B 转发端规则 | 28 条 TAKEOVER 规则：11 端口×TCP/UDP RETURN 排除 + 通用 DNAT + MASQUERADE + FORWARD 放行 |
| B 已监听端口保护 | B:80 ETag=`etag-B-xxxx`（B 自身页面），**自动排除生效，原有业务未被劫持** |
| 未监听端口转发 | 临时在 A 起 18080 服务，从公网访问 `203.0.113.20:18080` 返回 A 的唯一标识，转发链路正常（测后已清理） |
| 两端状态一致 | A 权威与 B 镜像的自动排除集、来源（ss）、生效排除集完全一致 |
| 幂等性 | 重复下发两次，规则数稳定 28，RETURN 排除规则无累积 |
| verify | 两端 SSH 正常、规则存在、配置成功（80 因被排除，两端响应头不一致属预期） |

> 本次部署同时暴露并修复了 3 个 mock 未能发现的真实环境 bug：① `paramiko.connect` 参数名 `host`→`hostname`；② multiport 超限判断由"段数"改为"端口槽位数"；③ `delete_by_tag` 现可清理 `:excl`/`:appAllow` 子标记规则。详见 `verification.json`。出站下发与破坏性验收仍未执行。

### 2026-11-23 多端口端到端验证（A 使用 B 的 IP）

80/443 在这两台测试机上被 B 本地监听、被自动排除保护，只是**测试机的偶然占用**，不代表转发能力受限。因此另选 B 未监听、且不在排除集内的端口，从第三方视角（沙箱）实测 A 使用 B 的 IP 的完整入站转发能力：

| 验证项 | 测试端口 | 结果 |
|---|---|---|
| 多端口 TCP 转发 | 18080 / 18081 / 18082 | 三个端口均 HTTP 200，命中 A 唯一标识 `A-TAKEOVER-MARK` |
| Host 头透传 | 18080/18081/18082 | 自定义 `Host: takeover-test.example.com` 原样透传，未被 DNAT 改写；响应头 `X-Takeover-Marker` 正确 |
| UDP 转发 | 18083 | UDP echo 返回 `UDP-A-MARK`，UDP 转发可用 |
| 并发访问 | 18084 | 24 并发请求 **24/24 全部命中 A** |
| B 原有业务保护 | 80 | B 本地仍返回自身页面 ETag=`etag-B-xxxx`，未被劫持 |
| 环境清理 | — | A 上临时服务与文件全部清理；两端 state 一致、iptables 规则数未变（B 28 / A 1） |

> **结论**：A 使用 B 的 IP 的入站转发能力在任意未占用端口上完整可用（TCP + UDP + Host 透传 + 并发均通过）。转发的判定标准是"端口是否被 B 占用 / 是否被加进排除集"，与端口号是否为 80/443 无关。出站身份接管（A 主动对外显示 B 的 IP）代码已就绪，但改应用端路由有误断网风险，仍待授权后在低峰执行。

### 2026-11-23 A 本机使用 B 的 IP 验证

针对"A 在本地是不是已经可以使用 B 的 IP"的实测（端口 18085，不在排除集）：

| 访问视角 | 结果 |
|---|---|
| A 本机 `curl http://127.0.0.1:18085/` | 返回 A 服务标识（自检正常） |
| **A 本机 `curl http://203.0.113.20:18085/`** | **返回 A 服务标识 `LOCAL-VIEW-MARK`，EXIT=0 —— 通了**。A 本机访问 B 公网 IP 的流量经 B 的 PREROUTING DNAT 绕回 A，命中 A 自己的服务 |
| 第三方访问 `http://203.0.113.20:18085/` | HTTP 200 命中 A，Host 头 `third-party.example` 原样透传 |

> **结论**：除排除端口外，**A 已经可以在本地直接使用 B 的 IP**。规则方向核对无误：B 的 `PREROUTING DNAT → 198.51.100.10` + `POSTROUTING MASQUERADE`、A 的 `appAllow`（源 203.0.113.20）全部在位。测试临时服务已清理（残留进程 0）。
>
> 注意区分方向：以上属于**入站 DNAT**（别人 / A 自己访问 B 的 IP 落到 A）。A **主动对外**访问（如访问外部网站/API）时源 IP 仍是 A 自身，这属于出站 V2.0，尚未下发。

## 接管效果验证与常见问题

已做的深度验证（证据见 `verification.json`）：

- 从第三方机器带唯一标识访问 `http://203.0.113.20/`，应用端的 access.log 记录了来自 `203.0.113.20` 的请求，说明流量确实由应用端处理，而不是转发端自己响应。
- 经转发端带不同域名 `Host` 头访问，响应与应用端本机完全一致，说明 **Host 头被原样透传**，把域名解析到转发端后，应用端的多站点可以正确匹配。
- 应用端业务直接访问不受影响。
- `verify` 已增强：除两端 SSH 与规则存在检查外，还会对命中端口分别探测转发端与应用端的 HTTP 响应头（ETag / Server / Location / Content-Type），一致时提示「疑似已命中应用端」。若主控端与转发端同机，会提示本机请求走 OUTPUT 链、不经过 PREROUTING DNAT，结果仅作参考——真正的判定仍以第三方机器访问转发端公网 IP 为准。

以下情况会让你“看不到应用端的内容”，多数是测试方法或配置问题，不是转发失效：

1. **在转发端本机自测**：转发端自己也监听 80（openresty 默认站点）。本机发起的请求走 OUTPUT 链，不会经过 PREROUTING 的 DNAT，所以 `curl http://127.0.0.1/` 或在转发端上用自己的公网 IP 访问，看到的永远是转发端自己的默认页。**请从第三方机器测试转发端公网 IP。**
2. **用 IP 而不是域名访问**：此时 Host 头是转发端 IP，应用端会落到默认站点。若要看某个域名的站点，请用该域名访问，并把域名解析到转发端 IP；DNAT 会保留 Host 头。
3. **转发规则被关闭 / 删除 / 回滚**：DNAT 撤销后，转发端本地 80 服务会立即接管，显示它自己的默认页。关闭规则前请知悉这一点。
4. **HTTPS 证书告警**：TCP 层转发会保留 SNI，但证书是应用端域名的证书；用 `https://转发端IP` 访问会报域名不匹配。用域名（解析到转发端）访问则正常。
5. **源 IP 变成转发端**：经过 MASQUERADE 后，应用端看到的所有客户端 IP 都是转发端 IP（本例 `203.0.113.20`）。依赖真实客户端 IP 做限流、审计、地域判断的业务会全部归到转发端；DNAT 本身无法保留真实 IP，需要 TOA 或 PROXY protocol 配合。
6. **重启后规则丢失**：持久化依赖 crontab `@reboot` 执行 `restore.sh`；若 cron 未运行或脚本异常，重启后规则消失，会退回第 3 条的状态。可用 `doctor` 检查 cron。
7. **排除端口误配 / conntrack 满**：业务端口若被加进排除端口就不会转发；高并发下连接跟踪表满会丢包。可用 `iptables -t nat -L -n -v` 和 `cat /proc/sys/net/netfilter/nf_conntrack_count` 观察。

## 安全设计

- 凭据：输入不回显；运行时用 `bytearray` 暂存并清零，禁用 core dump。按你的要求新增本地加密保存：`credentials.enc`（密文）+ `credential.key`（随机密钥），均为 600；密码明文绝不写入 `state.json`、`audit.log`、`bootstrap.log` 或命令行参数。
- SSH：TOFU 主机密钥校验（首次记录指纹，变更即中止），专用 `known_hosts`（600）。
- 注入防护：`ipaddress` 严格解析 IP、端口强制整数范围、规则 ID 自动生成、命令参数化、无 `shell=True`。
- 防火墙：SSH 端口强制排除且不可移除；规则带 `TAKEOVER:<id>` 标记精确增删；变更前全量备份；FORWARD 链按目标收紧；排除端口变更自动重算（幂等）。
- 业务保护：下发前实时检测转发端已监听端口（ss/netstat/proc 四级降级）并自动排除，检测失败即中止下发，避免 DNAT 劫持原有业务端口；映射端口占用冲突直接拒绝。
- 端口范围确认：添加规则前明确列出将转发的端口表达式、排除端口与 SSH 强制排除说明；端口映射模式列出全部映射，需二次确认后才下发。
- 状态与审计：`state.json`、`audit.log`、`known_hosts` 均为 600，不含密码。
- 全中文界面；CLI 子命令名保留英文。

## 回滚

```bash
python takeover.py rollback <relay-id>
# 或直接在转发端：
iptables-restore < /root/iptables.backup.TAKEOVER-20261120-152050
```
