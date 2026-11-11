# Sub App

[![CI](https://github.com/MinG-98/sub-app/actions/workflows/ci.yml/badge.svg)](https://github.com/MinG-98/sub-app/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

基于 FastAPI + Vue 3 的轻量节点订阅管理系统，用于集中维护代理节点、为不同用户分配节点、采集节点状态与流量，并生成 V2Ray/Shadowrocket/Clash 兼容的订阅内容。

代码开源以供参考；线上实例仅供本人个人使用，不开放注册，具体地址不在此公开。
管理台使用 Hash 路由，页面链接请保留 `/#/overview`、`/#/nodes` 等 `#/` 部分；`/nodes` 这类无 Hash 的直链不是管理页面入口。

## 目录

- [功能](#功能)
- [观测与拓扑](#观测与拓扑)
- [运维脚本与定时任务](#运维脚本与定时任务)
- [新节点一键接入](#新节点一键接入)
- [支持的订阅格式](#支持的订阅格式)
- [技术栈](#技术栈)
- [项目结构](#项目结构)
- [配置](#配置)
- [本地运行](#本地运行)
- [主要接口](#主要接口)
- [开发规范](#开发规范)
- [安全注意事项](#安全注意事项)
- [License](#license)

## 功能

- 管理代理节点：批量粘贴、启用/停用、排序、编辑和删除。
- 支持解析 `VLESS`、`VMess`、`Trojan`、`Hysteria2/Hy2` 和 `Shadowsocks` URI。
- 管理订阅用户：UID、备注、节点分配、启用/停用和订阅令牌轮换。
- 设备识别：根据订阅拉取请求记录设备指纹、User-Agent、IP、拉取次数和最近活动时间。
- 单独停用或删除设备，支持设备数量上限。
- 生成 Base64/V2Ray/Shadowrocket 原始订阅，以及 Clash/Mihomo YAML 配置。
- 仪表盘统计节点、用户、设备、24 小时拉取次数、活跃设备和最近拉取记录。
- 通过哪吒 API 采集节点在线状态、心跳、速度和 30 天内的节点流量历史。
- 为已适配节点维护用户级凭据状态；首批适配 Hysteria2 和 VLESS，旧凭据支持短暂兼容窗口。
- 通过独立采集脚本读取代理核心的用户级流量，并将哪吒整机流量与用户配额统计分开。
- 从管理机一键部署全新 Debian/Ubuntu Hy2 VPS/NAT 节点并注册 Agent；部署前只读预检，部署后核对中心心跳与应用版本。
- 为设备生成可撤销、可轮换的专属订阅访问标识，同时保留旧版 UA/IP 设备记录用于审计。
- 使用 SQLite 持久化数据；公开 `/healthz` 只提供最小存活状态，详细健康信息通过需要管理员登录的 `/api/admin/healthz` 查看。

## 观测与拓扑

- `/api/admin/overview/topology` 从当前分配关系生成管理拓扑，保留用户、节点和服务器三层关系。
- `/api/admin/latency` 与 `/api/admin/latency/probe` 提供受控的真实探测：控制面、节点入口 TCP 和代理出口分别记录；探测临时文件使用 root-only 权限，凭据不会写入状态文件或 API 响应。
- 仪表盘桌面端使用横向流量/活跃度柱状图；拓扑中的用户名在图外显示并稳定分色。`mobile-enhancements` 资源负责跨视口的品牌标记和紧凑布局。
- `/healthz` 只返回 `ok` 和时间戳，避免向未认证访问者暴露数据库、采集器、协调器和 Agent 详情；管理员登录后通过 `/api/admin/healthz` 获取完整状态。

## 运维脚本与定时任务

仪表盘和健康检查展示的采集/协调状态并非由应用自动刷新，而是由以下独立脚本写入 `/var/lib/sub-app/*.json` 状态文件，需要通过 cron 或 systemd timer 周期执行：

| 脚本 | 作用 | 关键环境变量（均有默认值，可省略） |
| --- | --- | --- |
| `scripts/nezha_collector.py` | 单次采集哪吒整机状态与流量 | `NEZHA_BASE_URL`、`NEZHA_API_TOKEN`（或写入 `NEZHA_ENV_FILE` 指向的文件，默认为 `/etc/sub-app/nezha.env`） |
| `scripts/proxy_collector.py` | 单次采集 Hysteria2/VLESS 用户级流量计数器 | `SUB_APP_VLESS_STATS_BINARY`（默认 `/usr/local/libexec/sub-app-vless-stats`）、`SUB_APP_PROXY_STATUS` |
| `scripts/reconciler.py` | 将用户分配与本机代理适配器配置做最终一致性协调（新增/轮换/吊销凭据的重试循环） | `SUB_APP_PROXY_ADAPTERS_ENV`（默认 `/etc/sub-app/proxy-adapters.env`）、`SUB_APP_RECONCILER_STATUS` |
| `scripts/latency_probe.py` | 触发一次真实延迟探测（控制面/节点入口/代理出口） | `SUB_APP_LATENCY_STATUS`、`SUB_APP_LATENCY_LOCK`、`SUB_APP_HYSTERIA_BIN`、`SUB_APP_SING_BOX_PROBE_BIN` |

生产服务启动前会检查 `SUB_APP_DB` 指向的数据库。已有应用表但两张核心表都没有记录时，默认拒绝启动，以免误把空库当成正式数据；只有在明确创建全新空实例时，才可临时在 `/etc/sub-app/app.env` 设置 `SUB_APP_ALLOW_EMPTY_DB=1` 完成首次初始化，确认数据已创建后应移除此项。

延迟探测通常由仪表盘按需触发（`POST /api/admin/latency/probe`），无需单独定时；其余三个脚本建议用 systemd timer 定期执行，例如：

仪表盘触发探测时，`/api/admin/latency/probe` 用当前运行 FastAPI 进程的解释器去启动 `scripts/latency_probe.py`（即 `sys.executable`），所以正常情况下不需要单独配置。仅当你想让它用另一个解释器（比如手动跑的场景与服务进程的 venv 不一致）时才需要设置 `SUB_APP_PYTHON` 覆盖。

```ini
# /etc/systemd/system/sub-app-nezha-collector.service
[Service]
Type=oneshot
User=sub-app
EnvironmentFile=/etc/sub-app/app.env
ExecStart=/opt/sub-app/.venv/bin/python /opt/sub-app/scripts/nezha_collector.py

# /etc/systemd/system/sub-app-nezha-collector.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

`proxy_collector.py` 和 `reconciler.py` 可按相同方式配置各自的 `.service`/`.timer`，运行间隔按节点数量和流量精度需求调整。

`scripts/pilot_hysteria_client.py` 与 `scripts/pilot_vless_client.py` 是一次性人工诊断脚本，用于在排查某个节点握手问题时手动运行，不应加入定时任务。

节点 Agent（`agent/` 目录，独立于以上中心侧脚本）的部署方式见 [agent/README.md](agent/README.md)。

节点的 `adapter_kind` 是显式持久化配置，不再以数据库自增 ID 决定适配器。新建节点默认 `shared`；管理员可在节点编辑页将其设为 `remote_agent`、`local_hy2` 或 `local_vless`，后两者分别绑定本机唯一的 HY2/VLESS 适配器。SQLite v5 迁移仅对实际存在且协议匹配的旧 ID 一次性回填，缺失或协议不匹配的记录保持 `shared`，不会新建节点或改动分配。

## 新节点一键接入

针对**全新的 Debian/Ubuntu VPS 或 NAT 小鸡**，可以从已验证管理机运行 `scripts/bootstrap_node.py`：先只读检查 SSH 主机身份、目标机空闲情况、TLS 材料、端口和美国控制面的健康状态；确认后加 `--apply` 安装固定摘要校验的 Hysteria2 和本项目 Agent，自动按两位序号、地区旗帜/名称和 `Hy2` 协议后缀生成规范节点名，创建节点并注册 Agent。订阅 URI 的名称始终由管理面板节点名生成，所以 Clash 与 V2Ray/小火箭订阅显示一致，即使旧 URI 缺少名称片段也不例外。最终验收要求收到新鲜且 generation 匹配的心跳，并用本地 Hy2 认证验证控制面凭据确已下发。

示例、证书/端口映射准备、失败处理和支持边界见 [新节点部署手册](deploy/NEW-NODE.md)。脚本不会接管现有 Xray/sing-box/Hy2 服务器，不会修改 SSH、系统防火墙、提供商 NAT 映射或 DNS，也**不会给新节点分配用户**。未提供 `--client` 执行公网客户端探测时，成功输出不代表公网代理链路已验证。VLESS/Xray 新机自动部署目前不支持。

订阅公告使用独立的 `announcements` 与 `announcement_allocations` 表，不参与节点采集、探测、适配器和流量统计；公告仍按订阅格式输出兼容的提示条目。SQLite v14 迁移旧版本明确生成的端口 1 占位 URI；v16 幂等核验端口 1，并补迁移同一全零 UUID / `127.0.0.1` 的端口 2、3 占位 URI，严格检查端口边界后复制原有用户分配。旧 Node 行和原分配记录保留作兼容核对，不会因迁移级联删除。

远程 Agent 注册使用 `POST /api/admin/agents`，明文 token 仅返回一次且响应禁止缓存；注册不会启用用户级凭据。节点侧配置需要由操作者按实际服务名、代理引擎和配置路径补齐，不能仅从订阅 URI 推断。轮换先生成 24 小时有效的观察 token，旧 token 继续有效；新 token 成功心跳后由管理员确认切换，确认后旧 token 即失效。完整节点侧字段见 [agent/README.md](agent/README.md)。

## 支持的订阅格式

订阅接口由 `target` 参数选择输出格式：

- `v2ray`、`base64`、`shadowrocket`：将原始节点 URI 按行编码为标准 Base64；`shadowrocket` 是给小火箭使用的明确格式入口。
- `raw`：按行输出原始节点 URI。
- `clash`、`clashmeta`、`mihomo`：输出包含代理、自动测速组和节点选择组的 YAML。

实际订阅地址由系统为每个用户生成，不要把包含用户令牌的完整订阅链接提交到 Git 或公开分享。

## 技术栈

- Python 3.10+
- FastAPI / Uvicorn
- SQLAlchemy + SQLite
- itsdangerous 会话签名
- PyYAML
- Vue 3 + Vite 前端（源码见 `frontend/`，线上使用构建后的静态 JS/CSS 资源）
- httpx（哪吒 API 和本地采集器）

## 项目结构

```text
.
├── app/
│   ├── converter.py   # 节点 URI 解析与订阅格式转换
│   ├── credentials.py # 用户节点凭据的派生、加密和脱敏输出
│   ├── proxy_adapters.py # Hysteria2/VLESS 代理适配器
│   ├── traffic.py     # 哪吒采集和流量增量归一化
│   ├── agent_api.py   # 节点 Agent 接入
│   ├── main.py        # FastAPI 应用、管理 API 和订阅接口
│   └── models.py      # SQLAlchemy 数据模型
├── scripts/           # 采集/同步脚本与新节点一键接入入口
├── deploy/
│   ├── NEW-NODE.md    # 新节点准备、端口/TLS、验收和故障处理
│   └── bootstrap_worker.py # 仅经 SSH 在目标新机运行的安装工作进程
├── frontend/          # 管理界面源码（Vue 3 + Vite，构建产物输出到 static/）
├── static/
│   ├── index.html     # 管理界面入口（由 frontend/ 构建生成，不要手改）
│   └── assets/        # 前端构建产物
├── .github/
│   ├── workflows/ci.yml          # lint、格式检查和测试
│   └── pull_request_template.md
├── requirements.txt       # 运行依赖
├── requirements-dev.txt   # 运行依赖 + ruff/black/pytest
├── pyproject.toml         # ruff/black 配置
├── .pre-commit-config.yaml
├── .gitignore
└── README.md
```

运行时的 `.env`、SQLite 数据库、虚拟环境和缓存目录不属于源代码，均由 `.gitignore` 排除。

## 配置

启动前必须设置以下环境变量：

| 变量 | 作用 |
| --- | --- |
| `SUB_APP_ADMIN_PASSWORD` | 管理后台登录密码 |
| `SUB_APP_ADMIN_USERNAME` | 管理台显示的管理员名称，默认为 `admin` |
| `SUB_APP_SECRET` | Cookie 会话签名密钥，应使用随机长字符串 |
| `SUB_APP_SESSION_MAX_AGE` | 管理会话有效期秒数，默认 8 小时 |
| `SUB_APP_DB` | SQLite 数据库路径；文件数据库必须使用绝对路径；不设置时默认为项目根目录下的 `data.db` |
| `SUB_APP_PUBLIC_BASE` | 生成订阅链接时使用的公网基地址 |

示例（请替换所有占位值，不要把真实值写入仓库）：

```bash
export SUB_APP_ADMIN_PASSWORD='change-this-password'
export SUB_APP_ADMIN_USERNAME='admin'
export SUB_APP_SECRET='generate-a-long-random-secret'
export SUB_APP_SESSION_MAX_AGE='28800'
export SUB_APP_DB='/var/lib/sub-app/data.db'
export SUB_APP_PUBLIC_BASE='https://your-domain.example'
```

## 本地运行

```bash
git clone https://github.com/MinG-98/sub-app.git
cd sub-app

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

export SUB_APP_ADMIN_PASSWORD='change-this-password'
export SUB_APP_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export SUB_APP_DB="$PWD/data.db"
export SUB_APP_PUBLIC_BASE='https://your-domain.example'

uvicorn app.main:app --host 127.0.0.1 --port 8080 --no-access-log
```

数据库表会在应用首次启动时自动创建。正式部署时建议让 Caddy、Nginx 或其他反向代理负责 HTTPS，并将 Uvicorn 仅绑定在回环地址或受控内网地址。

### 前端开发

管理界面源码在 `frontend/`（Vue 3 + Vite），构建产物直接输出到 `static/`，由 FastAPI 在 `/` 和 `/static` 提供服务：

```bash
cd frontend
npm ci
npm run dev     # 本地开发，通过 vite 代理转发 /api、/sub、/healthz 到 127.0.0.1:8080
npm run build   # 会清理并覆盖 ../static，仅用于明确的发布构建
```

`npm run dev` 默认将 API 请求代理到 `http://127.0.0.1:8080`（对应上一节的本地运行命令），需要本地已启动后端。常规开发和 CI 应把构建输出到临时目录；不要因此自动覆盖或提交 `static/`。CI 会将同一提交的后端源码与临时目录构建出的前端 `static/` 组装为保留 7 天的 GitHub Actions artifact；这只是未部署的发布候选，不会发布到生产或更新仓库 `static/`。下载后仍须先做 UI 验收并核实目标机的路径、环境文件、数据库和回滚方案。

`deploy/systemd/sub-app.service` 是单机参考单元：假设代码安装在 `/opt/sub-app`、运行账号为 `sub-app`、环境文件为 `/etc/sub-app/app.env`、反向代理连接 `127.0.0.1:8080`；Uvicorn 使用单 worker，状态目录为权限受限的 `/var/lib/sub-app`，并关闭会记录 `/sub/{token}` 路径的访问日志。部署前须确认 `SUB_APP_DB` 等变量指向现有生产数据，而不是让新服务意外创建一份空数据库。此模板未在生产启用，也不替代现有 HTTPS 代理与定时采集服务。

`deploy/systemd/sub-app-backup-root.service` 使用同一环境文件中的 `SUB_APP_DB` 和仓库脚本 `/opt/sub-app/scripts/backup_db.py`；该 root 变体只授予 `CAP_DAC_READ_SEARCH` 以读取受限应用数据库，备份写入独立的 `/var/lib/sub-app-backup`。常规 `sub-app-backup.service` 则以应用账号运行。两者均只生成同机副本，异地备份与恢复演练仍需另行配置。

本机 VLESS 同步不要求 Web 服务获得 root 或 `/etc/sing-box-reality` 写权限。需要将 `scripts/vless_sync_helper.py` 安装为 root 所有的 `/usr/local/libexec/sub-app-vless-sync-root.py`，安装 `deploy/systemd/sub-app-vless-sync.socket` 与 `sub-app-vless-sync@.service` 后启用 socket。Unix socket 仅开放给 `sub-app` 组；root helper 固定只改 `reality-in` 的 VLESS 用户列表、固定执行 sing-box 校验及 `sing-box-reality.service` 重启，并在失败时恢复原配置。不要给 Web 服务配置通用 sudo、shell 或任意路径写入权限。

## 主要接口

| 接口 | 说明 |
| --- | --- |
| `GET /` | 管理后台页面 |
| `GET /healthz` | 公开最小存活检查，不返回内部组件详情 |
| `GET /api/admin/healthz` | 管理员登录后查看数据库、采集器、协调器、Agent 和适配器详情 |
| `GET /api/admin/audit-logs?limit=100` | 查看最近的成功管理员写入操作元数据（最多 250 条） |
| `POST /api/admin/login` | 管理员登录 |
| `/api/admin/nodes` | 节点增删改查 |
| `/api/admin/nodes/{id}/traffic` | 节点流量曲线和时间范围汇总 |
| `POST /api/admin/agents` | 为已设为 `remote_agent` 的节点一次性签发 token |
| `/api/admin/agents/{id}/rotate` | 分阶段轮换或取消 Agent token |
| `/api/admin/collector/status` | 哪吒、代理流量和节点 Agent 采集状态 |
| `/api/admin/friends` | 订阅用户增删改查 |
| `/api/admin/devices` | 设备记录管理 |
| `GET /api/admin/stats` | 统计和最近拉取记录 |
| `GET /sub/{token}` | 生成订阅内容，使用 `target` 选择格式 |

除公开最小存活检查和订阅接口外，管理接口需要登录 Cookie。订阅响应显式设置 `private, no-store`；订阅令牌本身等同于访问凭据，应按密码处理。

## 开发规范

```bash
python -m pip install -r requirements-dev.txt
pre-commit install   # 可选：提交前自动跑 ruff/black 和基础检查
```

- 代码风格由 [black](https://black.readthedocs.io/) 统一格式化，静态检查用 [ruff](https://docs.astral.sh/ruff/)；配置见 `pyproject.toml`。
- 提交前建议本地跑一遍：

  ```bash
  ruff check .
  black --check .
  pytest -q
  ```

- GitHub Actions（`.github/workflows/ci.yml`）在每次 push/PR 到 `master` 时执行同样的检查，PR 请保持 CI 全绿再合并。
- CI 也会运行前端测试和 Vite 生产构建（构建到临时目录，不覆盖仓库 `static/`）；`static/` 仍是 FastAPI 当前直接服务的运行资产，CI 只验证其入口引用有效文件，不代表它与源码构建内容一致。生产发布应使用经 UI 验收的构建产物，不能把 CI 成功当成已部署或视觉验收。
- PR 请使用 `.github/pull_request_template.md` 中的 Summary/Test plan 结构描述改动。

## 安全注意事项

- 不要提交 `.env`、`data.db`、订阅令牌、节点 URI、密码、私钥或其他运行时凭据。
- 哪吒 Token、代理适配器密钥和节点配置应通过 VPS 上的 root-only 环境文件注入，不写入仓库、数据库或页面。
- 管理密码和 `SUB_APP_SECRET` 应使用随机且互不重复的值，并通过服务管理器或安全的环境文件注入。
- 生产环境必须使用 HTTPS；应用设置的会话 Cookie 启用了 `HttpOnly`、`Secure` 和 `SameSite=Lax`，默认有效期为 8 小时。
- 应用会为管理页和 API 添加 HSTS（仅 HTTPS 请求）、CSP、`nosniff`、`Referrer-Policy` 和禁止 iframe 嵌入等响应头；反向代理应正确转发 `X-Forwarded-Proto`。
- 限制管理后台的公网访问范围，并定期轮换暴露过的管理员密码、会话密钥和订阅令牌。
- 管理员登录在 SQLite 中按 ASGI 对端地址持久化失败次数，默认 15 分钟内 8 次失败后暂时锁定 15 分钟；仅在可信代理配置正确时才应让 Uvicorn 解析转发地址，应用不会直接信任请求中的 `X-Forwarded-For` 或 `CF-Connecting-IP`。登出会在服务端撤销对应会话；管理员凭据变更会轮换持久化会话纪元，因此即使之后恢复旧密码，旧 Cookie 也不会复活。数据库仅保存会话 ID 的 HMAC 摘要，不保存 Cookie 原文。
- 已认证管理员的成功写入操作会记录到只追加的 `admin_audit_logs` 表，可通过 `GET /api/admin/audit-logs` 查看；仅记录会话指纹、方法、路径和状态码，不记录请求正文或凭证值。因管理员仍共用一个账号，该指纹只能区分会话，不能证明具体操作者；失败尝试和字段级前后值目前不在该日志范围内。
- SQLite 数据库包含用户、设备、IP、User-Agent 和拉取记录，应设置合适的文件权限并纳入独立备份。
- SQLite 文件数据库启动时启用 WAL；管理健康页会报告运行时 SQLite 版本，并对尚未确认包含 WAL-reset 修复的版本显示警告（发行版可能有回补，需按实际构建核实；参考 [SQLite WAL 文档](https://www.sqlite.org/wal.html)）。不要直接复制仍在运行的 `.db` 文件；使用 `scripts/backup_db.py` 的在线备份（包含已提交的 WAL 数据），它会验证 `quick_check`、以 `0600` 保存快照，并仅按配置清理专用备份目录中超过保留期的 `sub-app-backup-*.sqlite3`。应用与备份服务都必须显式配置 `SUB_APP_DB`，指向绝对路径下已初始化且服务账号可写的数据库；应用 systemd 模板会在启动前拒绝空库或错库。直接运行备份脚本时，默认目录为 `/var/backups/sub-app`；systemd 备份单元使用受限的 `/var/lib/sub-app-backup`（由 `StateDirectory` 创建），默认保留 30 天。该脚本只生成同机备份，异地副本和恢复演练仍需由部署环境单独配置。

## License

本项目采用 [MIT License](LICENSE)。
