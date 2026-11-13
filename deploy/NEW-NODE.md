# 从管理机一键接入一台全新的 Hy2 VPS

入口：仓库根目录的 `scripts/bootstrap_node.py`。控制面固定为美国 VPS 的
`https://sub.m1n6.uk`，使用现有管理员与 Agent API，不需要部署新版后台、修改 UI 或直接操作生产数据库。
一台新机创建一个**原生 Hysteria2 + Agent**；不迁移存量服务，不分配用户，不自动开启独立凭据。

## 先准备什么

- 管理机：Python 3.10+、OpenSSH、SUB 管理员登录权限。通过提供商控制台独立核对新机 SSH 指纹，把已验证的主机密钥放入当前账户的 known_hosts；非 22 端口使用 `[host]:port` 记录。脚本不接受未知指纹，不使用 SSH 别名，也不转发 SSH agent。
- 新机：空白 Debian 12+ 或 Ubuntu 22.04+、systemd、root 公钥登录、系统自带 `/usr/bin/python3`（3.10+）、apt、OpenSSL、CA 根证书。支持 amd64 / arm64 和 IPv4；Alpine/OpenRC、IPv6-only、已运行 Xray/sing-box/Hy2 的机器不适用。下载及安装需要至少 150 MiB 可用磁盘。极低内存小鸡还需单独评估运行余量。
- NAT 面板/防火墙先放行 **公网 UDP → 本机 UDP**。SSH、Hy2、签证书用的端口互相独立；控制面只需出站 HTTPS。脚本不改 SSH、防火墙、端口映射、DNS 或系统网络参数。目标机还需能访问软件源和 GitHub 发布物。
- TLS 二选一：① 目标已有公网信任的完整证书链与匹配私钥，均在目标机 `/etc/` 下，并有自己的续期方案；② 新域名已解析到本机且公网 **TCP 80 → 本机 80**，使用 `--acme-email` 让 Hy2 通过 HTTP-01 申请/续期。只有 UDP 的 NAT 机请选择①，例如提前用 DNS-01 签发证书。不要传私钥内容、订阅 token 或管理员密码作为参数。

## 一条命令

以下全部是示例地址。先不加 `--apply` 做只读预检，通过后在同一条命令末尾加 `--apply`。管理员密码只在本地终端提示时输入；远端只收到本节点的 token。

```sh
python3 scripts/bootstrap_node.py \
  --region SG --ssh-host 203.0.113.20 --ssh-port 23900 \
  --identity "$HOME/.ssh/new_vps_key" \
  --public-host 203.0.113.20 --public-port 28443 --listen-port 8443 \
  --sni hy2.example.net \
  --cert /etc/letsencrypt/live/hy2.example.net/fullchain.pem \
  --key /etc/letsencrypt/live/hy2.example.net/privkey.pem
```

名称由 SUB 已有最大两位节点序号自动递增；例如当前最高序号是 `15`，新加坡 Hy2 会显示为 `16｜🇸🇬 新加坡 Hy2`。支持的地区代码：`DE`、`HK`、`JP`、`KR`、`MY`、`SG`、`US`。同一控制面请串行运行部署，避免两个并发新节点争用序号。

订阅生成时始终把管理面板的节点名写入 URI 的标准名称片段；现有 URI 片段为空或过期，也会在 raw、V2Ray/小火箭 Base64 与 Clash/Mihomo 订阅中显示管理面板的规范名。数据库内原 URI 不会被批量改写。

直连 VPS 自动签证书：用 `--acme-email ops@example.net` **替换** `--cert`、`--key`。推荐再加 `--client /实际路径/hysteria`，提供管理机可信的 Hysteria 2 客户端和 curl。这样验收会从管理机经公网 UDP 入口发送一次代理 HTTPS 请求至 `https://example.com/`；失败就隔离新节点。不传客户端，只报告“控制面/本机已验证”，**不证明**供应商 NAT、外部客户端网络或实际订阅可用。

## 安装边界与验收

1. SSH 预检目标机、代理进程/常用 unit 与路径、UDP/回环端口、证书或 ACME 条件、目标机到中心的 HTTPS 健康检查。检测不是全系统资产清单，勿把有业务的机器当新机。
2. 中心拒绝同名或同 Hy2 公网端点；使用独一份临时名称确认新记录 ID，并立即停用、设为 `remote_agent`、签发 token。现有创建 API 默认启用，创建和停用不是单个事务；此时没有用户分配。请勿并发部署同一端点，也不要在安装中途分配用户。若创建后 API 断线且未拿到 ID，先按终端打印的临时名查后台。
3. SSH 标准输入传送安装数据。Hy2 固定版本并校验该架构的 SHA-256；如果缺少 PyYAML，仅用发行版 apt 安装。专属目录 `/opt/sub-app-new-node` 为 0700，Agent 配置为 0600。只写 `sub-app-new-hy2.service` 和 `sub-app-new-agent.service` 两个专属 unit；认证与流量接口仅绑定回环。启动时无有效凭据即拒绝连接。
4. 等停用配置收到新鲜且版本一致的心跳，才启用；再等一个**不同的**已应用版本，并验证本机 Hy2 统计接口与 Agent 对新凭据的认证。可选外部拨测通过后才报告出口成功。先给 TEST 用户分配、拉取订阅并实测，再决定是否打开独立凭据并扩大分配。脚本不代替 Clash / 小火箭的客户端验收。

## 失败与退出

- 已取得 ID 的失败：尽力在中心停用**仅本次新建的节点**；安装开始后只停止/禁用标记匹配的两项新服务。断网、强制杀进程、系统关机不能保证两边同步回滚。未确认时有明确提示，核对后台 ID、状态以及新机两个 unit；**不要**重复执行、盲删记录或轮换全站 token。
- 只保留专属目录、日志和失败记录用于恢复；不删除现有软件包、已有证书或后台数据。成功后重复运行也会拒绝覆盖，不会二次发 token。若要拆除，在确认主机及安装标记后先停用节点，核对订阅分配，再停这两个 unit，撤销该节点 Agent token。不要公开配置、状态文件或备份。
- 诊断先看 `systemctl is-active sub-app-new-hy2.service sub-app-new-agent.service` 和后台该节点最近心跳；若本机认证通过但公网失败，对照面板的 UDP 映射、证书名和公网防火墙。不要把日志原样发到公共渠道。

参考：[官方 Hy2 服务端 TLS/ACME 配置](https://v2.hysteria.network/docs/advanced/Full-Server-Config/#tls)、[固定发布版本](https://github.com/HyNetworks/hysteria/releases/tag/app%2Fv2.13.0)。
