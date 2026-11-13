# 贡献指南

感谢你关注 SUB。这个项目是一个自托管的 FastAPI + Vue 3 节点订阅管理
系统，贡献前请先了解它的安全边界：仓库只保存源代码和脱敏文档，个人部署的
数据库、环境变量、节点配置和订阅凭据不属于贡献内容。

## 开始前

1. 先搜索已有的 Issue 和 Pull Request，避免重复工作。
2. 对较大的功能或涉及数据模型、认证、代理核心配置的改动，先开 Issue 说明
   目标、影响范围和回滚方案。
3. 不要在公开讨论中粘贴管理员密码、`SUB_APP_SECRET`、哪吒 Token、Agent
   Token、节点 URI、UUID、订阅链接、真实 IP 或包含个人信息的日志。

## 本地环境

后端需要 Python 3.10+，前端需要 Node.js 和 npm：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt

cd frontend
npm install
```

本地运行所需环境变量和后端启动方式见 [README.md](README.md) 的“配置”和
“本地运行”章节。请使用测试用的随机密钥和本地数据库，不要连接个人生产数据。

## 开发与验证

后端改动提交前至少运行：

```bash
ruff check .
black --check .
python -m compileall -q app scripts agent/node-agent.py agent/tests tests
pytest -q
```

前端改动提交前运行：

```bash
cd frontend
npm test
npm run build -- --outDir /tmp/sub-ui-build
```

构建应写入临时目录，不要因开发或 CI 而覆盖或提交仓库中的 `static/`。
CI 会从同一提交将前端构建结果与应用源码组装为短期发布候选 artifact；
它不会自动部署。发布前先验收该 artifact 的界面，并确认目标机器、数据库、
环境文件、备份及回滚方案。不要手工修改生成后的 CSS/JS 来替代源码修改。

涉及 API、认证、订阅转换、凭据或代理适配器的改动，应补充或更新测试，并说明
兼容性、旧凭据保留策略和回滚方式。涉及节点配置的操作必须与 UI/文档改动分开，
不要把个人 VPS 配置或生产数据库提交到仓库。

## 分支和提交

- 从 `master` 创建描述清晰的短期分支，例如 `codex/fix-issue-template`。
- 每个提交尽量只解决一个主题，提交信息使用简短的动词开头描述。
- 提交前检查 `git status`，确认没有 `.env`、数据库、缓存、密钥或临时文件。
- 不要重写他人正在使用的分支历史。

## Pull Request

Pull Request 请使用仓库提供的模板，至少写清楚：

- 改了什么，以及为什么改。
- 影响哪些页面、接口、数据或部署步骤。
- 本地运行过哪些验证命令及结果。
- 是否需要数据库迁移、配置变更、服务重启或回滚。
- 是否存在尚未验证的风险、兼容性限制或后续工作。

提交 PR 后请等待 CI 通过。维护者可能要求拆分过大的改动、补充测试或完善
安全说明；未获明确同意前，不要合并或强推到默认分支。

## Issue 报告

Bug 或功能建议请使用对应的 Issue 模板。描述问题时尽量提供：复现步骤、预期
行为、实际行为、版本/提交号和已经执行的检查。所有日志、截图和配置片段都要
先脱敏。

安全漏洞不要公开提交 Issue，请遵循 [SECURITY.md](SECURITY.md)。
