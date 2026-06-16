# HawkWing External Range AI Workbench

HawkWing is an AI-assisted workbench for authorized external cyber ranges, CTF-style exercises, and blue-team training where defenders practice attacker workflows in a controlled environment.

It helps operators import temporary range targets, scan and rank findings, review them manually, assess an execution plan, launch isolated runner containers, collect evidence, and generate a final report.

> Safety boundary: HawkWing is intended only for authorized labs, cyber ranges, and competitions. It does not ship malware/webshell generation, phishing kits, DDoS tooling, RAT frameworks, or automatic covert access deployment.

## 中文说明

鹰翼 HawkWing 是一个面向授权外部靶场、网络攻防比赛和蓝队实战化训练的 AI 辅助攻防工作台。平台默认不内置本地靶场，适合在比赛或演练开始后导入临时指定的外部靶场目标，并围绕“扫描发现、人工复核、执行前容器评估、人工批准、临时 Runner 容器执行、证据沉淀、报告生成”形成完整闭环。

核心能力：

- 目标导入：支持 IP、CIDR、URL 等临时靶场目标。
- 全流程可视化：目标、扫描、复核、计划、执行、证据、会话、报告阶段一屏展示。
- 漏洞排序：扫描结果按风险分、严重性、置信度组织，方便队员优先复核。
- AI 执行前评估：人工选择漏洞后，AI 先对题目、目标和漏洞进行初步分析，再推荐启动几个容器、使用哪类存量 Runner 镜像、是否需要动态 Runner 提案。
- 自动镜像准备：AI 推荐通过平台策略校验后，存量 Runner 镜像缺失会自动本地构建；允许的外部动态镜像可按策略自动拉取。
- 并行 Runner：每个渗透/验证任务使用临时容器隔离执行，结束后证据入库。
- 工具分层：主控 API 不堆叠攻击工具，工具主要放在 Runner 镜像和工具目录中，便于按题型维护。
- 状态与证据总线：Runner 输出、证据文件、授权会话引用、执行计划都统一进入项目状态。
- AI 配置入口：页面右上角可以配置 OpenAI、Claude、DeepSeek、自定义 OpenAI-compatible API，默认界面为中文，也支持英文切换。

安全边界：

- 本项目只适用于已授权靶场、CTF/攻防演练和教学环境。
- 项目不提供木马/免杀/钓鱼/DDoS/隐蔽持久化自动投放功能。
- 对代理、会话、凭据、权限验证等高风险内容采用人工审批和证据登记思路，避免平台变成不可控的自动化攻击器。

## Features

- Workspace and temporary target import
- Scan job orchestration
- Finding ranking and manual review
- AI-guided Execution Plan Assessment before launching containers
- Stock runner image library by challenge type
- Dynamic runner proposal policy with human approval
- Tool Catalog with risk levels and allow/approval/disabled states
- AI Skill / Runbook registry
- Shared state and evidence event bus
- Evidence indexing with SHA256
- Approved session/pivot reference registry
- Stage visualization for the full workflow
- Markdown report generation
- Runtime AI API configuration for OpenAI, Claude, DeepSeek, and custom OpenAI-compatible providers
- Chinese-first UI with English language switch
- Linux / WSL2 Docker Compose deployment

## Architecture

```text
Web Console
  -> FastAPI API
    -> PostgreSQL
    -> Redis / Celery
    -> Execution Planner
    -> Tool Catalog / Skill Registry
    -> Docker Runner Manager
      -> Temporary Runner Containers
        -> Evidence Artifacts
    -> Markdown Report
```

Core flow:

```text
Import targets
-> Scan
-> Review findings
-> AI analyzes challenge context and recommends runners
-> Assess execution plan and image policy
-> Approve plan
-> Auto-build stock runner images or pull allowed dynamic images
-> Launch runner containers
-> Collect evidence
-> Register approved sessions if needed
-> Generate report
```

## Runner Library

Stock runner profiles:

```text
runner-recon-basic              Reconnaissance and service discovery
runner-web-basic                Web crawl, content discovery, template validation
runner-web-advanced             Approved deeper web validation
runner-traffic-basic            Pcap and traffic analysis
runner-ad-basic                 Authorized Active Directory enumeration
runner-linux-privesc            Linux privilege escalation enumeration
runner-windows-privesc          Windows privilege escalation enumeration support
runner-forensics-basic          Memory, disk, firmware, and file forensics
runner-pwn-rev-basic            Pwn and reverse engineering support
runner-cloud-container-basic    Cloud, container, SBOM, and Kubernetes checks
runner-pivot-proxy              Approved session/pivot metadata support
runner-report                   Report conversion support
```

Configuration files:

```text
config/tool-catalog.yaml
config/runner-profiles.yaml
config/skill-registry.yaml
config/dynamic-runner-policy.yaml
config/evidence-bus-schema.yaml
```

## Quick Start

Linux or Windows WSL2:

```bash
cd hawkwing-workbench/deploy
cp .env.example .env
docker compose --profile build-runners build
docker compose up -d
```

Open:

```text
Web Console: http://localhost:3000
API Docs:    http://localhost:8000/docs
Health:      http://localhost:8000/api/health
```

中文快速启动：

```bash
cd hawkwing-workbench/deploy
cp .env.example .env
docker compose --profile build-runners build
docker compose up -d
```

启动后访问：

```text
主页面:   http://localhost:3000
API 文档: http://localhost:8000/docs
健康检查: http://localhost:8000/api/health
```

第一次进入页面后，点击右上角 `AI 未配置` / `AI 已配置` 按钮即可打开 AI 配置窗口。DeepSeek、OpenAI、Claude 官方地址会自动填充；如果使用中转服务或私有网关，请选择 `Custom` 并填写 Base URL。

To start only the control plane first:

```bash
cd hawkwing-workbench/deploy
cp .env.example .env
docker compose up --build
```

## AI API Configuration

Preferred method: open the Web Console and use the top-right AI configuration button.

Optional environment fallback: edit `deploy/.env`:

```env
AI_PROVIDER=openai
AI_API_BASE=https://api.example.com/v1
AI_API_KEY=replace-with-your-key
AI_MODEL=gpt-4.1-mini
AI_TIMEOUT_SECONDS=60
```

If no AI key is configured, the platform still runs with rule-based planning and placeholder summaries.

Provider defaults:

```text
OpenAI    https://api.openai.com/v1       gpt-4.1-mini
Claude    https://api.anthropic.com/v1    claude-3-5-sonnet-latest
DeepSeek  https://api.deepseek.com/v1     deepseek-chat
Custom    user supplied OpenAI-compatible Base URL and model
```

## Repository Layout

```text
apps/api       FastAPI backend, Celery workers, AI client, runner orchestration
apps/web       React/Vite web console
config         Tool catalog, runner profiles, skill registry, policies, templates
data           Local artifacts, reports, workspace data
deploy         Docker Compose deployment
docs           Architecture, deployment, user, and runner guides
runners        Stock runner image library
scripts        Helper scripts for Linux/WSL deployment
```

## Documentation

- [Architecture](docs/architecture.md)
- [Deployment](docs/deployment.md)
- [Advanced Orchestration](docs/advanced-orchestration.md)
- [Runner Plugin Guide](docs/runner-plugin-guide.md)
- [User Guide](docs/user-guide.md)
- [Full Chinese Project Description](项目全面说明.md)
- [GitHub Publish Checklist](docs/github-publish-checklist.md)

## Security Model

HawkWing uses:

- Human approval for high-risk runners and execution plans
- Tool risk levels and disabled categories
- Temporary runner containers instead of installing tools in the API container
- Evidence hashing and audit events
- Session registration rather than automatic covert channel deployment
- Dynamic runner policy checks before build/pull proposals

See [SECURITY.md](SECURITY.md) and [DISCLAIMER.md](DISCLAIMER.md).

## Current Status

This is a deployable project scaffold with advanced orchestration architecture. Some runner workflows are baseline placeholders and should be extended with authorized, competition-specific runbooks before production use.

## License

No open-source license has been selected yet. Before publishing publicly, choose a license that matches your intended sharing model. See `docs/github-publish-checklist.md`.
