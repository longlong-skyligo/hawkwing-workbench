# 部署说明

## 1. 环境要求

推荐：

```text
Ubuntu Server 24.04 LTS
Docker Engine 29.x
Docker Compose Plugin
CPU 8 核以上
内存 16 GB 以上
磁盘 500 GB SSD
```

Windows 用户建议使用 WSL2：

```text
Windows 11
WSL2 Ubuntu 24.04
Docker Desktop 或 WSL 内 Docker Engine
```

## 2. 启动步骤

```bash
cd hawkwing-workbench/deploy
cp .env.example .env
docker compose --profile build-runners build
docker compose up
```

如果只想先验证控制台、API、数据库和任务队列，可以先不构建全部 Runner：

```bash
docker compose up --build
```

完整比赛环境建议提前构建并缓存全部存量 Runner 镜像：

```bash
docker compose --profile build-runners build runner-recon-basic runner-web-basic runner-web-advanced
docker compose --profile build-runners build runner-traffic-basic runner-ad-basic runner-forensics-basic
docker compose --profile build-runners build runner-linux-privesc runner-windows-privesc runner-pwn-rev-basic runner-cloud-container-basic
docker compose up
```

访问：

```text
Web 控制台：http://localhost:3000
API 文档：http://localhost:8000/docs
健康检查：http://localhost:8000/api/health
```

## 3. 配置 AI API

编辑 `deploy/.env`：

```env
AI_PROVIDER=openai-compatible
AI_API_BASE=https://api.example.com/v1
AI_API_KEY=replace-with-your-key
AI_MODEL=gpt-4.1-mini
AI_TIMEOUT_SECONDS=60
```

验证：

```bash
curl http://localhost:8000/api/ai/config
```

## 4. Runner 镜像说明

平台现在包含存量 Runner 镜像库：

```text
runner-recon-basic
runner-web-basic
runner-web-advanced
runner-traffic-basic
runner-ad-basic
runner-linux-privesc
runner-windows-privesc
runner-forensics-basic
runner-pwn-rev-basic
runner-cloud-container-basic
runner-report
```

要求保持输出：

```text
/out/result.json
/out/timeline.json
/out/commands.log
/out/evidence/
```

工具目录、Runner Profile、AI Skill 和动态镜像策略分别位于：

```text
config/tool-catalog.yaml
config/runner-profiles.yaml
config/skill-registry.yaml
config/dynamic-runner-policy.yaml
```

注意：部分工具需要在构建镜像时访问外部软件源或 GitHub。离线比赛环境应提前构建镜像并导入目标环境。

## 5. 数据目录

```text
data/artifacts  任务证据
data/reports    Markdown 报告
data/workspaces 工作空间中间数据
```

## 6. 停止服务

```bash
docker compose down
```

清理数据库卷：

```bash
docker compose down -v
```
