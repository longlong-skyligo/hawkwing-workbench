# 架构说明

HawkWing 使用模块化单体后端 + Celery Worker + 临时 Docker Runner 的架构。

```text
Web Console
  -> FastAPI API
    -> PostgreSQL
    -> Redis/Celery
    -> Docker Runner Manager
      -> Temporary Runner Container
        -> Artifacts
    -> Markdown Report
```

## 设计原则

- AI 负责分析、摘要、排序建议，不直接执行系统命令。
- 所有执行动作通过后端任务编排。
- 每个渗透验证任务使用独立临时容器。
- 容器结束后先收集证据，再释放容器。
- 报告基于结构化结果和证据生成。

## Advanced Architecture

Current upgraded flow:

```text
Scan findings
  -> Manual review
  -> Execution Plan Assessment
  -> Policy review
  -> Human approval
  -> Stock runner or dynamic runner proposal
  -> Parallel execution
  -> Evidence bus
  -> Attack path graph
  -> Report
```

Core registries:

```text
Tool Catalog: config/tool-catalog.yaml
Runner Profiles: config/runner-profiles.yaml
Skill Registry: config/skill-registry.yaml
Dynamic Runner Policy: config/dynamic-runner-policy.yaml
Evidence Bus Schema: config/evidence-bus-schema.yaml
```

The platform does not install all offensive tools in the API container. Instead, stock runner images are built by category. AI and the Web Console call the Tool Gateway and Execution Planner, which schedule isolated runner containers.

## Dynamic Runner Policy

Dynamic runners are allowed only as a controlled fallback:

```text
1. Prefer stock runners.
2. Generate Dockerfile or external image proposal.
3. Run policy checks.
4. Require human approval.
5. Build or pull image.
6. Execute with runtime limits.
7. Collect evidence and remove container.
```

The default policy blocks dangerous Dockerfile patterns such as Docker socket mounts, host networking, privileged execution indicators, and direct `curl | bash` style commands.

## Shared State

Runner containers do not directly share files with each other. They communicate through the platform:

```text
WorkspaceStateEvent
EvidenceFile
Finding
ExecutionPlan
AttackPathNode
AttackPathEdge
```

This keeps multi-container workflows auditable and avoids uncontrolled lateral state sharing.

## 后续扩展点

```text
1. 将 scan simulator 替换为 runner-recon-basic 实际输出解析。
2. 将 runner-web-basic/advanced 接入授权漏洞验证插件。
3. 增加 MinIO 保存证据对象。
4. 增加 OpenSearch 搜索原始日志。
5. 增加 Neo4j 表达攻击路径。
6. 将 Docker Runner 替换为 Kubernetes Job。
7. 增加 MCP Facade，让 AI 通过受控工具接口调用 Tool Gateway。
```
