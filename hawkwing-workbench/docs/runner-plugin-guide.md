# Runner 插件开发说明

Runner 是临时容器。平台为每个验证任务创建一个 Runner，任务结束后收集 `/out` 目录并释放容器。

## 输入

平台会挂载一个工作目录到容器的 `/out`，其中包含：

```text
/out/input.json
```

示例：

```json
{
  "workspace_id": 1,
  "job_id": 2,
  "target": "10.10.10.5",
  "finding_id": 3,
  "mode": "controlled_validation"
}
```

## 输出

Runner 必须生成：

```text
/out/result.json
/out/commands.log
/out/evidence/
```

推荐生成：

```text
/out/timeline.json
/out/stdout.log
/out/stderr.log
/out/evidence/http/
/out/evidence/screenshots/
/out/evidence/files/
```

## result.json

```json
{
  "status": "confirmed",
  "confidence": 0.9,
  "impact": "controlled_access_validated",
  "privilege_obtained": "limited",
  "summary": "Finding was validated in the authorized range.",
  "evidence_files": ["evidence/http/response-001.txt"],
  "recommendation": "Patch or restrict exposed service."
}
```

## 注意事项

- 只在授权靶场中启用真实验证插件。
- 不要在 Runner 中挂载宿主机敏感目录。
- 不要使用 privileged 容器。
- 保持输出格式稳定，方便报告生成。
