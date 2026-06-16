# {{ workspace_name }} 攻防解题报告

## 1. 项目概况

- 项目名称：{{ workspace_name }}
- 项目状态：{{ status }}
- 目标数量：{{ target_count }}
- 漏洞数量：{{ finding_count }}
- Runner 任务数量：{{ pentest_job_count }}
- 工具目录数量：{{ tool_count }}
- Runner Profile 数量：{{ runner_profile_count }}
- AI Skill/Runbook 数量：{{ skill_count }}

## 2. 目标范围

{% for target in targets %}
- {{ target.value }}（{{ target.type }}）
{% endfor %}

## 3. 漏洞发现

| 编号 | 目标 | 标题 | 风险 | 置信度 | 状态 |
|---|---|---|---|---|---|
{% for finding in findings %}
| {{ finding.id }} | {{ finding.target }} | {{ finding.title }} | {{ finding.severity }} | {{ finding.confidence }} | {{ finding.status }} |
{% endfor %}

## 4. Runner 执行结果

| 任务 | 漏洞 | Runner Profile | Runner Image | 状态 | 摘要 |
|---|---|---|---|---|---|
{% for job in pentest_jobs %}
| {{ job.id }} | {{ job.finding_id }} | {{ job.runner_profile }} | {{ job.runner_image }} | {{ job.status }} | {{ job.result_summary }} |
{% endfor %}

## 5. 候选 Flag

{% if flags %}
{% for item in flags %}
```text
{{ item.flag }}
```

- 来源：任务 {{ item.job_id }} / {{ item.source }} / {{ item.target }}
{% endfor %}
{% else %}
暂无候选 flag。请继续查看 Runner 证据和 AI 分析建议。
{% endif %}

## 6. 执行计划

{% for plan in execution_plans %}
### Plan {{ plan.id }} - {{ plan.status }}

- 目标：{{ plan.objective }}
- 风险摘要：{{ plan.risk_summary }}
- 审批人：{{ plan.approved_by }}

{% endfor %}

## 7. 证据索引

| 编号 | 类型 | 任务 | SHA256 | 路径 |
|---|---|---|---|---|
{% for evidence in evidence_files %}
| {{ evidence.id }} | {{ evidence.file_type }} | {{ evidence.pentest_job_id }} | {{ evidence.sha256 }} | {{ evidence.path }} |
{% endfor %}

## 8. 状态事件

| 事件 | 来源 | 目标 | 时间 |
|---|---|---|---|
{% for event in state_events %}
| {{ event.event_type }} | {{ event.source }} | {{ event.target_ref }} | {{ event.created_at }} |
{% endfor %}

## 9. 复盘建议

{{ ai_summary }}

## 10. 附录

- 报告由 HawkWing External Range AI Workbench 自动生成。
- 证据文件位于项目 `data/artifacts` 目录。
