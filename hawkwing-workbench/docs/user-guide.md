# 使用说明

## 蓝队队员

1. 打开 `http://localhost:3000`。
2. 点击“新建工作空间”。
3. 输入比赛给定的 IP、CIDR、URL 或域名。
4. 点击“导入目标”。
5. 点击“启动标准扫描”。
6. 在漏洞排行中勾选需要验证的漏洞。
7. 点击“并行渗透验证”。
8. 等待任务完成，查看容器任务状态。
9. 点击“生成 Markdown 报告”。

## 裁判人员

裁判可通过以下位置查看过程：

```text
API 文档：http://localhost:8000/docs
审计接口：/api/workspaces/{workspace_id}/audit-logs
报告目录：data/reports
证据目录：data/artifacts
```

重点检查：

```text
任务是否在比赛时间内执行
目标是否符合临时靶场范围
是否存在证据文件
临时容器是否已释放
报告是否完整
```

