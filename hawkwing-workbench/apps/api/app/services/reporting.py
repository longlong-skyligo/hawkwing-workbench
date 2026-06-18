import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import PentestJob, Workspace


def _candidate_value(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("candidate") or item.get("flag") or item.get("value") or "").strip()
    return str(item or "").strip()


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _latest_writeup_for_job(settings, workspace_id: int, job_id: int) -> Path | None:
    artifact_dir = Path(settings.artifact_root) / f"workspace-{workspace_id}" / f"pentest-job-{job_id}"
    candidates = list(artifact_dir.glob("writeup_*.md")) + list(artifact_dir.glob("runner-writeup.md"))
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _collect_runner_writeups(settings, workspace_id: int, jobs: list[PentestJob]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for job in jobs:
        writeup_path = _latest_writeup_for_job(settings, workspace_id, job.id)
        result_path = Path(settings.artifact_root) / f"workspace-{workspace_id}" / f"pentest-job-{job.id}" / "result.json"
        result = _read_json(result_path)
        flags = []
        for item in result.get("flag_candidates") or []:
            value = _candidate_value(item)
            if value and value not in flags:
                flags.append(value)
        if writeup_path:
            content = writeup_path.read_text(encoding="utf-8", errors="replace")
        else:
            content = job.result_summary or "Runner 尚未生成 writeup。"
        items.append({
            "job": job,
            "path": writeup_path,
            "content": content.strip(),
            "flags": flags,
        })
    return items


def _build_report(workspace: Workspace, writeups: list[dict[str, Any]]) -> str:
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    solved_flags: list[str] = []
    for item in writeups:
        for flag in item["flags"]:
            if flag not in solved_flags:
                solved_flags.append(flag)

    if len(writeups) == 1:
        item = writeups[0]
        job = item["job"]
        flag_block = "\n".join(f"- `{flag}`" for flag in item["flags"]) or "- 未提取到明确 flag。"
        return f"""# {workspace.name} 渗透报告

生成时间：{generated_at}

## 报告结论

本报告基于单个 Runner 容器的 writeup 生成。Runner #01 使用 `{job.runner_profile}` 对目标 `{job.target}` 完成验证，并记录了拿到 flag 的复现流程。

## 最终结果

{flag_block}

## Runner Writeup

{item["content"]}
"""

    summary_lines = []
    for index, item in enumerate(writeups, start=1):
        job = item["job"]
        flags = ", ".join(f"`{flag}`" for flag in item["flags"]) or "未提取到明确 flag"
        summary_lines.append(f"{index}. Runner #{index:02d} `{job.runner_profile}` -> {flags}")

    merged_sections = []
    for index, item in enumerate(writeups, start=1):
        job = item["job"]
        merged_sections.append(f"""## Runner #{index:02d}

- 目标：`{job.target}`
- Runner：`{job.runner_profile}`
- 状态：`{job.status}`

{item["content"]}
""")

    final_flags = "\n".join(f"- `{flag}`" for flag in solved_flags) or "- 未提取到明确 flag。"
    return f"""# {workspace.name} 渗透报告

生成时间：{generated_at}

## 报告结论

本报告基于当前项目中 {len(writeups)} 个 Runner 容器的 writeup 综合生成，重点汇总各容器实际完成的解题过程和最终结果。

## 最终结果

{final_flags}

## Runner 汇总

{chr(10).join(summary_lines)}

{chr(10).join(merged_sections)}
"""


def generate_workspace_report(db: Session, workspace_id: int) -> Path:
    settings = get_settings()
    workspace = db.get(Workspace, workspace_id)
    if not workspace:
        raise ValueError("workspace not found")

    jobs = (
        db.query(PentestJob)
        .filter(PentestJob.workspace_id == workspace_id)
        .order_by(PentestJob.id.asc())
        .all()
    )
    writeups = _collect_runner_writeups(settings, workspace_id, jobs)

    out_dir = Path(settings.report_root) / f"workspace-{workspace_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"渗透报告_{datetime.now().strftime('%Y%m%d%H%M')}.md"
    out_file.write_text(_build_report(workspace, writeups), encoding="utf-8")
    return out_file


def latest_workspace_report(workspace_id: int) -> Path | None:
    settings = get_settings()
    report_dir = Path(settings.report_root) / f"workspace-{workspace_id}"
    if not report_dir.exists():
        return None
    legacy_report = Path(settings.report_root) / f"workspace-{workspace_id}-report.md"
    candidates = list(report_dir.glob("渗透报告_*.md"))
    if legacy_report.exists():
        candidates.append(legacy_report)
    if not candidates:
        return None
    return max(candidates, key=lambda path: path.stat().st_mtime)
