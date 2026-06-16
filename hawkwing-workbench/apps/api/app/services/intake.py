import json
import re
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.models import Workspace, WorkspaceAttachment
from app.services.ai_client import AIClient
from app.services.execution_planner import _extract_json_object


TARGET_PATTERN = re.compile(
    r"(https?://[^\s\"'<>]+|\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b)",
    re.IGNORECASE,
)


def extract_targets(text: str) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []
    for match in TARGET_PATTERN.findall(text or ""):
        value = match.strip().rstrip("),.;")
        if value and value not in seen:
            seen.add(value)
            targets.append(value)
    return targets


def attachment_summaries(db: Session, workspace_id: int) -> list[dict[str, Any]]:
    attachments = db.query(WorkspaceAttachment).filter(WorkspaceAttachment.workspace_id == workspace_id).order_by(WorkspaceAttachment.id.desc()).limit(10).all()
    summaries: list[dict[str, Any]] = []
    for item in attachments:
        path = Path(item.path)
        preview = ""
        if path.suffix.lower() in {".txt", ".md", ".json", ".yaml", ".yml", ".csv", ".log"} and path.exists():
            preview = path.read_text(encoding="utf-8", errors="replace")[:4000]
        summaries.append(
            {
                "filename": item.filename,
                "content_type": item.content_type,
                "size": item.size,
                "sha256": item.sha256,
                "preview": preview,
            }
        )
    return summaries


async def analyze_project_intake(db: Session, workspace: Workspace) -> dict[str, Any]:
    attachments = attachment_summaries(db, workspace.id)
    deterministic_targets = extract_targets(workspace.description + "\n" + "\n".join(item.get("preview", "") for item in attachments))

    # Browser pre-capture of explicit URLs in description
    browser_summaries = ""
    for tgt in deterministic_targets:
        if tgt.startswith(("http://", "https://")):
            try:
                from app.services.browser import capture_page_summary
                browser_summaries += "\n\n" + capture_page_summary(tgt)
            except Exception:
                pass

    prompt = {
        "task": "Read a CTF/range project brief and identify scope targets plus a concise solving approach.",
        "rules": [
            "Return JSON only.",
            "Only include targets explicitly present in the description or attachments.",
            "Prefer http/https URLs when present.",
            "Do not invent targets.",
        ],
        "project": {"name": workspace.name, "description": workspace.description},
        "attachments": attachments,
        "browser_preview": browser_summaries if browser_summaries else "(browser capture not available — target may be JS-rendered; use curl evidence or other sources)",
        "deterministic_targets": deterministic_targets,
        "required_schema": {
            "summary": "short Chinese description of the challenge requirement",
            "targets": ["explicit target strings"],
            "initial_strategy": ["ordered safe analysis steps"],
            "category_hint": "web/pwn/reverse/forensics/ad/cloud/unknown",
        },
    }
    ai_text = await AIClient(db).chat(
        json.dumps(prompt, ensure_ascii=False, indent=2),
        system="你是授权 CTF/靶场的读题分析助手。只输出 JSON，不要编造目标。",
    )
    ai_data = _extract_json_object(ai_text)
    ai_targets = [str(item).strip() for item in ai_data.get("targets", []) if str(item).strip()]
    targets = ai_targets or deterministic_targets
    return {
        "summary": ai_data.get("summary") or "已完成题目描述读取，平台将基于显式目标启动后续扫描。",
        "targets": targets,
        "initial_strategy": ai_data.get("initial_strategy") or ["识别目标服务", "低噪声扫描", "按风险排序漏洞", "人工确认后启动 Runner"],
        "category_hint": ai_data.get("category_hint") or "unknown",
        "ai_raw": ai_text[:4000],
    }
