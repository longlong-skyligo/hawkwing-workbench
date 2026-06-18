import json
import re
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import PentestJob, RunnerAISession


FLAG_RE = re.compile(r"(?:flag|ctf|FLAG|CTF)\{[^}\r\n]{1,200}\}")
ACCOUNT_PAIR_RE = re.compile(
    r"(?:username|user|account|login|用户名|账户|账号)\s*[:=：]\s*([^\s,;，；/]+).*?"
    r"(?:password|passwd|pass|pwd|密码)\s*[:=：]\s*([^\s,;，；]+)",
    re.IGNORECASE | re.DOTALL,
)
PERMISSION_RE = re.compile(
    r"(?:取得|获得|拿到|获取|got|gained|obtained|as)\s*([A-Za-z0-9_.@\\/-]{2,80})\s*(?:用户)?权限",
    re.IGNORECASE,
)
WHOAMI_RE = re.compile(r"(?:whoami|current user|当前用户)\s*[:=：]\s*([A-Za-z0-9_.@\\/-]{2,80})", re.IGNORECASE)


def _read_text(path: Path, limit: int = 20000) -> str:
    if not path.exists() or not path.is_file():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:limit]


def _candidate_to_text(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("candidate") or item.get("flag") or item.get("value") or "").strip()
    return str(item or "").strip()


def _add_clue(clues: list[dict], seen: set[tuple[str, str]], clue_type: str, value: str, message: str, source: str, job: PentestJob) -> None:
    value = value.strip()
    if not value:
        return
    key = (clue_type, value)
    if key in seen:
        return
    seen.add(key)
    clues.append({
        "type": clue_type,
        "value": value,
        "message": message,
        "source": source,
        "job_id": job.id,
        "target": job.target,
        "runner_profile": job.runner_profile,
    })


def _extract_from_text(text: str, source: str, job: PentestJob, clues: list[dict], seen: set[tuple[str, str]]) -> None:
    for flag in FLAG_RE.findall(text):
        _add_clue(clues, seen, "flag", flag, f"拿到flag，{flag}", source, job)

    for username, password in ACCOUNT_PAIR_RE.findall(text):
        value = f"{username}/{password}"
        _add_clue(clues, seen, "credential", value, f"账户已破解：{value}", source, job)

    for user in PERMISSION_RE.findall(text):
        _add_clue(clues, seen, "permission", user, f"取得{user}用户权限", source, job)

    for user in WHOAMI_RE.findall(text):
        _add_clue(clues, seen, "permission", user, f"取得{user}用户权限", source, job)

    if "uid=0(root)" in text or "euid=0(root)" in text:
        _add_clue(clues, seen, "permission", "root", "取得root用户权限", source, job)


def collect_workspace_clues(db: Session, workspace_id: int) -> list[dict]:
    settings = get_settings()
    jobs = db.query(PentestJob).filter(PentestJob.workspace_id == workspace_id).order_by(PentestJob.id.desc()).all()
    clues: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for job in jobs:
        _extract_from_text(job.result_summary or "", "job-summary", job, clues, seen)

        artifact_dir = Path(settings.artifact_root) / f"workspace-{workspace_id}" / f"pentest-job-{job.id}"
        for filename in ("result.json", "flag-extraction.json", "commands.log", "container.log"):
            path = artifact_dir / filename
            text = _read_text(path)
            if not text:
                continue
            if path.suffix == ".json":
                try:
                    data = json.loads(text)
                    for item in data.get("flag_candidates") or []:
                        flag = _candidate_to_text(item)
                        if flag:
                            _add_clue(clues, seen, "flag", flag, f"拿到flag，{flag}", filename, job)
                    text = json.dumps(data, ensure_ascii=False)
                except Exception:
                    pass
            _extract_from_text(text, filename, job, clues, seen)

        sessions = (
            db.query(RunnerAISession)
            .filter(RunnerAISession.workspace_id == workspace_id, RunnerAISession.pentest_job_id == job.id)
            .order_by(RunnerAISession.id.desc())
            .limit(5)
            .all()
        )
        for session in sessions:
            _extract_from_text(session.content or "", f"runner-ai-round-{session.round_num}", job, clues, seen)

    return clues[:30]
