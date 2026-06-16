import json
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import PentestJob
from app.services.ai_client import AIClient


def _read_text(path: Path, max_chars: int = 8000) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:max_chars]


async def analyze_runner_artifacts(db: Session, job: PentestJob, artifact_dir: str) -> Path:
    root = Path(artifact_dir)
    result_text = _read_text(root / "result.json")
    command_log = _read_text(root / "commands.log")
    timeline_text = _read_text(root / "timeline.json")

    prompt = {
        "task": "Analyze controlled CTF/range runner output and produce operator guidance.",
        "constraints": [
            "Only discuss authorized lab or competition validation.",
            "Do not generate malware, persistence, phishing, or destructive instructions.",
            "Focus on evidence, likely vulnerability category, next safe validation steps, and report wording.",
        ],
        "job": {
            "id": job.id,
            "workspace_id": job.workspace_id,
            "finding_id": job.finding_id,
            "target": job.target,
            "runner_profile": job.runner_profile,
            "runner_image": job.runner_image,
            "status": job.status,
        },
        "artifacts": {
            "result_json": result_text,
            "commands_log": command_log,
            "timeline_json": timeline_text,
        },
        "output_format": "Markdown with sections: Evidence Summary, Likely Direction, Recommended Next Checks, Report Notes.",
    }
    content = await AIClient(db).chat(
        json.dumps(prompt, ensure_ascii=False, indent=2),
        system="你是授权网络攻防比赛的 Runner 证据分析助手，只提供合规、安全、可复核的分析建议。",
    )
    output_path = root / "ai-analysis.md"
    output_path.write_text(content, encoding="utf-8")
    return output_path
