import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import PentestJob, RunnerAISession
from app.services.ai_client import AIClient

RUNNER_AI_ROLE = (
    "你是一个网络安全专家，正在做一道 CTF 题目。"
    "可以参考主控 AI 的建议，但必须结合实际证据，以拿到 flag 为最终目标。"
    "你可以调用容器内的 nmap、curl、ffuf、nuclei、katana、dirsearch、playwright 等工具。"
    "如果证据不足，明确指出缺少什么、下一步该怎么做，不要编造 flag。"
)


def _read_text(path: Path, max_chars: int = 12000) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:max_chars]


def _read_http_evidence(root: Path, max_files: int = 8) -> dict[str, str]:
    http_dir = root / "evidence" / "http"
    evidence: dict[str, str] = {}
    if not http_dir.exists():
        return evidence
    for path in list(http_dir.glob("*.txt"))[:max_files]:
        evidence[path.name] = _read_text(path, 4000)
    return evidence


def _extract_flags_from_text(text: str) -> list[dict]:
    """Extract flag candidates from text using common CTF flag patterns."""
    import re
    candidates: list[dict] = []
    seen: set[str] = set()

    patterns = [
        r'(?:flag|FLAG|ctf|CTF)[{（(]\s*[^}）)]+\s*[}）)]',
        r'[A-Za-z0-9_\-]{8,}\{[^}]+\}',
        r'(?:答案|answer|password|passwd|key)[:：]\s*(\S+)',
        r'(?:FLAG|flag)[:：]\s*(\S+)',
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            value = match.group(0).strip()
            if value not in seen and len(value) > 4:
                seen.add(value)
                candidates.append({"candidate": value, "source": "text-extraction", "pattern": pattern})

    return candidates


def _log_runner_session(db: Session, job: PentestJob, round_num: int, role: str, content: str, metadata: dict | None = None):
    session = RunnerAISession(
        workspace_id=job.workspace_id,
        pentest_job_id=job.id,
        round_num=round_num,
        role=role,
        content=content,
        metadata_json=json.dumps(metadata or {}, ensure_ascii=False),
    )
    db.add(session)
    db.commit()


async def analyze_runner_artifacts(
    db: Session,
    job: PentestJob,
    artifact_dir: str,
    plan_context: dict[str, Any] | None = None,
) -> Path:
    """
    Runner AI multi-turn analysis.
    Each runner gets its own AI "session" — separate system prompt and context.
    The main AI's plan_context is passed in as the solution guidance.

    Multi-turn flow:
      Round 1 — Triage: understand target, evidence, and plan
      Round 2 — Solve: test hypotheses, extract flag/answer
      Round 3 — Writeup: produce reproducible writeup
    """
    settings = get_settings()
    root = Path(artifact_dir)
    result_text = _read_text(root / "result.json")
    command_log = _read_text(root / "commands.log")
    timeline_text = _read_text(root / "timeline.json")
    input_text = _read_text(root / "input.json")
    http_evidence = _read_http_evidence(root)
    container_log = _read_text(root / "container.log", 8000)

    plan_context = plan_context or {}

    # ── Round 1: Triage ──────────────────────────────────────────
    round1_prompt = json.dumps({
        "round": 1,
        "task": "Triage. Review the main AI solution plan and runner evidence. Identify what the runner did, what it found, and whether a flag/answer was recovered.",
        "main_ai_plan": {
            "objective": plan_context.get("target_objective", ""),
            "background": plan_context.get("vulnerability_background", ""),
            "strategies": plan_context.get("solution_strategies", []),
            "runner_prompt_from_main_ai": plan_context.get("container", {}).get("runner_prompt", ""),
        },
        "job_meta": {
            "id": job.id,
            "workspace_id": job.workspace_id,
            "target": job.target,
            "runner_profile": job.runner_profile,
        },
        "runner_evidence_summary": {
            "input_json": input_text[:3000],
            "result_json": result_text[:4000],
            "commands_log_tail": command_log[-3000:],
            "timeline_json": timeline_text[:2000],
            "http_evidence_keys": list(http_evidence.keys()),
            "container_log_tail": container_log[-2000:],
        },
        "required_output_format": {
            "flag_found": "true/false",
            "flag_candidates": "list of candidate flag/answer values",
            "runner_accomplished": "summary of what the runner achieved",
            "gaps": "what is still missing or unclear",
        },
    }, ensure_ascii=False, indent=2)

    triage_result = await AIClient(db).chat(
        round1_prompt,
        system=RUNNER_AI_ROLE + " [Triage 轮] 分析 Runner 执行结果和证据，判断是否拿到 flag。只输出 JSON。",
    )
    _log_runner_session(db, job, 1, "ai", triage_result, {"stage": "triage"})

    triage = _extract_json(triage_result)

    # ── Round 2: Solve (if flag not found) ────────────────────────
    flag_candidates = triage.get("flag_candidates", [])
    if not triage.get("flag_found") or not flag_candidates:
        round2_prompt = json.dumps({
            "round": 2,
            "task": "Solve. The triage round did not find a definitive flag. Deep-dive into the evidence and try to reconstruct or reason about where the flag/answer might be.",
            "previous_analysis": triage_result[:3000],
            "plan_context_summary": plan_context.get("target_objective", ""),
            "full_result_json": result_text[:8000],
            "full_commands_log": command_log[-5000:],
            "full_container_log": container_log[-4000:],
            "http_evidence": {k: v[:2000] for k, v in http_evidence.items()},
            "required_output_format": {
                "flag_reconstructed": "true/false",
                "flag_candidates": "list of candidate flag/answer values with confidence",
                "reasoning_chain": "step-by-step reasoning about where the flag is likely to be",
                "next_actions_if_unsolved": "what the runner should try next",
            },
        }, ensure_ascii=False, indent=2)

        solve_result = await AIClient(db).chat(
            round2_prompt,
            system=RUNNER_AI_ROLE + " [Solve 轮] 深入分析 Runner 输出和证据，从原始数据中重建 flag/答案。只输出 JSON。",
        )
        _log_runner_session(db, job, 2, "ai", solve_result, {"stage": "solve"})

        solve = _extract_json(solve_result)
        extra_candidates = solve.get("flag_candidates", [])
        all_candidates = flag_candidates + extra_candidates
        reasoning = solve.get("reasoning_chain", "")
    else:
        all_candidates = flag_candidates
        reasoning = triage.get("runner_accomplished", "")

    # Also extract flags from raw text
    text_flags = _extract_flags_from_text(result_text + "\n" + command_log + "\n" + container_log)
    for tf in text_flags:
        if not any(c.get("candidate") == tf["candidate"] for c in all_candidates):
            all_candidates.append(tf)

    # ── Round 3: Writeup ─────────────────────────────────────────
    round3_prompt = json.dumps({
        "round": 3,
        "task": "Writeup. Produce a complete, reproducible CTF writeup based on all evidence and analysis.",
        "main_ai_plan": {
            "objective": plan_context.get("target_objective", ""),
            "background": plan_context.get("vulnerability_background", ""),
            "strategies": plan_context.get("solution_strategies", []),
        },
        "triage_analysis": triage_result[:3000],
        "flag_candidates": all_candidates,
        "reasoning_chain": reasoning,
        "job_meta": {
            "id": job.id,
            "target": job.target,
            "runner_profile": job.runner_profile,
            "runner_image": job.runner_image,
        },
        "command_log_summary": command_log[-4000:],
        "result_json_summary": result_text[:4000],
        "http_evidence_summary": {k: v[:1500] for k, v in http_evidence.items()},
        "required_sections": [
            "Summary (中文摘要)",
            "Target And Objective (目标与题目要求)",
            "Evidence (证据与发现)",
            "Attempts And Reasoning (解题尝试与推理)",
            "Flag Or Answer (flag/答案)",
            "Reproduction Steps (复现步骤)",
            "Residual Risk (残余风险)",
        ],
    }, ensure_ascii=False, indent=2)

    writeup = await AIClient(db).chat(
        round3_prompt,
        system=RUNNER_AI_ROLE + " [Writeup 轮] 根据解题方案、执行证据和前几轮分析，生成可复现的完整 CTF Writeup（Markdown 格式）。",
    )
    _log_runner_session(db, job, 3, "ai", writeup, {"stage": "writeup"})

    # ── Save outputs ──────────────────────────────────────────────
    analysis_path = root / "ai-analysis.md"
    writeup_path = root / "runner-writeup.md"

    solve_text = ""
    try:
        solve_text = solve_result
    except NameError:
        solve_text = "跳过（Triage 轮已拿到 flag）"

    analysis_md = f"""# Runner AI Analysis — Job #{job.id}

## Round 1 — Triage
{triage_result}

## Round 2 — Solve
{solve_text}

## Round 3 — Writeup
{writeup}

## Flag Candidates
{json.dumps(all_candidates, ensure_ascii=False, indent=2)}
"""
    analysis_path.write_text(analysis_md, encoding="utf-8")
    writeup_path.write_text(writeup, encoding="utf-8")

    # ── Write structured flag results ─────────────────────────────
    flag_result = {
        "flag_candidates": all_candidates,
        "extraction_method": "ai-multi-turn",
        "rounds": 3,
        "triage_flag_found": triage.get("flag_found", False),
    }
    (root / "flag-extraction.json").write_text(json.dumps(flag_result, ensure_ascii=False, indent=2), encoding="utf-8")

    return writeup_path


def _extract_json(text: str) -> dict[str, Any]:
    """Robust JSON extraction from AI output."""
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Try to find JSON block
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass
    # Try markdown code block
    import re
    m = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    return {}
