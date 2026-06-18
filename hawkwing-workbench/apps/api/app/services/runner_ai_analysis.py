import json
from pathlib import Path
from typing import Any
from datetime import datetime

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import PentestJob, RunnerAISession
from app.services.ai_client import AIClient

RUNNER_AI_ROLE = (
    "你是一个网络安全专家，正在做一道 CTF 题目。"
    "你可以参考主控 AI 的建议，但以拿到 flag 为最终目标。"
    "你是 flag 提取的主引擎——证据采集器只负责抓取原始数据，由你来分析并找到 flag。"
    "仔细检查：HTML 源码、JavaScript 逻辑、Cookie、HTTP 头、Base64 编码串、注释中的隐藏信息。"
    "常见 flag 可能藏在：JS 变量、Base64 解码后、HTML 注释、响应头、前端逻辑判断中。"
    "如果证据不足，明确指出缺少什么、下一步该怎么做，不要编造 flag。"
)

RUNNER_AI_ROLE = (
    "你是一个网络安全和 CTF 解题专家，正在分析 runner 容器采集到的真实证据。"
    "你可以参考主控 AI 的建议，但最终目标是基于证据拿到 flag。"
    "优先检查 proof-summary.json、proof_*.body.txt、HTTP 响应正文、HTML 源码、JavaScript、Cookie、HTTP 头和日志。"
    "只有当精确 flag 字符串出现在真实证据中时，才可以判定 flag_found=true。"
    "不要编造示例 flag；如果证据不足，明确指出缺少什么证据和下一步要做什么。"
)


def _read_text(path: Path, max_chars: int = 12000) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")[:max_chars]


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _read_http_evidence(root: Path, max_files: int = 30) -> dict[str, str]:
    http_dir = root / "evidence" / "http"
    evidence: dict[str, str] = {}
    if not http_dir.exists():
        return evidence
    for path in sorted(http_dir.glob("*.txt"))[:max_files]:
        evidence[path.name] = _read_text(path, 4000)
    for path in sorted(http_dir.glob("proof-*.json"))[:max_files]:
        evidence[path.name] = _read_text(path, 6000)
    return evidence


def _extract_flags_from_text(text: str) -> list[dict]:
    """Extract flag candidates from text using common CTF flag patterns."""
    import re
    candidates: list[dict] = []
    seen: set[str] = set()

    patterns = [
        r'(?:flag|FLAG|ctf|CTF)\{\s*[^}\r\n]{1,200}\s*\}',
        r'(?:answer|password|passwd|key)[:：]\s*(\S+)',
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


def _candidate_value(candidate: Any) -> str:
    if isinstance(candidate, dict):
        value = candidate.get("candidate") or candidate.get("flag") or candidate.get("value") or ""
        return str(value).strip()
    return str(candidate or "").strip()


def _dedupe_candidates(candidates: list[Any]) -> list[dict]:
    deduped: list[dict] = []
    seen: set[str] = set()
    for item in candidates:
        value = _candidate_value(item)
        if not value or value in seen:
            continue
        seen.add(value)
        if isinstance(item, dict):
            normalized = dict(item)
            normalized["candidate"] = value
        else:
            normalized = {"candidate": value, "source": "ai-analysis"}
        deduped.append(normalized)
    return deduped


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
    authorization_text = _read_text(root / "authorization.json", 4000)
    http_evidence = _read_http_evidence(root)
    proof_summary = _read_text(root / "evidence" / "http" / "proof-summary.json", 8000)
    container_log = _read_text(root / "container.log", 8000)

    plan_context = plan_context or {}

    # ── Round 1: Triage ──────────────────────────────────────────
    round1_prompt = json.dumps({
        "round": 1,
        "task": "Triage. The evidence collector has finished grabbing raw data from the target. As the primary flag extraction engine, YOUR job is to find the flag.",
        "instructions": [
            "Read ALL provided HTML/JS/headers carefully.",
            "Look for flag patterns (flag{...}, ctf{...}, CTF{...}, ctfshow{...}, FLAG{...}).",
            "Prioritize proof-summary.json and proof_*.body.txt. These are real requests constructed by the runner.",
            "Only mark flag_found=true when the exact flag string appears in real evidence. Never invent example flags.",
            "If you find Base64 strings, decode them and search the decoded text for flags.",
            "Check JavaScript code for hardcoded passwords, comparisons, or hidden logic.",
            "Check HTTP response headers for custom fields (X-Flag, etc).",
            "Check HTML comments, hidden inputs, meta tags.",
            "For PHP eval/source leak challenges, inspect the constructed hello=... responses and extract the flag from the response body.",
        ],
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
        "raw_evidence": {
            "input_json": input_text[:3000],
            "authorization_json": authorization_text,
            "result_json": result_text[:4000],
            "commands_log_tail": command_log[-3000:],
            "timeline_json": timeline_text[:2000],
            "proof_summary_json": proof_summary,
            "http_evidence": {k: v[:6000] for k, v in http_evidence.items()},
            "full_container_log": container_log[-8000:],
        },
        "required_output_format": {
            "flag_found": "true/false",
            "flag_candidates": "list of flag/answer strings found",
            "extraction_method": "how you found each flag (e.g. 'Base64 decode of JS variable', 'plain text in HTML', 'HTTP header')",
            "runner_accomplished": "summary of what the collector gathered",
            "gaps": "what is still missing or unclear — be specific about what additional evidence would help",
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
            "authorization_json": authorization_text,
            "full_commands_log": command_log[-5000:],
            "full_container_log": container_log[-4000:],
            "proof_summary_json": proof_summary,
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
        all_candidates = _dedupe_candidates(flag_candidates + extra_candidates)
        reasoning = solve.get("reasoning_chain", "")
    else:
        all_candidates = _dedupe_candidates(flag_candidates)
        reasoning = triage.get("runner_accomplished", "")

    # Also extract flags from raw text
    text_flags = _extract_flags_from_text(result_text + "\n" + command_log + "\n" + container_log + "\n" + proof_summary)
    for tf in text_flags:
        if not any(_candidate_value(c) == tf["candidate"] for c in all_candidates):
            all_candidates.append(tf)

    # ── Round 3: Writeup ─────────────────────────────────────────
    round3_prompt = json.dumps({
        "round": 3,
        "task": "Writeup. Produce a focused CTF runner writeup based only on the operations this runner container actually performed to get the flag.",
        "scope_rule": "只写 runner 容器中找到 flag 的操作流程，不要写项目总览、漏洞清单、证据索引、泛化安全建议或与本 runner 无关的内容。",
        "writeup_creator_skill_style": [
            "整体使用三段自然串联的简体中文叙事，不使用章节标题、编号列表或目录。",
            "第一段用一两句话说明题目类型和核心技术逻辑。",
            "第二段只写最终成功路径，放入真实使用的 HTTP 请求、payload 或命令；操作块必须使用 Markdown 四空格缩进，不要使用反引号围栏。",
            "第三段解释关键细节并给出最终 flag。",
            "不要写尝试失败的路径、泛化建议、漏洞清单、证据索引或占位符。",
            "不要使用行内反引号，也不要使用 ``` 代码围栏。",
            "整体控制在 30 到 60 行以内。",
        ],
        "preferred_sections": [
            "解题摘要",
            "目标",
            "关键观察",
            "容器执行的请求",
            "拿到的 Flag",
            "复现步骤",
        ],
        "writeup_language": "请使用简体中文输出，不要输出乱码。",
        "clean_required_headings": [
            "中文摘要",
            "目标与题目要求",
            "证据与发现",
            "解题尝试与推理",
            "Flag 或答案",
            "复现步骤",
            "残余风险",
        ],
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
        "proof_summary_json": proof_summary,
        "http_evidence_summary": {k: v[:1500] for k, v in http_evidence.items()},
        "final_format_contract": {
            "source_skill": "writeup-creator",
            "naming_rule": "The saved filename is writeup_YYYYMMDDHHMMSS.md.",
            "must_follow": [
                "Write exactly three natural paragraphs in Simplified Chinese.",
                "Do not use headings, numbered lists, bullet lists, tables, inline backticks, or fenced code blocks.",
                "Put the one successful reproducible HTTP request, command, or payload in a four-space indented Markdown code block.",
                "Only include the final successful path used by the runner container to obtain the flag.",
                "End with the exact flag from real evidence.",
            ],
            "ignore_conflicting_fields": "Ignore any required_sections, preferred_sections, or heading lists in this payload.",
        },
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
    _log_runner_session(db, job, 3, "ai", writeup, {"stage": "writeup-draft"})

    polish_prompt = json.dumps({
        "task": "Rewrite the draft to strictly follow the writeup-creator skill.",
        "draft": writeup,
        "hard_rules": [
            "Use Simplified Chinese.",
            "Use this exact shape: paragraph 1, blank line, paragraph 2 ending with a colon, blank line, one four-space indented request/command block, blank line, paragraph 3 with the key explanation and exact flag.",
            "No headings, no numbered lists, no bullet lists, no tables.",
            "No inline backticks and no fenced code blocks.",
            "The only operation block must be a four-space indented Markdown code block.",
            "Do not put the operation block after the final flag paragraph.",
            "Only keep the final successful path used by the runner. Remove failed attempts or alternate attempts.",
            "Keep the real target, real payload, real response detail, and exact flag.",
            "Do not add generic security advice.",
        ],
        "evidence": {
            "target": job.target,
            "flag_candidates": all_candidates,
            "proof_summary_json": proof_summary,
        },
    }, ensure_ascii=False, indent=2)
    writeup = await AIClient(db).chat(
        polish_prompt,
        system="你是 writeup-creator。只做格式收束和精简，不新增事实。严格遵守用户给定 skill：极简、三段自然叙事、无标题、无反引号、只写最终成功路径。",
    )
    _log_runner_session(db, job, 3, "ai", writeup, {"stage": "writeup-final"})

    # ── Save outputs ──────────────────────────────────────────────
    analysis_path = root / "ai-analysis.md"
    writeup_path = root / f"writeup_{datetime.now().strftime('%Y%m%d%H%M%S')}.md"

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
