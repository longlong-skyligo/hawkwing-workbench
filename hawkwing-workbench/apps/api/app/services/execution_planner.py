import json
import re
from typing import Any

from sqlalchemy.orm import Session

from app.models import Finding
from app.services.ai_client import AIClient
from app.services.catalog import find_runner_profile, get_runner_profiles, get_skill_registry, get_tool_catalog
from app.services.dynamic_builder import propose_dynamic_runner


def _profile_for_finding(finding: Finding) -> str:
    target = (finding.target or "").lower()
    text = f"{finding.title} {finding.raw_detail} {finding.source_tool}".lower()
    if target.startswith(("http://", "https://")):
        if finding.severity.lower() in {"critical", "high"} and finding.confidence >= 0.75:
            return "runner-web-advanced"
        return "runner-web-basic"
    if re.search(r"\b(ad|ldap|smb|kerberos|domain)\b", text) or "active directory" in text:
        return "runner-ad-basic"
    if any(token in text for token in ["pcap", "traffic", "packet", "zeek", "suricata"]):
        return "runner-traffic-basic"
    if any(token in text for token in ["forensics", "memory", "disk", "firmware", "binwalk"]):
        return "runner-forensics-basic"
    if any(token in text for token in ["linux privesc", "sudo", "suid", "linpeas"]):
        return "runner-linux-privesc"
    if any(token in text for token in ["windows privesc", "service path", "winpeas"]):
        return "runner-windows-privesc"
    if any(token in text for token in ["binary", "pwn", "reverse", "elf"]):
        return "runner-pwn-rev-basic"
    if any(token in text for token in ["kubernetes", "container", "docker", "cloud", "aws", "azure"]):
        return "runner-cloud-container-basic"
    return "runner-web-basic"


def _extract_json_object(text: str) -> dict[str, Any]:
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return {}
    return {}


def _safe_profile(profile_name: str, fallback: str, profiles: dict[str, Any]) -> str:
    return profile_name if profile_name in profiles and profile_name != "runner-dynamic" else fallback


def build_execution_plan(
    db: Session,
    workspace_id: int,
    finding_ids: list[int],
    scenario_text: str = "",
    allow_dynamic: bool = True,
) -> dict[str, Any]:
    findings = (
        db.query(Finding)
        .filter(Finding.workspace_id == workspace_id, Finding.id.in_(finding_ids))
        .order_by(Finding.risk_score.desc())
        .all()
    )
    profiles = get_runner_profiles().get("runner_profiles", {})
    tools = get_tool_catalog().get("tools", {})
    skills = get_skill_registry().get("skills", {})

    containers = []
    for finding in findings:
        profile_name = _profile_for_finding(finding)
        profile = find_runner_profile(profile_name)
        containers.append(
            {
                "name": f"{profile_name}-finding-{finding.id}",
                "runner_type": "stock",
                "runner_profile": profile_name,
                "image": profile.get("image", "hawkwing-runner-web-basic:latest"),
                "purpose": profile.get("purpose", "Validate selected finding"),
                "finding_id": finding.id,
                "targets": [finding.target],
                "tools": profile.get("tools", [])[:8],
                "risk_level": profile.get("risk_level", finding.severity),
                "requires_approval": bool(profile.get("require_approval", finding.severity.lower() in {"high", "critical"})),
                "timeout_seconds": 1800,
                "runner_prompt": "",
            }
        )

    dynamic_images = []
    if allow_dynamic and any(keyword in scenario_text.lower() for keyword in ["firmware", "iot", "custom image", "special tool", "qemu", "android", "apk", "ics"]):
        dynamic_images.append(propose_dynamic_runner(scenario_text))

    return {
        "workspace_id": workspace_id,
        "objective": "Solve the selected CTF/range findings and recover the target answer or flag.",
        "recommended_parallelism": {
            "total_containers": len(containers) + len(dynamic_images),
            "max_parallel": min(4, max(1, len(containers))),
            "per_target_limit": 1,
            "high_risk_max": 1 if any(item["risk_level"] in {"high", "critical"} for item in containers) else 0,
        },
        "containers": containers,
        "dynamic_images": dynamic_images,
        "catalog_summary": {
            "tool_count": len(tools),
            "runner_profile_count": len(profiles),
            "skill_count": len(skills),
        },
        "reasoning_summary": "Deterministic runner selection was used as a fallback before AI planning.",
    }


async def build_ai_guided_execution_plan(
    db: Session,
    workspace_id: int,
    finding_ids: list[int],
    scenario_text: str = "",
    allow_dynamic: bool = True,
) -> dict[str, Any]:
    base_plan = build_execution_plan(db, workspace_id, finding_ids, scenario_text, allow_dynamic)
    findings = (
        db.query(Finding)
        .filter(Finding.workspace_id == workspace_id, Finding.id.in_(finding_ids))
        .order_by(Finding.risk_score.desc())
        .all()
    )
    profiles = get_runner_profiles().get("runner_profiles", {})
    profile_summary = {
        name: {
            "purpose": value.get("purpose", ""),
            "risk_level": value.get("risk_level", "medium"),
            "require_approval": bool(value.get("require_approval", False)),
            "tools": value.get("tools", [])[:12],
        }
        for name, value in profiles.items()
        if name != "runner-dynamic"
    }
    prompt = {
        "task": "Act as the main architecture AI. Read the challenge brief and scan findings, then produce a detailed solution plan for runner AIs.",
        "rules": [
            "This is an authorized CTF/range workflow.",
            "Runner AIs are authorized to use all tools available inside their containers against the listed target only.",
            "Runner prompts may include CTF exploitation techniques such as fuzzing, injection, deserialization testing, auth bypass checks, source disclosure, local file reads, and controlled proof-of-execution when needed to recover the flag.",
            "Keep the authorization bounded to scenario targets and explicitly tell runners not to access unlisted third-party systems.",
            "Use only listed stock runner_profile values.",
            "Prefer web runners for http/https targets unless there is strong evidence for another category.",
            "Do not recommend malware, phishing, destructive actions, persistence, or covert real-world access.",
            "The runner_prompt must be detailed enough for a runner AI to solve the task, freely call container tools within scope, capture proof, extract the flag, and write a writeup.",
            "Return JSON only.",
        ],
        "scenario_text": scenario_text,
        "findings": [
            {
                "id": finding.id,
                "target": finding.target,
                "title": finding.title,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "risk_score": finding.risk_score,
                "source_tool": finding.source_tool,
                "raw_detail": finding.raw_detail[:2000],
                "deterministic_fallback_runner": _profile_for_finding(finding),
            }
            for finding in findings
        ],
        "available_runner_profiles": profile_summary,
        "required_schema": {
            "target_objective": "what answer or flag the project is trying to obtain",
            "vulnerability_background": "detailed reasoning based on challenge brief and findings",
            "solution_strategies": [
                {
                    "name": "strategy name",
                    "likelihood": "high/medium/low",
                    "reasoning": "why this path may work",
                    "steps": ["ordered steps for the runner AI"],
                }
            ],
            "overall_analysis": "short Chinese summary for the operator UI",
            "recommendations": [
                {
                    "finding_id": "integer",
                    "runner_profile": "one available runner_profile",
                    "rationale": "why this runner fits this finding",
                    "focus_tools": ["tool names from the runner"],
                    "next_checks": ["checks the runner should perform"],
                    "runner_prompt": "full prompt for the runner AI; include objective, explicit authorization for the listed target, permitted CTF actions, available tool usage, hypotheses, evidence to gather, flag extraction, and writeup requirements",
                    "confidence": "0.0-1.0",
                }
            ],
        },
    }
    ai_text = await AIClient(db).chat(
        json.dumps(prompt, ensure_ascii=False, indent=2),
        system="你是授权 CTF/靶场平台的主控 AI。你负责审题、结合扫描结果论证解题方案，并给 Runner AI 生成详细提示词。只输出 JSON。",
    )
    ai_data = _extract_json_object(ai_text)
    recommendations = {int(item.get("finding_id", 0)): item for item in ai_data.get("recommendations", []) if item.get("finding_id")}

    for item in base_plan.get("containers", []):
        finding_id = int(item.get("finding_id", 0))
        recommendation = recommendations.get(finding_id, {})
        fallback = item["runner_profile"]
        profile_name = _safe_profile(str(recommendation.get("runner_profile", "")), fallback, profiles)
        profile = find_runner_profile(profile_name)
        item["runner_profile"] = profile_name
        item["image"] = profile.get("image", item["image"])
        item["purpose"] = profile.get("purpose", item["purpose"])
        item["tools"] = profile.get("tools", item.get("tools", []))[:8]
        item["risk_level"] = profile.get("risk_level", item["risk_level"])
        item["requires_approval"] = bool(profile.get("require_approval", item["requires_approval"]))
        item["runner_prompt"] = recommendation.get("runner_prompt", "")
        item["ai_recommendation"] = {
            "rationale": recommendation.get("rationale", "AI recommendation unavailable; deterministic fallback was used."),
            "focus_tools": recommendation.get("focus_tools", item["tools"][:5]),
            "next_checks": recommendation.get("next_checks", []),
            "confidence": recommendation.get("confidence", 0),
            "fallback_runner": fallback,
        }

    base_plan["target_objective"] = ai_data.get("target_objective", "Recover the challenge answer or flag.")
    base_plan["vulnerability_background"] = ai_data.get("vulnerability_background", "")
    base_plan["solution_strategies"] = ai_data.get("solution_strategies", [])
    base_plan["ai_initial_analysis"] = ai_data.get("overall_analysis", "AI returned no structured analysis; deterministic fallback was used.")
    base_plan["ai_planning_mode"] = "main_ai_solution_plan_for_runner_ai"
    base_plan["reasoning_summary"] = "Main AI reviewed the challenge and findings, then produced runner-specific prompts under stock runner policy."
    return base_plan


def dumps_plan(plan: dict[str, Any]) -> str:
    return json.dumps(plan, ensure_ascii=False, indent=2)


def loads_plan(plan_json: str) -> dict[str, Any]:
    return json.loads(plan_json or "{}")
