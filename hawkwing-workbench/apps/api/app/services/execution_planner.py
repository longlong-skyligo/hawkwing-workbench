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
    if (
        re.search(r"\b(ad|ldap|smb|kerberos|domain)\b", text)
        or "active directory" in text
    ):
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
    if finding.severity.lower() in {"critical", "high"} and finding.confidence >= 0.75:
        return "runner-web-advanced"
    return "runner-web-basic"


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
        profile_tools = profile.get("tools", [])
        containers.append(
            {
                "name": f"{profile_name}-finding-{finding.id}",
                "runner_type": "stock",
                "runner_profile": profile_name,
                "image": profile.get("image", "hawkwing-runner-web-basic:latest"),
                "purpose": profile.get("purpose", "Validate selected finding"),
                "finding_id": finding.id,
                "targets": [finding.target],
                "tools": profile_tools[:8],
                "risk_level": profile.get("risk_level", finding.severity),
                "requires_approval": bool(profile.get("require_approval", finding.severity.lower() in {"high", "critical"})),
                "timeout_seconds": 1800,
            }
        )

    dynamic_images = []
    scenario_lower = scenario_text.lower()
    complex_keywords = ["firmware", "iot", "custom image", "special tool", "qemu", "android", "apk", "ics"]
    if allow_dynamic and any(keyword in scenario_lower for keyword in complex_keywords):
        dynamic_images.append(propose_dynamic_runner(scenario_text))

    max_parallel = min(4, max(1, len(containers)))
    high_risk = [item for item in containers if item["risk_level"] in {"high", "critical"}]
    plan = {
        "workspace_id": workspace_id,
        "objective": "Validate selected findings with stock runners and optional dynamic runners.",
        "recommended_parallelism": {
            "total_containers": len(containers) + len(dynamic_images),
            "max_parallel": max_parallel,
            "per_target_limit": 1,
            "high_risk_max": 1 if high_risk else 0,
        },
        "containers": containers,
        "dynamic_images": dynamic_images,
        "catalog_summary": {
            "tool_count": len(tools),
            "runner_profile_count": len(profiles),
            "skill_count": len(skills),
        },
        "reasoning_summary": (
            "Stock runner profiles were selected by finding type, severity, and confidence. "
            "Dynamic runner proposals are generated only when the scenario suggests unsupported specialized tooling."
        ),
    }
    return plan


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
    if profile_name in profiles and profile_name != "runner-dynamic":
        return profile_name
    return fallback


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
        "task": "Before any container execution, analyze the CTF/range target and choose suitable stock runner containers.",
        "rules": [
            "Use only listed stock runner_profile values.",
            "Prefer web runners for http/https targets unless there is strong evidence for another category.",
            "Do not recommend malware, persistence, phishing, destructive actions, or covert access deployment.",
            "If the evidence is weak, choose a low-noise reconnaissance or web-basic runner.",
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
                "raw_detail": finding.raw_detail[:1200],
                "deterministic_fallback_runner": _profile_for_finding(finding),
            }
            for finding in findings
        ],
        "available_runner_profiles": profile_summary,
        "required_schema": {
            "overall_analysis": "short Chinese analysis of the likely challenge category and first move",
            "recommendations": [
                {
                    "finding_id": "integer",
                    "runner_profile": "one available runner_profile",
                    "rationale": "why this runner fits",
                    "focus_tools": ["tool names from the runner"],
                    "next_checks": ["safe validation checks"],
                    "confidence": "0.0-1.0",
                }
            ],
        },
    }

    ai_text = await AIClient(db).chat(
        json.dumps(prompt, ensure_ascii=False, indent=2),
        system="你是授权 CTF/靶场的执行前分析调度助手。你只输出 JSON，并且只能从平台提供的存量 Runner 中选择。",
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
        item["ai_recommendation"] = {
            "rationale": recommendation.get("rationale", "AI recommendation unavailable; deterministic fallback was used."),
            "focus_tools": recommendation.get("focus_tools", item["tools"][:5]),
            "next_checks": recommendation.get("next_checks", []),
            "confidence": recommendation.get("confidence", 0),
            "fallback_runner": fallback,
        }

    base_plan["ai_initial_analysis"] = ai_data.get(
        "overall_analysis",
        "AI 未返回可解析的结构化分析，平台已使用安全的确定性 Runner 选择逻辑。",
    )
    base_plan["ai_planning_mode"] = "ai_guided_with_deterministic_fallback"
    base_plan["reasoning_summary"] = (
        "AI analyzed selected findings and recommended stock runner profiles before execution. "
        "The platform applied runner allow-list validation and deterministic fallback where needed."
    )
    return base_plan


def dumps_plan(plan: dict[str, Any]) -> str:
    return json.dumps(plan, ensure_ascii=False, indent=2)


def loads_plan(plan_json: str) -> dict[str, Any]:
    return json.loads(plan_json or "{}")
