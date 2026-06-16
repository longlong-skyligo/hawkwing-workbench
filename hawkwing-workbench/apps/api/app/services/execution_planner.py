import json
from typing import Any

from sqlalchemy.orm import Session

from app.models import Finding
from app.services.catalog import find_runner_profile, get_runner_profiles, get_skill_registry, get_tool_catalog
from app.services.dynamic_builder import propose_dynamic_runner


def _profile_for_finding(finding: Finding) -> str:
    text = f"{finding.title} {finding.raw_detail} {finding.source_tool}".lower()
    if any(token in text for token in ["ad", "active directory", "ldap", "smb", "kerberos", "domain"]):
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


def dumps_plan(plan: dict[str, Any]) -> str:
    return json.dumps(plan, ensure_ascii=False, indent=2)


def loads_plan(plan_json: str) -> dict[str, Any]:
    return json.loads(plan_json or "{}")

