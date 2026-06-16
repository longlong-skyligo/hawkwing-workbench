from dataclasses import dataclass

from app.services.catalog import get_dynamic_runner_policy


@dataclass
class PolicyResult:
    allowed: bool
    reasons: list[str]


def check_dynamic_dockerfile(dockerfile: str) -> PolicyResult:
    policy = get_dynamic_runner_policy().get("dynamic_runner_policy", {})
    denied = policy.get("denied_dockerfile_patterns", [])
    reasons: list[str] = []
    lowered = dockerfile.lower()
    for pattern in denied:
        if str(pattern).lower() in lowered:
            reasons.append(f"Denied pattern found: {pattern}")
    if "from " not in lowered:
        reasons.append("Dockerfile must include a FROM line.")
    return PolicyResult(allowed=not reasons, reasons=reasons)


def propose_dynamic_runner(scenario_text: str) -> dict:
    dockerfile = "\n".join(
        [
            "FROM debian:12-slim",
            "RUN apt-get update && apt-get install -y --no-install-recommends \\",
            "    ca-certificates curl jq python3 python3-pip file binutils \\",
            "    && rm -rf /var/lib/apt/lists/*",
            "WORKDIR /runner",
        ]
    )
    policy_result = check_dynamic_dockerfile(dockerfile)
    return {
        "runner_type": "dynamic",
        "name": "dynamic-analysis-runner",
        "base_image": "debian:12-slim",
        "purpose": scenario_text or "Specialized analysis where stock runners are insufficient.",
        "dockerfile": dockerfile,
        "risk_level": "high",
        "requires_approval": True,
        "policy_allowed": policy_result.allowed,
        "policy_reasons": policy_result.reasons,
        "network": "restricted",
        "timeout_seconds": 1800,
    }

