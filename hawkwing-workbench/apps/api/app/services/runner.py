import json
from pathlib import Path

import docker
from docker.errors import ImageNotFound

from app.config import get_settings
from app.services.catalog import get_dynamic_runner_policy


LOCAL_STOCK_IMAGE_PREFIX = "hawkwing-runner-"


class RunnerManager:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.client = docker.from_env()

    def _host_path(self, container_path: Path) -> str:
        """Convert container path to host path for Docker volume mounts."""
        raw = str(container_path)
        host_root = self.settings.host_data_root
        if host_root:
            return raw.replace("/data/", host_root.rstrip("/") + "/", 1)
        return raw

    def run_validation(self, job_id: int, workspace_id: int, target: str, finding_id: int, image: str, plan_context: dict | None = None) -> dict:
        artifact_dir = Path(self.settings.artifact_root) / f"workspace-{workspace_id}" / f"pentest-job-{job_id}"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_image_available(image)

        input_payload = {
            "workspace_id": workspace_id,
            "job_id": job_id,
            "target": target,
            "finding_id": finding_id,
            "mode": "authorized_ctf_solve",
            "authorization": {
                "scope": "current_project_authorized_target_only",
                "objective": "recover_the_challenge_flag",
                "allowed_targets": [target],
                "tool_access": "runner_may_call_all_tools_available_inside_its_container",
                "permitted_ctf_actions": [
                    "web_reconnaissance",
                    "content_discovery_and_fuzzing",
                    "payload_construction",
                    "injection_testing",
                    "deserialization_testing",
                    "authentication_bypass_testing",
                    "local_file_read_or_source_disclosure_when_required_by_the_challenge",
                    "controlled_remote_code_execution_proof_when_required_by_the_challenge",
                    "flag_extraction_and_evidence_capture",
                ],
                "boundaries": [
                    "stay_within_allowed_targets",
                    "do_not_pivot_to_unlisted_third_party_hosts",
                    "do_not_persist_access_or_damage_services",
                    "record_exact_requests_commands_outputs_and_flags",
                ],
            },
            "plan_context": plan_context or {},
        }
        (artifact_dir / "input.json").write_text(json.dumps(input_payload, ensure_ascii=False, indent=2), encoding="utf-8")

        container = self.client.containers.run(
            image=image,
            command=["/out/input.json", "/out"],
            volumes={self._host_path(artifact_dir): {"bind": "/out", "mode": "rw"}},
            detach=True,
            auto_remove=False,
            mem_limit="2g",
            nano_cpus=2_000_000_000,
            network_mode="bridge",
            environment={
                "HAWKWING_AUTHORIZED_TARGET": target,
                "HAWKWING_CTF_MODE": "authorized_target_only",
                "HAWKWING_OBJECTIVE": "recover_flag",
                "HAWKWING_TOOL_ACCESS": "all_container_tools",
            },
            labels={
                "hawkwing-workspace": str(workspace_id),
                "hawkwing-job": str(job_id),
                "hawkwing-runner": "true",
            },
        )
        result = container.wait(timeout=1800)
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        (artifact_dir / "container.log").write_text(logs, encoding="utf-8")
        container_id = container.id
        container.remove(force=True)
        return {"container_id": container_id, "exit_code": result.get("StatusCode", -1), "artifact_dir": str(artifact_dir)}

    def _ensure_image_available(self, image: str) -> None:
        try:
            self.client.images.get(image)
        except ImageNotFound as exc:
            if image.startswith(LOCAL_STOCK_IMAGE_PREFIX):
                self._build_stock_runner(image)
                return
            if self._policy_allows_external_pull(image):
                self.client.images.pull(image)
                return
            raise RuntimeError(f"Image {image} is not available locally and is not allowed by dynamic runner pull policy.") from exc

    def _build_stock_runner(self, image: str) -> None:
        profile_name = image.split(":", 1)[0].removeprefix("hawkwing-")
        context_root = Path(self.settings.runner_build_context)
        dockerfile = context_root / profile_name / "Dockerfile"
        if profile_name == "runner-report":
            context_path = context_root / profile_name
            dockerfile_arg = "Dockerfile"
        else:
            context_path = context_root
            dockerfile_arg = f"{profile_name}/Dockerfile"

        if not dockerfile.exists():
            raise RuntimeError(
                f"Stock runner Dockerfile not found for {image}: {dockerfile}. "
                "Check RUNNER_BUILD_CONTEXT and the runners directory mount."
            )

        self.client.images.build(
            path=str(context_path),
            dockerfile=dockerfile_arg,
            tag=image,
            rm=True,
            forcerm=True,
        )

    def _policy_allows_external_pull(self, image: str) -> bool:
        policy = get_dynamic_runner_policy().get("dynamic_runner_policy", {})
        if not policy.get("allow_external_image_pull", False):
            return False
        if policy.get("deny_latest_tag", True) and (":" not in image or image.endswith(":latest")):
            return False
        registry = "docker.io"
        first = image.split("/", 1)[0]
        if "." in first or ":" in first:
            registry = first
        return registry in set(policy.get("allowed_registries", []))
