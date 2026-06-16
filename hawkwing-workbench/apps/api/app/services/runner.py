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

    def run_validation(self, job_id: int, workspace_id: int, target: str, finding_id: int, image: str, plan_context: dict | None = None) -> dict:
        artifact_dir = Path(self.settings.artifact_root) / f"workspace-{workspace_id}" / f"pentest-job-{job_id}"
        artifact_dir.mkdir(parents=True, exist_ok=True)
        self._ensure_image_available(image)

        input_payload = {
            "workspace_id": workspace_id,
            "job_id": job_id,
            "target": target,
            "finding_id": finding_id,
            "mode": "controlled_validation",
            "plan_context": plan_context or {},
        }
        (artifact_dir / "input.json").write_text(json.dumps(input_payload, ensure_ascii=False, indent=2), encoding="utf-8")

        container = self.client.containers.run(
            image=image,
            command=["/out/input.json", "/out"],
            volumes={str(artifact_dir): {"bind": "/out", "mode": "rw"}},
            detach=True,
            auto_remove=False,
            mem_limit="2g",
            nano_cpus=2_000_000_000,
            network_mode="bridge",
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
