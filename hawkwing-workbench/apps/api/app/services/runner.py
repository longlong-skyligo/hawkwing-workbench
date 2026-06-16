import json
from pathlib import Path

import docker

from app.config import get_settings


class RunnerManager:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.client = docker.from_env()

    def run_validation(self, job_id: int, workspace_id: int, target: str, finding_id: int, image: str) -> dict:
        artifact_dir = Path(self.settings.artifact_root) / f"workspace-{workspace_id}" / f"pentest-job-{job_id}"
        artifact_dir.mkdir(parents=True, exist_ok=True)

        input_payload = {
            "workspace_id": workspace_id,
            "job_id": job_id,
            "target": target,
            "finding_id": finding_id,
            "mode": "controlled_validation",
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
        )
        result = container.wait(timeout=1800)
        logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        (artifact_dir / "container.log").write_text(logs, encoding="utf-8")
        container_id = container.id
        container.remove(force=True)
        return {"container_id": container_id, "exit_code": result.get("StatusCode", -1), "artifact_dir": str(artifact_dir)}
