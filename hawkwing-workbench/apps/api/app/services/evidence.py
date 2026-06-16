import hashlib
from pathlib import Path

from sqlalchemy.orm import Session

from app.models import EvidenceFile
from app.services.state_bus import emit_state_event


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in {".png", ".jpg", ".jpeg", ".webp"}:
        return "screenshot"
    if suffix in {".pcap", ".pcapng"}:
        return "pcap"
    if suffix == ".json":
        return "json"
    if suffix in {".log", ".txt"}:
        return "log"
    if "http" in path.parts:
        return "http"
    if "forensics" in path.parts:
        return "forensics"
    return "file"


def index_artifacts(db: Session, workspace_id: int, pentest_job_id: int, artifact_dir: str) -> int:
    root = Path(artifact_dir)
    if not root.exists():
        return 0

    count = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        db.add(
            EvidenceFile(
                workspace_id=workspace_id,
                pentest_job_id=pentest_job_id,
                file_type=_file_type(path),
                path=str(path),
                sha256=_sha256(path),
            )
        )
        count += 1

    db.commit()
    emit_state_event(
        db,
        workspace_id=workspace_id,
        event_type="evidence.created",
        source="evidence-indexer",
        target_ref=f"pentest_job:{pentest_job_id}",
        data={"artifact_dir": artifact_dir, "file_count": count},
    )
    return count

