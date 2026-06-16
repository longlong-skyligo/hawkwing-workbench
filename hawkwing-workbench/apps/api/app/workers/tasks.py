from datetime import datetime
import asyncio

from app.config import get_settings
from app.db import SessionLocal
from app.models import AuditLog, Finding, PentestJob, ScanJob, Target
from app.services.evidence import index_artifacts
from app.services.runner import RunnerManager
from app.services.runner_ai_analysis import analyze_runner_artifacts
from app.services.state_bus import emit_state_event
from app.workers.celery_app import celery_app


@celery_app.task
def run_scan_job(scan_job_id: int) -> None:
    db = SessionLocal()
    try:
        job = db.get(ScanJob, scan_job_id)
        if not job:
            return
        job.status = "running"
        db.commit()

        targets = db.query(Target).filter(Target.workspace_id == job.workspace_id, Target.enabled == 1).all()
        for target in targets:
            db.add(
                Finding(
                    workspace_id=job.workspace_id,
                    target=target.value,
                    title="Example high-value entry: web service or admin surface needs review",
                    severity="high",
                    confidence=0.72,
                    risk_score=8.1,
                    status="ranked",
                    source_tool="mvp-scan-simulator",
                    raw_detail="MVP simulator finding. Replace with parsed runner-recon-basic output in the next implementation phase.",
                )
            )

        job.status = "completed"
        job.result_summary = f"Scan completed. Processed {len(targets)} targets."
        job.finished_at = datetime.utcnow()
        db.add(AuditLog(workspace_id=job.workspace_id, action="scan.completed", detail=job.result_summary))
        db.commit()
        emit_state_event(
            db,
            workspace_id=job.workspace_id,
            event_type="finding.created",
            source="scan-worker",
            data={"scan_job_id": scan_job_id, "target_count": len(targets)},
        )
    finally:
        db.close()


@celery_app.task
def run_pentest_job(pentest_job_id: int) -> None:
    db = SessionLocal()
    settings = get_settings()
    try:
        job = db.get(PentestJob, pentest_job_id)
        if not job:
            return
        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        emit_state_event(
            db,
            workspace_id=job.workspace_id,
            event_type="runner.started",
            source=job.runner_profile,
            target_ref=job.target,
            data={"pentest_job_id": job.id, "finding_id": job.finding_id},
        )

        runner = RunnerManager()
        result = runner.run_validation(
            job_id=job.id,
            workspace_id=job.workspace_id,
            target=job.target,
            finding_id=job.finding_id,
            image=job.runner_image or settings.runner_web_image,
        )

        job.status = "completed" if result["exit_code"] == 0 else "failed"
        job.container_id = result["container_id"]
        try:
            analysis_path = asyncio.run(analyze_runner_artifacts(db, job, result["artifact_dir"]))
            emit_state_event(
                db,
                workspace_id=job.workspace_id,
                event_type="runner.ai_analysis.created",
                source="ai-runner-analyzer",
                target_ref=job.target,
                data={"pentest_job_id": job.id, "path": str(analysis_path)},
            )
        except Exception as analysis_exc:
            emit_state_event(
                db,
                workspace_id=job.workspace_id,
                event_type="runner.ai_analysis.failed",
                source="ai-runner-analyzer",
                target_ref=job.target,
                data={"pentest_job_id": job.id, "error": str(analysis_exc)},
            )
        evidence_count = index_artifacts(db, job.workspace_id, job.id, result["artifact_dir"])
        job.result_summary = (
            f"Runner finished with exit code {result['exit_code']}. "
            f"Indexed {evidence_count} evidence files at {result['artifact_dir']}."
        )
        job.finished_at = datetime.utcnow()
        db.add(AuditLog(workspace_id=job.workspace_id, action="pentest.completed", detail=job.result_summary))
        db.commit()
        emit_state_event(
            db,
            workspace_id=job.workspace_id,
            event_type="runner.completed",
            source=job.runner_profile,
            target_ref=job.target,
            data={
                "pentest_job_id": job.id,
                "finding_id": job.finding_id,
                "container_id": job.container_id,
                "status": job.status,
                "artifact_dir": result.get("artifact_dir"),
                "evidence_count": evidence_count,
            },
        )
    except Exception as exc:
        job = db.get(PentestJob, pentest_job_id)
        if job:
            job.status = "failed"
            job.result_summary = str(exc)
            job.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()
