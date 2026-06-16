from datetime import datetime
import asyncio
import json
from pathlib import Path

from app.config import get_settings
from app.db import SessionLocal
from app.models import AuditLog, ExecutionPlan, Finding, PentestJob, ScanJob, Target
from app.services.evidence import index_artifacts
from app.services.runner import RunnerManager
from app.services.runner_ai_analysis import analyze_runner_artifacts
from app.services.state_bus import emit_state_event
from app.services.execution_planner import loads_plan
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
        plan_context = {}
        if job.plan_id:
            plan = db.get(ExecutionPlan, job.plan_id)
            if plan:
                plan_data = loads_plan(plan.plan_json)
                plan_context = {
                    "target_objective": plan_data.get("target_objective", ""),
                    "vulnerability_background": plan_data.get("vulnerability_background", ""),
                    "solution_strategies": plan_data.get("solution_strategies", []),
                    "container": next(
                        (
                            item
                            for item in plan_data.get("containers", [])
                            if int(item.get("finding_id", 0)) == job.finding_id and item.get("runner_profile") == job.runner_profile
                        ),
                        {},
                    ),
                }
        result = runner.run_validation(
            job_id=job.id,
            workspace_id=job.workspace_id,
            target=job.target,
            finding_id=job.finding_id,
            image=job.runner_image or settings.runner_web_image,
            plan_context=plan_context,
        )

        job.container_id = result["container_id"]

        # Skip AI analysis if runner produced no output (no result.json)
        result_path = Path(result["artifact_dir"]) / "result.json"
        runner_produced_output = result_path.exists()

        if runner_produced_output:
            try:
                analysis_path = asyncio.run(analyze_runner_artifacts(db, job, result["artifact_dir"], plan_context))
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
        else:
            job.status = "failed"
            job.result_summary = "Runner container produced no output (no result.json). The runner may have failed to execute. Check container.log for details."
            job.finished_at = datetime.utcnow()
            db.commit()
            return

        job.status = "completed" if result["exit_code"] == 0 else "failed"
        flag_note = ""
        # Read both result.json and flag-extraction.json (from Runner AI)
        all_candidates = []
        for candidate_file in ("result.json", "flag-extraction.json"):
            candidate_path = Path(result["artifact_dir"]) / candidate_file
            if candidate_path.exists():
                try:
                    data = json.loads(candidate_path.read_text(encoding="utf-8"))
                    candidates = data.get("flag_candidates") or []
                    for item in candidates:
                        value = item.get("candidate", "") if isinstance(item, dict) else str(item)
                        if value and value not in all_candidates:
                            all_candidates.append(value)
                except Exception:
                    pass
        if all_candidates:
            flag_note = f" Flag candidates: {', '.join(all_candidates[:5])}."
        evidence_count = index_artifacts(db, job.workspace_id, job.id, result["artifact_dir"])
        job.result_summary = (
            f"Runner finished with exit code {result['exit_code']}. "
            f"Indexed {evidence_count} evidence files at {result['artifact_dir']}.{flag_note}"
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
