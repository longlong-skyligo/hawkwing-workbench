from datetime import datetime
from pathlib import Path
import json

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db, init_db
from app.models import (
    AuditLog,
    EvidenceFile,
    ExecutionPlan,
    Finding,
    PentestJob,
    ScanJob,
    SessionReference,
    Target,
    Workspace,
    WorkspaceStateEvent,
)
from app.schemas import (
    AIAnalyzeRequest,
    AIConfigUpdate,
    ExecutionPlanApproveRequest,
    ExecutionPlanAssessRequest,
    PentestBatchStart,
    ScanStart,
    SessionReferenceCreate,
    TargetImport,
    ToolRunRequest,
    WorkspaceCreate,
    WorkspaceOut,
)
from app.services.catalog import get_dynamic_runner_policy, get_runner_profiles, get_skill_registry, get_tool_catalog
from app.services.execution_planner import build_ai_guided_execution_plan, dumps_plan, loads_plan
from app.services.ai_client import AIClient, public_ai_config, resolve_ai_config, upsert_ai_config
from app.services.reporting import generate_workspace_report
from app.services.state_bus import emit_state_event
from app.workers.tasks import run_pentest_job, run_scan_job

settings = get_settings()
app = FastAPI(title=settings.app_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "app": settings.app_name}


@app.get("/api/ai/config")
def ai_config(db: Session = Depends(get_db)) -> dict:
    return public_ai_config(resolve_ai_config(db))


@app.put("/api/ai/config")
def update_ai_config(payload: AIConfigUpdate, db: Session = Depends(get_db)) -> dict:
    config = upsert_ai_config(
        db,
        provider=payload.provider,
        api_base=payload.api_base,
        api_key=payload.api_key,
        model=payload.model,
    )
    db.add(AuditLog(actor="operator", action="ai.config.updated", detail=f"provider={config.provider}, model={config.model}"))
    db.commit()
    return public_ai_config(config)


@app.get("/api/tools/catalog")
def tool_catalog() -> dict:
    return get_tool_catalog()


@app.get("/api/runners/profiles")
def runner_profiles() -> dict:
    return get_runner_profiles()


@app.get("/api/skills")
def skill_registry() -> dict:
    return get_skill_registry()


@app.get("/api/policies/dynamic-runner")
def dynamic_runner_policy() -> dict:
    return get_dynamic_runner_policy()


@app.get("/api/workspaces/{workspace_id}/stage-summary")
def stage_summary(workspace_id: int, db: Session = Depends(get_db)):
    target_count = db.query(Target).filter(Target.workspace_id == workspace_id).count()
    scan_jobs = db.query(ScanJob).filter(ScanJob.workspace_id == workspace_id).all()
    finding_count = db.query(Finding).filter(Finding.workspace_id == workspace_id).count()
    reviewed_count = db.query(Finding).filter(Finding.workspace_id == workspace_id, Finding.status != "new").count()
    plans = db.query(ExecutionPlan).filter(ExecutionPlan.workspace_id == workspace_id).all()
    jobs = db.query(PentestJob).filter(PentestJob.workspace_id == workspace_id).all()
    evidence_count = db.query(EvidenceFile).filter(EvidenceFile.workspace_id == workspace_id).count()
    session_count = db.query(SessionReference).filter(SessionReference.workspace_id == workspace_id).count()
    report_path = Path(settings.report_root) / f"workspace-{workspace_id}-report.md"

    def status(done: bool, active: bool = False) -> str:
        if active:
            return "active"
        return "done" if done else "pending"

    return {
        "stages": [
            {"key": "targets", "label": "Targets", "status": status(target_count > 0), "count": target_count},
            {
                "key": "scan",
                "label": "Scan",
                "status": status(any(job.status == "completed" for job in scan_jobs), any(job.status == "running" for job in scan_jobs)),
                "count": len(scan_jobs),
            },
            {"key": "review", "label": "Review", "status": status(reviewed_count > 0), "count": finding_count},
            {"key": "plan", "label": "Plan", "status": status(bool(plans), any(plan.status in {"draft", "approved"} for plan in plans)), "count": len(plans)},
            {
                "key": "execute",
                "label": "Execute",
                "status": status(any(job.status == "completed" for job in jobs), any(job.status == "running" for job in jobs)),
                "count": len(jobs),
            },
            {"key": "evidence", "label": "Evidence", "status": status(evidence_count > 0), "count": evidence_count},
            {"key": "sessions", "label": "Sessions", "status": status(session_count > 0), "count": session_count},
            {"key": "report", "label": "Report", "status": status(report_path.exists()), "count": 1 if report_path.exists() else 0},
        ]
    }


@app.post("/api/ai/analyze")
async def ai_analyze(payload: AIAnalyzeRequest, db: Session = Depends(get_db)) -> dict:
    result = await AIClient(db).chat(payload.prompt)
    return {"workspace_id": payload.workspace_id, "result": result}


@app.post("/api/workspaces", response_model=WorkspaceOut)
def create_workspace(payload: WorkspaceCreate, db: Session = Depends(get_db)):
    workspace = Workspace(name=payload.name, description=payload.description)
    db.add(workspace)
    db.commit()
    db.refresh(workspace)
    db.add(AuditLog(workspace_id=workspace.id, action="workspace.created", detail=workspace.name))
    db.commit()
    return workspace


@app.get("/api/workspaces")
def list_workspaces(db: Session = Depends(get_db)):
    return db.query(Workspace).order_by(Workspace.id.desc()).all()


@app.get("/api/workspaces/{workspace_id}")
def get_workspace(workspace_id: int, db: Session = Depends(get_db)):
    workspace = db.get(Workspace, workspace_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="workspace not found")
    return workspace


@app.post("/api/workspaces/{workspace_id}/targets/import")
def import_targets(workspace_id: int, payload: TargetImport, db: Session = Depends(get_db)):
    if not db.get(Workspace, workspace_id):
        raise HTTPException(status_code=404, detail="workspace not found")
    for item in payload.targets:
        value = item.strip()
        if not value:
            continue
        target_type = "url" if value.startswith(("http://", "https://")) else "cidr" if "/" in value else "ip"
        db.add(Target(workspace_id=workspace_id, value=value, type=target_type))
    db.add(AuditLog(workspace_id=workspace_id, action="targets.imported", detail=f"count={len(payload.targets)}"))
    db.commit()
    return {"imported": len(payload.targets)}


@app.get("/api/workspaces/{workspace_id}/targets")
def list_targets(workspace_id: int, db: Session = Depends(get_db)):
    return db.query(Target).filter(Target.workspace_id == workspace_id).all()


@app.post("/api/workspaces/{workspace_id}/scan/start")
def start_scan(workspace_id: int, payload: ScanStart, db: Session = Depends(get_db)):
    if not db.get(Workspace, workspace_id):
        raise HTTPException(status_code=404, detail="workspace not found")
    job = ScanJob(workspace_id=workspace_id, mode=payload.mode, status="queued")
    db.add(job)
    db.commit()
    db.refresh(job)
    run_scan_job.delay(job.id)
    return {"scan_job_id": job.id, "status": job.status}


@app.get("/api/workspaces/{workspace_id}/findings")
def list_findings(workspace_id: int, db: Session = Depends(get_db)):
    return db.query(Finding).filter(Finding.workspace_id == workspace_id).order_by(Finding.risk_score.desc()).all()


@app.post("/api/workspaces/{workspace_id}/pentest/batch")
def start_batch_pentest(workspace_id: int, payload: PentestBatchStart, db: Session = Depends(get_db)):
    jobs = []
    for finding_id in payload.finding_ids:
        finding = db.get(Finding, finding_id)
        if not finding or finding.workspace_id != workspace_id:
            continue
        job = PentestJob(
            workspace_id=workspace_id,
            finding_id=finding.id,
            target=finding.target,
            runner_image=payload.runner_image or settings.runner_web_image,
            runner_profile=payload.runner_profile or "runner-web-basic",
            plan_id=payload.plan_id,
            status="queued",
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        run_pentest_job.delay(job.id)
        jobs.append(job.id)
    db.add(AuditLog(workspace_id=workspace_id, action="pentest.batch_started", detail=f"jobs={jobs}"))
    db.commit()
    return {"pentest_job_ids": jobs}


@app.post("/api/workspaces/{workspace_id}/execution-plans/assess")
async def assess_execution_plan(workspace_id: int, payload: ExecutionPlanAssessRequest, db: Session = Depends(get_db)):
    if not db.get(Workspace, workspace_id):
        raise HTTPException(status_code=404, detail="workspace not found")
    plan_data = await build_ai_guided_execution_plan(
        db=db,
        workspace_id=workspace_id,
        finding_ids=payload.finding_ids,
        scenario_text=payload.scenario_text,
        allow_dynamic=payload.allow_dynamic,
    )
    plan = ExecutionPlan(
        workspace_id=workspace_id,
        status="draft",
        objective=plan_data["objective"],
        selected_finding_ids=json.dumps(payload.finding_ids),
        plan_json=dumps_plan(plan_data),
        risk_summary=plan_data["reasoning_summary"],
        requires_approval=1,
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    db.add(AuditLog(workspace_id=workspace_id, action="execution_plan.created", detail=f"plan_id={plan.id}"))
    db.add(
        WorkspaceStateEvent(
            workspace_id=workspace_id,
            event_type="execution_plan.created",
            source="execution-planner",
            target_ref=f"execution_plan:{plan.id}",
            data_json=plan.plan_json,
        )
    )
    db.commit()
    return {"plan_id": plan.id, "plan": plan_data}


@app.get("/api/workspaces/{workspace_id}/execution-plans")
def list_execution_plans(workspace_id: int, db: Session = Depends(get_db)):
    plans = db.query(ExecutionPlan).filter(ExecutionPlan.workspace_id == workspace_id).order_by(ExecutionPlan.id.desc()).all()
    return [
        {
            "id": plan.id,
            "workspace_id": plan.workspace_id,
            "status": plan.status,
            "objective": plan.objective,
            "risk_summary": plan.risk_summary,
            "requires_approval": bool(plan.requires_approval),
            "approved_by": plan.approved_by,
            "created_at": plan.created_at,
            "plan": loads_plan(plan.plan_json),
        }
        for plan in plans
    ]


@app.get("/api/execution-plans/{plan_id}")
def get_execution_plan(plan_id: int, db: Session = Depends(get_db)):
    plan = db.get(ExecutionPlan, plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="execution plan not found")
    return {
        "id": plan.id,
        "workspace_id": plan.workspace_id,
        "status": plan.status,
        "objective": plan.objective,
        "risk_summary": plan.risk_summary,
        "requires_approval": bool(plan.requires_approval),
        "approved_by": plan.approved_by,
        "created_at": plan.created_at,
        "plan": loads_plan(plan.plan_json),
    }


@app.post("/api/execution-plans/{plan_id}/approve")
def approve_execution_plan(plan_id: int, payload: ExecutionPlanApproveRequest, db: Session = Depends(get_db)):
    plan = db.get(ExecutionPlan, plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="execution plan not found")
    plan.status = "approved"
    plan.approved_by = payload.approved_by
    plan.approved_at = datetime.utcnow()
    db.add(AuditLog(workspace_id=plan.workspace_id, action="execution_plan.approved", detail=f"plan_id={plan.id}"))
    db.commit()
    return {"plan_id": plan.id, "status": plan.status}


@app.post("/api/execution-plans/{plan_id}/execute")
def execute_execution_plan(plan_id: int, db: Session = Depends(get_db)):
    plan = db.get(ExecutionPlan, plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="execution plan not found")
    if plan.status != "approved":
        raise HTTPException(status_code=400, detail="execution plan must be approved before execution")

    plan_data = loads_plan(plan.plan_json)
    jobs = []
    for item in plan_data.get("containers", []):
        finding_id = int(item.get("finding_id", 0))
        finding = db.get(Finding, finding_id)
        if not finding:
            continue
        job = PentestJob(
            workspace_id=plan.workspace_id,
            finding_id=finding.id,
            target=finding.target,
            runner_image=item.get("image", settings.runner_web_image),
            runner_profile=item.get("runner_profile", "runner-web-basic"),
            plan_id=plan.id,
            plan_item_name=item.get("name", ""),
            status="queued",
        )
        db.add(job)
        db.commit()
        db.refresh(job)
        run_pentest_job.delay(job.id)
        jobs.append(job.id)

    plan.status = "executing"
    plan.executed_at = datetime.utcnow()
    db.add(AuditLog(workspace_id=plan.workspace_id, action="execution_plan.executed", detail=f"jobs={jobs}"))
    db.commit()
    return {"plan_id": plan.id, "pentest_job_ids": jobs, "dynamic_images": plan_data.get("dynamic_images", [])}


@app.get("/api/workspaces/{workspace_id}/state-events")
def workspace_state_events(workspace_id: int, db: Session = Depends(get_db)):
    return db.query(WorkspaceStateEvent).filter(WorkspaceStateEvent.workspace_id == workspace_id).order_by(WorkspaceStateEvent.id.desc()).limit(200).all()


@app.get("/api/workspaces/{workspace_id}/evidence")
def list_evidence(workspace_id: int, db: Session = Depends(get_db)):
    return db.query(EvidenceFile).filter(EvidenceFile.workspace_id == workspace_id).order_by(EvidenceFile.id.desc()).limit(500).all()


@app.post("/api/workspaces/{workspace_id}/sessions")
def register_session(workspace_id: int, payload: SessionReferenceCreate, db: Session = Depends(get_db)):
    if not db.get(Workspace, workspace_id):
        raise HTTPException(status_code=404, detail="workspace not found")
    session = SessionReference(
        workspace_id=workspace_id,
        session_type=payload.session_type,
        target=payload.target,
        tool=payload.tool,
        status=payload.status,
        approval_ref=payload.approval_ref,
        notes=payload.notes,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    emit_state_event(
        db,
        workspace_id=workspace_id,
        event_type="session.reference.created",
        source="operator",
        target_ref=f"session:{session.id}",
        data={
            "session_type": session.session_type,
            "target": session.target,
            "tool": session.tool,
            "status": session.status,
            "approval_ref": session.approval_ref,
        },
    )
    return session


@app.get("/api/workspaces/{workspace_id}/sessions")
def list_sessions(workspace_id: int, db: Session = Depends(get_db)):
    return db.query(SessionReference).filter(SessionReference.workspace_id == workspace_id).order_by(SessionReference.id.desc()).all()


@app.post("/api/workspaces/{workspace_id}/tools/run")
def run_tool_from_catalog(workspace_id: int, payload: ToolRunRequest, db: Session = Depends(get_db)):
    tools = get_tool_catalog().get("tools", {})
    tool = tools.get(payload.tool)
    if not tool:
        raise HTTPException(status_code=404, detail="tool not found")
    if tool.get("status") == "disabled":
        raise HTTPException(status_code=400, detail="tool is disabled by policy")
    profile = payload.runner_profile or tool.get("runner_profile") or "runner-web-basic"
    profiles = get_runner_profiles().get("runner_profiles", {})
    profile_data = profiles.get(profile)
    if not profile_data:
        raise HTTPException(status_code=404, detail="runner profile not found")
    finding = Finding(
        workspace_id=workspace_id,
        target=payload.target,
        title=f"Manual tool run: {payload.tool}",
        severity="medium",
        confidence=0.5,
        risk_score=5.0,
        status="selected_for_validation",
        source_tool=payload.tool,
        raw_detail=payload.purpose,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    job = PentestJob(
        workspace_id=workspace_id,
        finding_id=finding.id,
        target=payload.target,
        runner_image=profile_data.get("image", settings.runner_web_image),
        runner_profile=profile,
        plan_item_name=f"manual-{payload.tool}",
        status="queued",
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    run_pentest_job.delay(job.id)
    return {"pentest_job_id": job.id, "finding_id": finding.id, "runner_profile": profile}


@app.get("/api/workspaces/{workspace_id}/pentest-jobs")
def list_pentest_jobs(workspace_id: int, db: Session = Depends(get_db)):
    return db.query(PentestJob).filter(PentestJob.workspace_id == workspace_id).order_by(PentestJob.id.desc()).all()


@app.post("/api/workspaces/{workspace_id}/report/generate")
def generate_report(workspace_id: int, db: Session = Depends(get_db)):
    path = generate_workspace_report(db, workspace_id)
    return {"report_path": str(path)}


@app.get("/api/workspaces/{workspace_id}/report/download")
def download_report(workspace_id: int, db: Session = Depends(get_db)):
    path = generate_workspace_report(db, workspace_id)
    if not Path(path).exists():
        raise HTTPException(status_code=404, detail="report not found")
    return FileResponse(path, filename=Path(path).name, media_type="text/markdown")


@app.get("/api/workspaces/{workspace_id}/audit-logs")
def audit_logs(workspace_id: int, db: Session = Depends(get_db)):
    return db.query(AuditLog).filter(AuditLog.workspace_id == workspace_id).order_by(AuditLog.id.desc()).all()
