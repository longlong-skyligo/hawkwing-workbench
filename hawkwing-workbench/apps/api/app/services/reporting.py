from pathlib import Path
from jinja2 import Template
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import EvidenceFile, ExecutionPlan, Finding, PentestJob, SessionReference, Target, Workspace, WorkspaceStateEvent
from app.services.catalog import get_runner_profiles, get_skill_registry, get_tool_catalog
from app.services.execution_planner import loads_plan


def generate_workspace_report(db: Session, workspace_id: int) -> Path:
    settings = get_settings()
    workspace = db.get(Workspace, workspace_id)
    if not workspace:
        raise ValueError("workspace not found")

    targets = db.query(Target).filter(Target.workspace_id == workspace_id).all()
    findings = db.query(Finding).filter(Finding.workspace_id == workspace_id).order_by(Finding.risk_score.desc()).all()
    pentest_jobs = db.query(PentestJob).filter(PentestJob.workspace_id == workspace_id).all()
    execution_plans = db.query(ExecutionPlan).filter(ExecutionPlan.workspace_id == workspace_id).order_by(ExecutionPlan.id.desc()).all()
    state_events = db.query(WorkspaceStateEvent).filter(WorkspaceStateEvent.workspace_id == workspace_id).order_by(WorkspaceStateEvent.id.desc()).limit(50).all()
    evidence_files = db.query(EvidenceFile).filter(EvidenceFile.workspace_id == workspace_id).order_by(EvidenceFile.id.desc()).limit(100).all()
    sessions = db.query(SessionReference).filter(SessionReference.workspace_id == workspace_id).order_by(SessionReference.id.desc()).all()
    tool_catalog = get_tool_catalog().get("tools", {})
    runner_profiles = get_runner_profiles().get("runner_profiles", {})
    skills = get_skill_registry().get("skills", {})

    template_path = Path("/app/config/report-template.md")
    if not template_path.exists():
        template_path = Path("config/report-template.md")
    template = Template(template_path.read_text(encoding="utf-8"))

    report = template.render(
        workspace_name=workspace.name,
        status=workspace.status,
        target_count=len(targets),
        finding_count=len(findings),
        pentest_job_count=len(pentest_jobs),
        targets=targets,
        findings=findings,
        pentest_jobs=pentest_jobs,
        execution_plans=execution_plans,
        execution_plan_payloads=[loads_plan(plan.plan_json) for plan in execution_plans],
        state_events=state_events,
        evidence_files=evidence_files,
        sessions=sessions,
        tool_count=len(tool_catalog),
        runner_profile_count=len(runner_profiles),
        skill_count=len(skills),
        ai_summary="建议优先修复高风险、高置信度、面向外部暴露的入口，并结合平台证据进行复盘。",
    )

    out_dir = Path(settings.report_root)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"workspace-{workspace_id}-report.md"
    out_file.write_text(report, encoding="utf-8")
    return out_file
