from datetime import datetime
from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class Workspace(Base):
    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(50), default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    targets: Mapped[list["Target"]] = relationship(back_populates="workspace")
    findings: Mapped[list["Finding"]] = relationship(back_populates="workspace")
    pentest_jobs: Mapped[list["PentestJob"]] = relationship(back_populates="workspace")
    execution_plans: Mapped[list["ExecutionPlan"]] = relationship(back_populates="workspace")


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    type: Mapped[str] = mapped_column(String(50), default="ip")
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    enabled: Mapped[int] = mapped_column(Integer, default=1)

    workspace: Mapped[Workspace] = relationship(back_populates="targets")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="medium")
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    risk_score: Mapped[float] = mapped_column(Float, default=5.0)
    status: Mapped[str] = mapped_column(String(50), default="new")
    source_tool: Mapped[str] = mapped_column(String(100), default="system")
    raw_detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    workspace: Mapped[Workspace] = relationship(back_populates="findings")


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    mode: Mapped[str] = mapped_column(String(50), default="standard")
    status: Mapped[str] = mapped_column(String(50), default="queued")
    result_summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class PentestJob(Base):
    __tablename__ = "pentest_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"))
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    runner_image: Mapped[str] = mapped_column(String(200), nullable=False)
    runner_profile: Mapped[str] = mapped_column(String(100), default="runner-web-basic")
    plan_id: Mapped[int | None] = mapped_column(ForeignKey("execution_plans.id"), nullable=True)
    plan_item_name: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(50), default="queued")
    container_id: Mapped[str] = mapped_column(String(200), default="")
    result_summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    workspace: Mapped[Workspace] = relationship(back_populates="pentest_jobs")


class EvidenceFile(Base):
    __tablename__ = "evidence_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    pentest_job_id: Mapped[int | None] = mapped_column(ForeignKey("pentest_jobs.id"), nullable=True)
    file_type: Mapped[str] = mapped_column(String(50), default="log")
    path: Mapped[str] = mapped_column(String(1000), nullable=False)
    sha256: Mapped[str] = mapped_column(String(128), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int | None] = mapped_column(ForeignKey("workspaces.id"), nullable=True)
    actor: Mapped[str] = mapped_column(String(100), default="system")
    action: Mapped[str] = mapped_column(String(200), nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ExecutionPlan(Base):
    __tablename__ = "execution_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    status: Mapped[str] = mapped_column(String(50), default="draft")
    objective: Mapped[str] = mapped_column(Text, default="")
    selected_finding_ids: Mapped[str] = mapped_column(Text, default="[]")
    plan_json: Mapped[str] = mapped_column(Text, default="{}")
    risk_summary: Mapped[str] = mapped_column(Text, default="")
    requires_approval: Mapped[int] = mapped_column(Integer, default=1)
    approved_by: Mapped[str] = mapped_column(String(100), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    workspace: Mapped[Workspace] = relationship(back_populates="execution_plans")


class WorkspaceStateEvent(Base):
    __tablename__ = "workspace_state_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    source: Mapped[str] = mapped_column(String(200), default="system")
    target_ref: Mapped[str] = mapped_column(String(500), default="")
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AISettings(Base):
    __tablename__ = "ai_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    provider: Mapped[str] = mapped_column(String(50), default="openai")
    api_base: Mapped[str] = mapped_column(String(500), default="")
    api_key: Mapped[str] = mapped_column(Text, default="")
    model: Mapped[str] = mapped_column(String(200), default="gpt-4.1-mini")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AttackPathNode(Base):
    __tablename__ = "attack_path_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    node_type: Mapped[str] = mapped_column(String(100), nullable=False)
    label: Mapped[str] = mapped_column(String(500), nullable=False)
    ref: Mapped[str] = mapped_column(String(500), default="")
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AttackPathEdge(Base):
    __tablename__ = "attack_path_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    source_node_id: Mapped[int] = mapped_column(ForeignKey("attack_path_nodes.id"))
    target_node_id: Mapped[int] = mapped_column(ForeignKey("attack_path_nodes.id"))
    relation: Mapped[str] = mapped_column(String(200), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    data_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SessionReference(Base):
    __tablename__ = "session_references"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"))
    session_type: Mapped[str] = mapped_column(String(100), default="access")
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    tool: Mapped[str] = mapped_column(String(100), default="")
    status: Mapped[str] = mapped_column(String(50), default="registered")
    approval_ref: Mapped[str] = mapped_column(String(200), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
