from pydantic import BaseModel, Field


class WorkspaceCreate(BaseModel):
    name: str
    description: str = ""


class WorkspaceOut(BaseModel):
    id: int
    name: str
    description: str
    status: str

    class Config:
        from_attributes = True


class TargetImport(BaseModel):
    targets: list[str] = Field(default_factory=list)


class ScanStart(BaseModel):
    mode: str = "standard"


class PentestBatchStart(BaseModel):
    finding_ids: list[int]
    runner_image: str | None = None
    runner_profile: str | None = None
    plan_id: int | None = None


class AIAnalyzeRequest(BaseModel):
    workspace_id: int
    prompt: str


class AIConfigUpdate(BaseModel):
    provider: str = "openai"
    api_base: str = ""
    api_key: str = ""
    model: str = ""


class ExecutionPlanAssessRequest(BaseModel):
    finding_ids: list[int] = Field(default_factory=list)
    scenario_text: str = ""
    allow_dynamic: bool = True


class ExecutionPlanApproveRequest(BaseModel):
    approved_by: str = "operator"


class ToolRunRequest(BaseModel):
    target: str
    tool: str
    runner_profile: str | None = None
    purpose: str = ""


class SessionReferenceCreate(BaseModel):
    session_type: str = "pivot"
    target: str
    tool: str = ""
    status: str = "registered"
    approval_ref: str = ""
    notes: str = ""
