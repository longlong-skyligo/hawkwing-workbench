import json
from typing import Any

from sqlalchemy.orm import Session

from app.models import WorkspaceStateEvent


def emit_state_event(
    db: Session,
    workspace_id: int,
    event_type: str,
    source: str,
    target_ref: str = "",
    data: dict[str, Any] | None = None,
) -> WorkspaceStateEvent:
    event = WorkspaceStateEvent(
        workspace_id=workspace_id,
        event_type=event_type,
        source=source,
        target_ref=target_ref,
        data_json=json.dumps(data or {}, ensure_ascii=False),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event

