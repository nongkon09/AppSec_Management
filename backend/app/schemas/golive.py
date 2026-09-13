import uuid
from datetime import datetime

from pydantic import BaseModel


class GoLiveChecklist(BaseModel):
    """Requirement.md FR-6.1: the three-part Go-Live checklist for one Application
    Version. `ready` is true only when every applicable part passes."""

    app_version_id: uuid.UUID
    sbom_pass: bool
    sbom_blocking_count: int
    sast_pass: bool
    sast_blocking_count: int
    pentest_required: bool
    pentest_pass: bool
    pentest_blocking_count: int
    ready: bool


class GoLiveApprovalOut(BaseModel):
    id: uuid.UUID
    app_version_id: uuid.UUID
    sbom_pass: bool
    sast_pass: bool
    pentest_pass: bool
    approver: str
    is_break_glass: bool
    created_at: datetime

    model_config = {"from_attributes": True}
