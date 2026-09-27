import uuid
from datetime import date, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

from app.models.finding import SeverityTier
from app.models.risk_exception import (
    ApprovalDecision,
    ExceptionStatus,
    ExceptionType,
    VexJustification,
)
from app.models.security_control import ControlEffectiveness
from app.models.user import ApprovalLevel


class BypassTool(StrEnum):
    RHACS = "rhacs"
    HARBOR = "harbor"
    TRIVY = "trivy"
    INSPECTOR = "inspector"
    SAST = "sast"
    OTHER = "other"


class ExceptionCreate(BaseModel):
    """Either the Findings the request is raised from, or (AppSec only) a CVE to cover
    across every Application — the replacement for the old global VEX suppression."""

    exception_type: ExceptionType
    finding_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)
    cve_id: str | None = Field(default=None, min_length=1, max_length=64)
    reason: str = Field(min_length=10, max_length=10_000)
    evidence: str | None = Field(default=None, max_length=10_000)
    compensating_measures: str | None = Field(default=None, max_length=10_000)
    control_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)
    residual_severity_tier: SeverityTier | None = None
    vex_justification: VexJustification | None = None
    expires_on: date

    @model_validator(mode="after")
    def _check_shape(self) -> "ExceptionCreate":
        if bool(self.finding_ids) == bool(self.cve_id):
            raise ValueError("provide either finding_ids or cve_id")
        if self.exception_type == ExceptionType.RISK_ACCEPTANCE:
            if self.vex_justification is not None:
                raise ValueError("vex_justification applies to false_positive/not_affected only")
        else:
            if self.vex_justification is None:
                raise ValueError("vex_justification is required for false_positive/not_affected")
            if self.residual_severity_tier is not None:
                raise ValueError("residual_severity_tier applies to risk_acceptance only")
        return self


class ExceptionDecisionIn(BaseModel):
    comment: str | None = Field(default=None, max_length=5_000)


class ExceptionEndIn(BaseModel):
    reason: str = Field(min_length=5, max_length=5_000)


class BypassCreate(BaseModel):
    tool: BypassTool
    reference_url: str | None = Field(default=None, max_length=1024)
    note: str | None = Field(default=None, max_length=5_000)


class ExceptionItemOut(BaseModel):
    application_id: uuid.UUID
    application_name: str
    issue_key: str
    label: str
    origin_finding_id: uuid.UUID | None


class ExceptionApprovalOut(BaseModel):
    approver: str
    approver_level: ApprovalLevel
    decision: ApprovalDecision
    comment: str | None
    decided_at: datetime

    model_config = {"from_attributes": True}


class ExceptionBypassOut(BaseModel):
    tool: str
    reference_url: str | None
    note: str | None
    recorded_by: str
    bypassed_at: datetime

    model_config = {"from_attributes": True}


class ControlSummaryOut(BaseModel):
    id: uuid.UUID
    name: str
    effectiveness: ControlEffectiveness
    review_due_on: date
    is_active: bool

    model_config = {"from_attributes": True}


class ExceptionOut(BaseModel):
    id: uuid.UUID
    reference: str
    exception_type: ExceptionType
    status: ExceptionStatus
    requested_by: str
    created_at: datetime
    reason: str
    evidence: str | None
    compensating_measures: str | None
    vex_justification: VexJustification | None
    original_severity_tier: SeverityTier
    kev_involved: bool
    residual_severity_tier: SeverityTier | None
    expires_on: date
    required_approvals: int
    required_min_level: ApprovalLevel
    required_top_level: ApprovalLevel
    decided_at: datetime | None
    ended_by: str | None
    ended_reason: str | None
    is_legacy: bool
    needs_review: bool
    items: list[ExceptionItemOut]
    approvals: list[ExceptionApprovalOut]
    bypasses: list[ExceptionBypassOut]
    controls: list[ControlSummaryOut]
    # For the current user: whether they may approve now, or why not.
    can_approve: bool
    approve_refusal: str | None


class PaginatedExceptions(BaseModel):
    items: list[ExceptionOut]
    total: int = Field(ge=0)


class ExceptionSweepOut(BaseModel):
    expired: int
    closed: int
    flagged_for_review: int
