import uuid
from datetime import date, datetime

from pydantic import BaseModel, Field, model_validator

from app.models.finding import FindingSource, FindingStatus, SeverityTier, VexStatus


class FindingCreate(BaseModel):
    """Manual Finding intake for sources that have no automated feed — Pentest findings
    are entered by hand (FR-6.5.5, Section 14) and SAST results can be recorded the same
    way until a SAST connector exists (Section 14 open item)."""

    app_version_id: uuid.UUID
    source: FindingSource
    component_id: uuid.UUID | None = None
    pentest_project_id: uuid.UUID | None = None
    cve_id: str | None = Field(default=None, max_length=64)
    title: str | None = Field(default=None, max_length=512)
    description: str | None = None
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    kev_flag: bool = False
    fixed_version: str | None = Field(default=None, max_length=255)
    reference_url: str | None = Field(default=None, max_length=1024)
    # Pentest findings carry a severity assigned by the tester rather than a CVSS-derived
    # tier, so an explicit tier overrides the rule engine when supplied (FR-6.5.5).
    severity_tier: SeverityTier | None = None
    # Optional stable identity for SAST findings (e.g. "sast:<rule>:<file>") so the same
    # issue recorded against a later version keeps its SLA clock and exceptions.
    issue_key: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def _require_identifier(self) -> "FindingCreate":
        if not self.cve_id and not self.title:
            raise ValueError("either cve_id or title is required to identify the Finding")
        return self


class FindingUpdate(BaseModel):
    """FR-10.2: the Dev Team's remediation plan is the one field they own on a Finding."""

    remediation_plan: str = Field(min_length=1, max_length=10_000)


class FindingOut(BaseModel):
    id: uuid.UUID
    app_version_id: uuid.UUID
    component_id: uuid.UUID | None
    pentest_project_id: uuid.UUID | None
    source: FindingSource
    cve_id: str | None
    title: str | None
    description: str | None
    cvss: float | None
    epss: float | None
    kev_flag: bool
    severity_tier: SeverityTier
    residual_severity_tier: SeverityTier | None
    effective_severity_tier: SeverityTier
    issue_key: str
    sla_started_on: date
    status: FindingStatus
    vex_status: VexStatus
    vex_justification: str | None
    due_date: date | None
    policy_version: int | None
    fixed_version: str | None
    reference_url: str | None
    remediation_plan: str | None
    remediation_plan_updated_by: str | None
    remediation_plan_updated_at: datetime | None
    first_detected_at: datetime
    fixed_at: datetime | None

    # Denormalised for the backlog table and the FR-10.5 drill-down breadcrumb, so the
    # list view does not need a request per row.
    application_id: uuid.UUID
    application_name: str
    owner_team: str
    version_label: str
    component_name: str | None
    component_version: str | None
    component_scope: str | None
    is_overdue: bool
    days_until_due: int | None

    model_config = {"from_attributes": True}


class PaginatedFindings(BaseModel):
    items: list[FindingOut]
    total: int = Field(ge=0)


class SeverityBreakdown(BaseModel):
    severity_tier: SeverityTier
    within_sla: int = 0
    overdue: int = 0
    total: int = 0


class ApplicationBacklog(BaseModel):
    application_id: uuid.UUID
    application_name: str
    owner_team: str
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    overdue: int = 0
    total: int = 0


class BacklogSummary(BaseModel):
    """FR-5.4 Backlog View: open Findings per severity and SLA state, per Application."""

    total_open: int = 0
    total_overdue: int = 0
    # FR-10.3 KPI: share of open Findings still inside their SLA window.
    sla_compliance_percent: float | None = None
    by_severity: list[SeverityBreakdown]
    by_application: list[ApplicationBacklog]
