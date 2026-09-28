import uuid
from datetime import date, datetime

from pydantic import BaseModel

from app.models.finding import SeverityTier


class MonthFigures(BaseModel):
    """Headline numbers for one calendar month, counted as issues (application +
    vulnerability), not per-version rows."""

    month: str  # YYYY-MM
    open_at_end: int
    overdue_at_end: int
    new: int
    fixed: int
    fixed_on_time: int
    # Share of issues fixed this month that were fixed by their SLA due date.
    on_time_percent: float | None
    median_days_to_fix: float | None


class SeveritySummary(BaseModel):
    severity_tier: SeverityTier
    open_at_end: int
    overdue_at_end: int
    new: int
    fixed: int
    median_days_to_fix: float | None


class RiskItem(BaseModel):
    finding_id: uuid.UUID
    label: str
    application_name: str
    owner_team: str
    severity_tier: SeverityTier
    kev: bool
    due_date: date | None
    days_overdue: int
    plan_target_date: date | None


class ApplicationSummary(BaseModel):
    application_id: uuid.UUID
    application_name: str
    owner_team: str
    open_at_end: int
    critical: int
    high: int
    overdue_at_end: int


class ExceptionFigures(BaseModel):
    approved_in_month: int
    active_at_end: int
    pending_now: int
    expiring_next_30_days: int


class ExecutiveSummary(BaseModel):
    period_start: date
    period_end: date
    # The day open/overdue figures are read at; today while the month is still running.
    as_of: date
    is_partial: bool
    generated_at: datetime
    generated_by: str
    # The owning team for a Dev Team reader; None means the whole organisation.
    scope_team: str | None
    current: MonthFigures
    previous: MonthFigures
    trend: list[MonthFigures]
    by_severity: list[SeveritySummary]
    kev_open_at_end: int
    top_risks: list[RiskItem]
    applications: list[ApplicationSummary]
    exceptions: ExceptionFigures
    stale_sbom_versions: int
