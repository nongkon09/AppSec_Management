"""Monthly executive summary (docs: README "Reports").

Figures are counted per issue, an (application, vulnerability) pair, the same way the
dashboard counts them, so a CVE open in two versions of one application is one issue.

History is reconstructed from timestamps on the findings (first detected, fixed) rather
than from daily snapshots, which means two approximations for past months:
- "open at month end" only looks at versions that are active today, because version
  activity is not recorded historically;
- a finding's due date and severity are today's values, so an exception approved later
  is already reflected.
The month in progress is read as of now ("so far"), not as of its future end date.
"""

import statistics
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import CurrentUser
from app.models.finding import SEVERITY_ORDER, Finding, FindingStatus, SeverityTier
from app.models.inventory import Application, AppVersion
from app.models.risk_exception import ExceptionItem, ExceptionStatus, RiskException
from app.models.user import Role
from app.schemas.report import (
    ApplicationSummary,
    ExceptionFigures,
    ExecutiveSummary,
    MonthFigures,
    RiskItem,
    SeveritySummary,
)

TREND_MONTHS = 6
TOP_RISKS = 8
TOP_APPLICATIONS = 5
EXPIRY_WINDOW_DAYS = 30
_RANK = {tier: index for index, tier in enumerate(SEVERITY_ORDER)}
_URGENT = {SeverityTier.CRITICAL, SeverityTier.HIGH}


@dataclass(frozen=True)
class _Row:
    finding_id: uuid.UUID
    app_id: uuid.UUID
    app_name: str
    owner_team: str
    issue_key: str
    tier: SeverityTier
    kev: bool
    detected: datetime
    fixed: datetime | None
    status: FindingStatus
    due: date | None
    sla_start: date
    active: bool
    label: str
    plan_target: date | None


@dataclass(frozen=True)
class _Month:
    key: str
    start: datetime
    end: datetime  # exclusive
    # The instant the month's state is read at: its end, or now for the month in progress.
    cutoff: datetime
    # The day "overdue" is judged against: the last day, or today for the month in progress.
    as_of: date

    @property
    def last_day(self) -> date:
        return (self.end - timedelta(days=1)).date()

    @property
    def partial(self) -> bool:
        return self.cutoff < self.end


def month_period(year: int, month: int, now: datetime) -> _Month:
    start = datetime(year, month, 1, tzinfo=UTC)
    end = datetime(year + (month == 12), month % 12 + 1, 1, tzinfo=UTC)
    if now < end:
        return _Month(f"{year:04d}-{month:02d}", start, end, cutoff=now, as_of=now.date())
    return _Month(
        f"{year:04d}-{month:02d}", start, end, cutoff=end, as_of=(end - timedelta(days=1)).date()
    )


def _previous(period: _Month, now: datetime) -> _Month:
    last = period.start - timedelta(days=1)
    return month_period(last.year, last.month, now)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _worst(tiers: Iterable[SeverityTier]) -> SeverityTier:
    return min(tiers, key=lambda tier: _RANK[tier])


def _median(values: list[int]) -> float | None:
    return round(float(statistics.median(values)), 1) if values else None


def _load_rows(db: Session, current_user: CurrentUser) -> list[_Row]:
    stmt = (
        select(Finding, Application, AppVersion.is_active)
        .join(AppVersion, Finding.app_version_id == AppVersion.id)
        .join(Application, AppVersion.application_id == Application.id)
        # False positives and "not affected" decisions were never real exposure.
        .where(Finding.status != FindingStatus.SUPPRESSED)
    )
    if current_user.role == Role.DEV_TEAM:
        stmt = stmt.where(Application.owner_team == (current_user.owner_team or ""))
    rows = []
    for finding, application, active in db.execute(stmt).all():
        rows.append(
            _Row(
                finding_id=finding.id,
                app_id=application.id,
                app_name=application.app_name,
                owner_team=application.owner_team,
                issue_key=finding.issue_key,
                tier=finding.effective_severity_tier,
                kev=finding.kev_flag,
                detected=_aware(finding.first_detected_at),
                fixed=_aware(finding.fixed_at) if finding.fixed_at else None,
                status=finding.status,
                due=finding.due_date,
                sla_start=finding.sla_started_on,
                active=bool(active),
                label=finding.cve_id or finding.title or finding.issue_key,
                plan_target=finding.remediation_target_date,
            )
        )
    return rows


def _is_open(row: _Row, at: datetime) -> bool:
    """Open at an instant: detected by then, not fixed by then, in a version in use,
    and not currently covered by an accepted risk (those are reported as exceptions)."""
    if not row.active or row.status == FindingStatus.RISK_ACCEPTED or row.detected >= at:
        return False
    return row.fixed is None or row.fixed >= at


def _group(rows: Iterable[_Row]) -> dict[tuple[uuid.UUID, str], list[_Row]]:
    issues: dict[tuple[uuid.UUID, str], list[_Row]] = {}
    for row in rows:
        issues.setdefault((row.app_id, row.issue_key), []).append(row)
    return issues


def _open_issues(
    issues: dict[tuple[uuid.UUID, str], list[_Row]], at: datetime
) -> dict[tuple[uuid.UUID, str], list[_Row]]:
    result = {}
    for key, rows in issues.items():
        open_rows = [row for row in rows if _is_open(row, at)]
        if open_rows:
            result[key] = open_rows
    return result


def _earliest_due(rows: list[_Row]) -> date | None:
    dues = [row.due for row in rows if row.due is not None]
    return min(dues) if dues else None


def _figures(
    issues: dict[tuple[uuid.UUID, str], list[_Row]], period: _Month
) -> tuple[MonthFigures, dict[SeverityTier, SeveritySummary]]:
    per_tier = {
        tier: SeveritySummary(
            severity_tier=tier,
            open_at_end=0,
            overdue_at_end=0,
            new=0,
            fixed=0,
            median_days_to_fix=None,
        )
        for tier in SEVERITY_ORDER
    }
    days_to_fix: dict[SeverityTier, list[int]] = {tier: [] for tier in SEVERITY_ORDER}
    open_at_end = _open_issues(issues, period.cutoff)
    overdue = new = fixed = on_time = with_due = 0

    for rows in open_at_end.values():
        tier = _worst(row.tier for row in rows)
        due = _earliest_due(rows)
        per_tier[tier].open_at_end += 1
        if due is not None and due < period.as_of:
            overdue += 1
            per_tier[tier].overdue_at_end += 1

    for key, rows in issues.items():
        tier = _worst(row.tier for row in rows)
        first_seen = min(row.detected for row in rows)
        if period.start <= first_seen < period.end:
            new += 1
            per_tier[tier].new += 1
        fixed_rows = [row for row in rows if row.fixed and period.start <= row.fixed < period.end]
        if not fixed_rows or key in open_at_end:
            continue
        fixed += 1
        per_tier[tier].fixed += 1
        fixed_on = max(row.fixed for row in fixed_rows if row.fixed).date()
        days_to_fix[tier].append((fixed_on - min(row.sla_start for row in rows)).days)
        due = _earliest_due(fixed_rows)
        if due is not None:
            with_due += 1
            on_time += int(fixed_on <= due)

    for tier, values in days_to_fix.items():
        per_tier[tier].median_days_to_fix = _median(values)
    figures = MonthFigures(
        month=period.key,
        open_at_end=len(open_at_end),
        overdue_at_end=overdue,
        new=new,
        fixed=fixed,
        fixed_on_time=on_time,
        on_time_percent=round(on_time / with_due * 100, 1) if with_due else None,
        median_days_to_fix=_median([v for values in days_to_fix.values() for v in values]),
    )
    return figures, per_tier


def _top_risks(
    issues: dict[tuple[uuid.UUID, str], list[_Row]], period: _Month
) -> tuple[list[RiskItem], list[ApplicationSummary], int]:
    as_of = period.as_of
    risks: list[RiskItem] = []
    apps: dict[uuid.UUID, ApplicationSummary] = {}
    kev_open = 0
    for (app_id, _), rows in _open_issues(issues, period.cutoff).items():
        tier = _worst(row.tier for row in rows)
        kev = any(row.kev for row in rows)
        kev_open += int(kev)
        lead = min(rows, key=lambda row: (row.due or date.max, _RANK[row.tier]))
        due = _earliest_due(rows)
        days_overdue = max((as_of - due).days, 0) if due else 0
        entry = apps.setdefault(
            app_id,
            ApplicationSummary(
                application_id=app_id,
                application_name=lead.app_name,
                owner_team=lead.owner_team,
                open_at_end=0,
                critical=0,
                high=0,
                overdue_at_end=0,
            ),
        )
        entry.open_at_end += 1
        entry.critical += int(tier == SeverityTier.CRITICAL)
        entry.high += int(tier == SeverityTier.HIGH)
        entry.overdue_at_end += int(days_overdue > 0)
        if tier in _URGENT or kev or days_overdue > 0:
            risks.append(
                RiskItem(
                    finding_id=lead.finding_id,
                    label=lead.label,
                    application_name=lead.app_name,
                    owner_team=lead.owner_team,
                    severity_tier=tier,
                    kev=kev,
                    due_date=due,
                    days_overdue=days_overdue,
                    plan_target_date=lead.plan_target,
                )
            )
    risks.sort(key=lambda r: (-r.days_overdue, _RANK[r.severity_tier], not r.kev, r.label))
    ranked_apps = sorted(
        (app for app in apps.values() if app.open_at_end),
        key=lambda a: (-a.critical, -a.overdue_at_end, -a.high, a.application_name),
    )
    return risks[:TOP_RISKS], ranked_apps[:TOP_APPLICATIONS], kev_open


def _exception_figures(db: Session, current_user: CurrentUser, period: _Month) -> ExceptionFigures:
    stmt = select(RiskException)
    if current_user.role == Role.DEV_TEAM:
        team_apps = select(Application.id).where(
            Application.owner_team == (current_user.owner_team or "")
        )
        stmt = stmt.where(
            RiskException.id.in_(
                select(ExceptionItem.exception_id).where(
                    ExceptionItem.application_id.in_(team_apps)
                )
            )
        )
    approved = active = pending = expiring = 0
    horizon = period.as_of + timedelta(days=EXPIRY_WINDOW_DAYS)
    ended = {ExceptionStatus.EXPIRED, ExceptionStatus.REVOKED, ExceptionStatus.CLOSED}
    for exception in db.execute(stmt).scalars():
        if exception.status == ExceptionStatus.PENDING:
            pending += 1
            continue
        decided = _aware(exception.decided_at) if exception.decided_at else None
        was_approved = exception.status == ExceptionStatus.APPROVED or exception.status in ended
        if not was_approved or decided is None or decided >= period.cutoff:
            continue
        if decided >= period.start:
            approved += 1
        still_running = exception.status == ExceptionStatus.APPROVED or (
            _aware(exception.updated_at) >= period.cutoff
        )
        if still_running and exception.expires_on > period.as_of:
            active += 1
            if exception.status == ExceptionStatus.APPROVED and exception.expires_on <= horizon:
                expiring += 1
    return ExceptionFigures(
        approved_in_month=approved,
        active_at_end=active,
        pending_now=pending,
        expiring_next_30_days=expiring,
    )


def _stale_versions(db: Session, current_user: CurrentUser) -> int:
    stmt = (
        select(AppVersion.id)
        .join(Application, AppVersion.application_id == Application.id)
        .where(AppVersion.is_active.is_(True), AppVersion.is_stale.is_(True))
    )
    if current_user.role == Role.DEV_TEAM:
        stmt = stmt.where(Application.owner_team == (current_user.owner_team or ""))
    return len(db.execute(stmt).all())


def executive_summary(
    db: Session,
    current_user: CurrentUser,
    year: int,
    month: int,
    now: datetime | None = None,
) -> ExecutiveSummary:
    now = now or datetime.now(UTC)
    period = month_period(year, month, now)
    issues = _group(_load_rows(db, current_user))
    current, per_tier = _figures(issues, period)
    previous, _ = _figures(issues, _previous(period, now))

    trend_periods = [period]
    for _ in range(TREND_MONTHS - 1):
        trend_periods.insert(0, _previous(trend_periods[0], now))
    trend = [current if p is period else _figures(issues, p)[0] for p in trend_periods]

    risks, applications, kev_open = _top_risks(issues, period)
    return ExecutiveSummary(
        period_start=period.start.date(),
        period_end=period.last_day,
        as_of=period.as_of,
        is_partial=period.partial,
        generated_at=now,
        generated_by=current_user.username,
        scope_team=current_user.owner_team if current_user.role == Role.DEV_TEAM else None,
        current=current,
        previous=previous,
        trend=trend,
        by_severity=list(per_tier.values()),
        kev_open_at_end=kev_open,
        top_risks=risks,
        applications=applications,
        exceptions=_exception_figures(db, current_user, period),
        stale_sbom_versions=_stale_versions(db, current_user),
    )


def parse_month(value: str, today: date) -> tuple[int, int]:
    """'YYYY-MM' to (year, month); a future month has nothing to report."""
    try:
        parsed = datetime.combine(date.fromisoformat(f"{value}-01"), time.min)
    except ValueError as error:
        raise ValueError("month must be YYYY-MM") from error
    if (parsed.year, parsed.month) > (today.year, today.month):
        raise ValueError("month is in the future")
    return parsed.year, parsed.month
