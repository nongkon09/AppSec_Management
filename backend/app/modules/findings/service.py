"""Finding backlog queries and manual intake (Requirement.md FR-3.3, FR-5.4, FR-10.2).

All reads go through `_scoped_finding_query`, which applies the Section 4 data scoping
rule: a Dev Team / Tech Lead only ever sees Findings belonging to Applications their team
owns, while AppSec / Audit / Management / Admin see the whole organisation.
"""

import logging
import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, joinedload

from app.core.audit import record_audit
from app.core.deps import CurrentUser
from app.models.component import Component
from app.models.finding import (
    SEVERITY_ORDER,
    Finding,
    FindingSource,
    FindingStatus,
    SeverityTier,
    build_issue_key,
)
from app.models.inventory import Application, AppVersion
from app.models.pentest import PentestProject, PentestStatus
from app.models.user import Role
from app.modules.exceptions import coverage as exception_coverage
from app.modules.findings import sla
from app.modules.integrations import service as integrations_service
from app.modules.policy import service as policy_service
from app.schemas.finding import (
    ApplicationBacklog,
    BacklogSummary,
    FindingCreate,
    FindingUpdate,
    SeverityBreakdown,
)

logger = logging.getLogger(__name__)

SLA_STATUS_OVERDUE = "overdue"
SLA_STATUS_WITHIN = "within_sla"

# Orders the backlog by urgency rather than alphabetically: Critical first, and within a
# tier the Findings closest to (or furthest past) their due date first.
_SEVERITY_SORT = {tier: index for index, tier in enumerate(SEVERITY_ORDER)}


def _scoped_finding_query(current_user: CurrentUser) -> Select[tuple[Finding]]:
    """Base SELECT joined up to Application, with Section 4 data scoping applied."""
    stmt = (
        select(Finding)
        .join(AppVersion, Finding.app_version_id == AppVersion.id)
        .join(Application, AppVersion.application_id == Application.id)
    )
    if current_user.role == Role.DEV_TEAM:
        # A Dev Team user without an owner_team assigned can see nothing rather than
        # everything — fail closed (Section 4 Data Scoping).
        stmt = stmt.where(Application.owner_team == (current_user.owner_team or ""))
    return stmt


# Residual tier when an approved exception set one, otherwise the policy tier.
EFFECTIVE_TIER = func.coalesce(Finding.residual_severity_tier, Finding.severity_tier)


def _apply_filters(
    stmt: Select[tuple[Finding]],
    *,
    today: date,
    include_inactive_versions: bool = False,
    application_id: uuid.UUID | None = None,
    app_version_id: uuid.UUID | None = None,
    severity: Sequence[SeverityTier] | None = None,
    status: Sequence[FindingStatus] | None = None,
    source: str | None = None,
    sla_status: str | None = None,
    search: str | None = None,
) -> Select[tuple[Finding]]:
    if application_id is not None:
        stmt = stmt.where(Application.id == application_id)
    if app_version_id is not None:
        stmt = stmt.where(Finding.app_version_id == app_version_id)
    elif not include_inactive_versions:
        # docs/risk-exception-design.md 3.3: only versions in use count toward the backlog.
        stmt = stmt.where(AppVersion.is_active.is_(True))
    if severity:
        stmt = stmt.where(EFFECTIVE_TIER.in_(list(severity)))
    if status:
        stmt = stmt.where(Finding.status.in_(list(status)))
    if source:
        stmt = stmt.where(Finding.source == source)
    if sla_status == SLA_STATUS_OVERDUE:
        stmt = stmt.where(
            Finding.status == FindingStatus.OPEN,
            Finding.due_date.is_not(None),
            Finding.due_date < today,
        )
    elif sla_status == SLA_STATUS_WITHIN:
        stmt = stmt.where(
            (Finding.status != FindingStatus.OPEN)
            | Finding.due_date.is_(None)
            | (Finding.due_date >= today)
        )
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            Finding.cve_id.ilike(pattern)
            | Finding.title.ilike(pattern)
            | Application.app_name.ilike(pattern)
        )
    return stmt


def list_findings(
    db: Session,
    current_user: CurrentUser,
    *,
    application_id: uuid.UUID | None = None,
    app_version_id: uuid.UUID | None = None,
    severity: Sequence[SeverityTier] | None = None,
    status: Sequence[FindingStatus] | None = None,
    source: str | None = None,
    sla_status: str | None = None,
    search: str | None = None,
    include_inactive_versions: bool = False,
    skip: int = 0,
    limit: int = 50,
    today: date | None = None,
) -> tuple[list[Finding], int]:
    as_of = today or datetime.now(UTC).date()
    filters = {
        "today": as_of,
        "include_inactive_versions": include_inactive_versions,
        "application_id": application_id,
        "app_version_id": app_version_id,
        "severity": severity,
        "status": status,
        "source": source,
        "sla_status": sla_status,
        "search": search,
    }

    base = _apply_filters(_scoped_finding_query(current_user), **filters)  # type: ignore[arg-type]
    total = db.execute(select(func.count()).select_from(base.subquery())).scalar_one()

    page = (
        base.options(
            joinedload(Finding.component),
            joinedload(Finding.app_version).joinedload(AppVersion.application),
        )
        # due_date ascending puts the most urgent first; NULL (best-effort) sorts last.
        .order_by(
            EFFECTIVE_TIER.asc(),
            Finding.due_date.is_(None).asc(),
            Finding.due_date.asc(),
            Finding.first_detected_at.desc(),
        )
        .offset(skip)
        .limit(limit)
    )
    items = list(db.execute(page).unique().scalars().all())
    # severity_tier is a VARCHAR enum, so the DB sorts it alphabetically; re-order by the
    # real tier ranking in Python (page-sized, so the cost is bounded).
    items.sort(key=lambda f: (_SEVERITY_SORT[f.effective_severity_tier], f.due_date or date.max))
    return items, total


def get_finding(db: Session, current_user: CurrentUser, finding_id: uuid.UUID) -> Finding | None:
    stmt = _scoped_finding_query(current_user).where(Finding.id == finding_id)
    return (
        db.execute(
            stmt.options(
                joinedload(Finding.component),
                joinedload(Finding.app_version).joinedload(AppVersion.application),
            )
        )
        .unique()
        .scalar_one_or_none()
    )


def backlog_summary(
    db: Session,
    current_user: CurrentUser,
    *,
    application_id: uuid.UUID | None = None,
    today: date | None = None,
) -> BacklogSummary:
    """FR-5.4 open counts per Severity and SLA state, plus a per-Application breakdown.

    Counts issues, not rows: the same vulnerability open in two active versions of one
    Application (say production and staging) is one issue, taken at its most severe tier
    and earliest due date.
    """
    as_of = today or datetime.now(UTC).date()
    stmt = _apply_filters(
        _scoped_finding_query(current_user).where(Finding.status == FindingStatus.OPEN),
        today=as_of,
        application_id=application_id,
    ).with_only_columns(
        Application.id,
        Application.app_name,
        Application.owner_team,
        Finding.issue_key,
        Finding.severity_tier,
        Finding.residual_severity_tier,
        Finding.due_date,
    )

    issues: dict[tuple[uuid.UUID, str], tuple[str, str, SeverityTier, date | None]] = {}
    for app_id, app_name, owner_team, issue_key, tier, residual, due in db.execute(stmt).all():
        effective = SeverityTier(residual or tier)
        key = (app_id, issue_key)
        current = issues.get(key)
        if current is None:
            issues[key] = (app_name, owner_team, effective, due)
            continue
        worst = min(current[2], effective, key=lambda t: _SEVERITY_SORT[t])
        dues = [d for d in (current[3], due) if d is not None]
        issues[key] = (app_name, owner_team, worst, min(dues) if dues else None)

    counts = {tier: [0, 0] for tier in SEVERITY_ORDER}
    per_app: dict[uuid.UUID, ApplicationBacklog] = {}
    for (app_id, _), (app_name, owner_team, tier, due) in issues.items():
        overdue = due is not None and due < as_of
        counts[tier][0] += 1
        counts[tier][1] += int(overdue)
        entry = per_app.setdefault(
            app_id,
            ApplicationBacklog(
                application_id=app_id, application_name=app_name, owner_team=owner_team
            ),
        )
        setattr(entry, tier.value, getattr(entry, tier.value) + 1)
        entry.total += 1
        entry.overdue += int(overdue)

    by_severity = [
        SeverityBreakdown(
            severity_tier=tier,
            total=counts[tier][0],
            overdue=counts[tier][1],
            within_sla=counts[tier][0] - counts[tier][1],
        )
        for tier in SEVERITY_ORDER
    ]
    total_open = sum(item.total for item in by_severity)
    total_overdue = sum(item.overdue for item in by_severity)
    by_application = sorted(
        per_app.values(),
        key=lambda a: (-a.critical, -a.high, -a.overdue, a.application_name),
    )
    return BacklogSummary(
        total_open=total_open,
        total_overdue=total_overdue,
        sla_compliance_percent=(
            round((total_open - total_overdue) / total_open * 100, 1) if total_open else None
        ),
        by_severity=by_severity,
        by_application=by_application,
    )


class PentestFindingNotAllowedError(ValueError):
    """FR-6.5.6: a Pentest Finding must reference a Pentest Project, and only counts
    toward the Backlog/SLA once that project has reached Report Final or later."""


def create_finding(db: Session, payload: FindingCreate, actor: str) -> Finding:
    """Record a Finding that arrived outside the automated SBOM feed.

    Severity comes from the effective policy's rule engine unless the caller supplied an
    explicit tier (Pentest testers assign severity themselves, FR-6.5.5), and the due date
    always comes from the SLA policy in force today (FR-5.2).
    """
    if payload.source == FindingSource.PENTEST:
        if payload.pentest_project_id is None:
            raise PentestFindingNotAllowedError(
                "A Pentest Finding must reference a pentest_project_id"
            )
        project = db.get(PentestProject, payload.pentest_project_id)
        if project is None:
            raise PentestFindingNotAllowedError("Pentest Project not found")
        if project.status not in (
            PentestStatus.REPORT_FINAL,
            PentestStatus.REMEDIATION_VERIFICATION,
            PentestStatus.CLOSED,
        ):
            raise PentestFindingNotAllowedError(
                "Pentest Findings can only be added once the Project reaches "
                "Report Final / Delivered"
            )

    detected_on = datetime.now(UTC).date()
    policy = policy_service.get_effective_policy(db, detected_on)
    version = db.get(AppVersion, payload.app_version_id)
    if version is None:
        raise ValueError("Application version not found")

    scope = "production"
    component_name = component_purl = None
    if payload.component_id is not None:
        component = db.get(Component, payload.component_id)
        if component is not None:
            scope = component.scope
            component_name = component.component_name
            component_purl = component.purl

    if payload.severity_tier is not None:
        tier = payload.severity_tier
    else:
        tier = policy_service.evaluate_severity(
            policy,
            cvss=payload.cvss,
            epss=payload.epss,
            kev_flag=payload.kev_flag,
            scope=scope,
        ).tier

    issue_key = payload.issue_key or build_issue_key(
        payload.source,
        component_name=component_name,
        purl=component_purl,
        cve_id=payload.cve_id,
        title=payload.title,
        pentest_project_id=payload.pentest_project_id,
    )
    finding = Finding(
        **payload.model_dump(exclude={"severity_tier", "issue_key"}),
        severity_tier=tier,
        status=FindingStatus.OPEN,
        policy_version=policy.version,
        issue_key=issue_key,
        sla_started_on=sla.resolve_sla_start(
            db, version.application_id, issue_key, today=detected_on
        ),
        first_detected_at=datetime.now(UTC),
    )
    sla.refresh_due_date(policy, finding)
    db.add(finding)
    db.flush()
    exception_coverage.apply_to_finding(db, finding, actor=actor)
    record_audit(
        db,
        actor=actor,
        action="finding.create_manual",
        entity_type="finding",
        entity_id=finding.id,
        after={
            "app_version_id": str(finding.app_version_id),
            "source": finding.source.value,
            "cve_id": finding.cve_id,
            "title": finding.title,
            "severity_tier": finding.severity_tier.value,
            "issue_key": finding.issue_key,
            "sla_started_on": finding.sla_started_on.isoformat(),
            "due_date": finding.due_date.isoformat() if finding.due_date else None,
            "policy_version": finding.policy_version,
        },
    )
    db.commit()
    db.refresh(finding)

    if finding.status != FindingStatus.OPEN:
        return finding  # covered by an approved exception; nothing to ticket
    try:
        # FR-7.2: route this manually created Finding to whatever connector is
        # configured for its Severity Tier, same as an SBOM-synced one. Best-effort —
        # an ITSM outage must not fail the Finding creation itself.
        integrations_service.route_finding_to_connectors(db, finding, actor=actor)
    except Exception:  # noqa: BLE001 - ticket routing is best-effort
        logger.exception("FR-7.2 routing failed for finding %s", finding.id)

    return finding


def _plan_state(finding: Finding) -> dict[str, str | None]:
    return {
        "remediation_plan": finding.remediation_plan,
        "remediation_action": finding.remediation_action,
        "remediation_target_date": (
            finding.remediation_target_date.isoformat() if finding.remediation_target_date else None
        ),
    }


def update_remediation_plan(
    db: Session, finding: Finding, payload: FindingUpdate, actor: str
) -> Finding:
    """FR-10.2 + FR-11.1: record the plan with who changed it and the previous value."""
    before = _plan_state(finding)
    finding.remediation_plan = payload.remediation_plan
    finding.remediation_action = payload.remediation_action
    finding.remediation_target_date = payload.remediation_target_date
    finding.remediation_plan_updated_by = actor
    finding.remediation_plan_updated_at = datetime.now(UTC)
    record_audit(
        db,
        actor=actor,
        action="finding.update_remediation_plan",
        entity_type="finding",
        entity_id=finding.id,
        before=before,
        after=_plan_state(finding),
    )
    db.commit()
    db.refresh(finding)
    return finding
