"""Finding backlog queries and manual intake (Requirement.md FR-3.3, FR-5.4, FR-10.2).

All reads go through `_scoped_finding_query`, which applies the Section 4 data scoping
rule: a Dev Team / Tech Lead only ever sees Findings belonging to Applications their team
owns, while AppSec / Audit / Management / Admin see the whole organisation.
"""

import logging
import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime

from sqlalchemy import Integer, Select, func, select
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
    VexStatus,
)
from app.models.inventory import Application, AppVersion
from app.models.pentest import PentestProject, PentestStatus
from app.models.user import Role
from app.modules.integrations import service as integrations_service
from app.modules.policy import service as policy_service
from app.schemas.finding import (
    ApplicationBacklog,
    BacklogSummary,
    FindingCreate,
    FindingUpdate,
    SeverityBreakdown,
    VexUpdate,
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


def _apply_filters(
    stmt: Select[tuple[Finding]],
    *,
    today: date,
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
    if severity:
        stmt = stmt.where(Finding.severity_tier.in_(list(severity)))
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
    skip: int = 0,
    limit: int = 50,
    today: date | None = None,
) -> tuple[list[Finding], int]:
    as_of = today or datetime.now(UTC).date()
    filters = {
        "today": as_of,
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
            Finding.severity_tier.asc(),
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
    items.sort(key=lambda f: (_SEVERITY_SORT[f.severity_tier], f.due_date or date.max))
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
    """FR-5.4: open Finding counts per Severity and SLA state, plus a per-Application
    breakdown for the FR-10.1 organisation overview."""
    as_of = today or datetime.now(UTC).date()
    overdue_clause = Finding.due_date.is_not(None) & (Finding.due_date < as_of)

    base = _scoped_finding_query(current_user).where(Finding.status == FindingStatus.OPEN)
    if application_id is not None:
        base = base.where(Application.id == application_id)

    severity_rows = db.execute(
        base.with_only_columns(
            Finding.severity_tier,
            func.count().label("total"),
            func.sum(func.cast(overdue_clause, Integer)).label("overdue"),
        ).group_by(Finding.severity_tier)
    ).all()

    counts: dict[SeverityTier, tuple[int, int]] = {}
    for tier, total, overdue in severity_rows:
        counts[SeverityTier(tier)] = (int(total or 0), int(overdue or 0))

    by_severity = [
        SeverityBreakdown(
            severity_tier=tier,
            total=counts.get(tier, (0, 0))[0],
            overdue=counts.get(tier, (0, 0))[1],
            within_sla=counts.get(tier, (0, 0))[0] - counts.get(tier, (0, 0))[1],
        )
        for tier in SEVERITY_ORDER
    ]

    total_open = sum(item.total for item in by_severity)
    total_overdue = sum(item.overdue for item in by_severity)

    app_rows = db.execute(
        base.with_only_columns(
            Application.id,
            Application.app_name,
            Application.owner_team,
            Finding.severity_tier,
            func.count().label("total"),
            func.sum(func.cast(overdue_clause, Integer)).label("overdue"),
        ).group_by(
            Application.id, Application.app_name, Application.owner_team, Finding.severity_tier
        )
    ).all()

    per_app: dict[uuid.UUID, ApplicationBacklog] = {}
    for app_id, app_name, owner_team, tier, total, overdue in app_rows:
        entry = per_app.setdefault(
            app_id,
            ApplicationBacklog(
                application_id=app_id, application_name=app_name, owner_team=owner_team
            ),
        )
        setattr(entry, SeverityTier(tier).value, int(total or 0))
        entry.total += int(total or 0)
        entry.overdue += int(overdue or 0)

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

    scope = "production"
    if payload.component_id is not None:
        component = db.get(Component, payload.component_id)
        if component is not None:
            scope = component.scope

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

    finding = Finding(
        **payload.model_dump(exclude={"severity_tier"}),
        severity_tier=tier,
        status=FindingStatus.OPEN,
        policy_version=policy.version,
        due_date=policy_service.compute_due_date(policy, tier, detected_on),
        first_detected_at=datetime.now(UTC),
    )
    db.add(finding)
    db.flush()
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
            "due_date": finding.due_date.isoformat() if finding.due_date else None,
            "policy_version": finding.policy_version,
        },
    )
    db.commit()
    db.refresh(finding)

    try:
        # FR-7.2: route this manually created Finding to whatever connector is
        # configured for its Severity Tier, same as an SBOM-synced one. Best-effort —
        # an ITSM outage must not fail the Finding creation itself.
        integrations_service.route_finding_to_connectors(db, finding, actor=actor)
    except Exception:  # noqa: BLE001 - ticket routing is best-effort
        logger.exception("FR-7.2 routing failed for finding %s", finding.id)

    return finding


# FR-8.1: setting VEX to one of these means the vulnerability does not need remediation
# (component absent, code path unreachable, compensating control, etc.) — the Finding
# drops out of the active backlog.
_VEX_SUPPRESSING_STATUSES = (VexStatus.NOT_AFFECTED, VexStatus.FIXED)


def update_vex_status(db: Session, finding: Finding, payload: VexUpdate, actor: str) -> Finding:
    """FR-8.1/8.2: only AppSec/Admin can call this (enforced at the router) — that
    restriction *is* the approval step for a VEX decision."""
    before_vex = finding.vex_status
    before_status = finding.status
    finding.vex_status = payload.vex_status
    finding.vex_justification = payload.vex_justification

    if payload.vex_status in _VEX_SUPPRESSING_STATUSES:
        finding.status = FindingStatus.SUPPRESSED
    elif finding.status == FindingStatus.SUPPRESSED:
        # Reopening a previously-suppressed Finding: affected/under_investigation both
        # mean it is back on the backlog.
        finding.status = FindingStatus.OPEN

    record_audit(
        db,
        actor=actor,
        action="finding.update_vex",
        entity_type="finding",
        entity_id=finding.id,
        before={"vex_status": before_vex.value, "status": before_status.value},
        after={"vex_status": finding.vex_status.value, "status": finding.status.value},
    )
    db.commit()
    db.refresh(finding)
    return finding


def global_suppress_vex(db: Session, cve_id: str, payload: VexUpdate, actor: str) -> list[Finding]:
    """FR-8.3: the single Global Suppression mechanism — apply the same VEX decision to
    every currently-OPEN Finding sharing this CVE, across every Application. Applied one
    Finding at a time (not a bulk UPDATE) so each gets its own FR-11.1 audit entry."""
    findings = list(
        db.execute(
            select(Finding).where(Finding.cve_id == cve_id, Finding.status == FindingStatus.OPEN)
        )
        .scalars()
        .all()
    )
    updated = [update_vex_status(db, finding, payload, actor) for finding in findings]
    record_audit(
        db,
        actor=actor,
        action="finding.global_vex_suppress",
        entity_type="cve",
        entity_id=cve_id,
        after={
            "vex_status": payload.vex_status.value,
            "vex_justification": payload.vex_justification,
            "affected_finding_count": len(updated),
        },
    )
    db.commit()
    return updated


def update_remediation_plan(
    db: Session, finding: Finding, payload: FindingUpdate, actor: str
) -> Finding:
    """FR-10.2 + FR-11.1: record the plan with who changed it and the previous value."""
    before = finding.remediation_plan
    finding.remediation_plan = payload.remediation_plan
    finding.remediation_plan_updated_by = actor
    finding.remediation_plan_updated_at = datetime.now(UTC)
    record_audit(
        db,
        actor=actor,
        action="finding.update_remediation_plan",
        entity_type="finding",
        entity_id=finding.id,
        before={"remediation_plan": before},
        after={"remediation_plan": finding.remediation_plan},
    )
    db.commit()
    db.refresh(finding)
    return finding
