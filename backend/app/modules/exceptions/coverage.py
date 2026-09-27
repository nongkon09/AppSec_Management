"""How an approved exception changes the Findings it covers, including Findings that
appear later in new versions of the same Application."""

from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.models.finding import Finding, FindingStatus, VexStatus
from app.models.inventory import AppVersion
from app.models.risk_exception import (
    ExceptionItem,
    ExceptionStatus,
    ExceptionType,
    RiskException,
)
from app.modules.findings import sla
from app.modules.policy import service as policy_service

SYSTEM_ACTOR = "system"


def _today() -> date:
    return datetime.now(UTC).date()


def active_exception_for(
    db: Session, application_id: object, issue_key: str, today: date | None = None
) -> RiskException | None:
    as_of = today or _today()
    return (
        db.execute(
            select(RiskException)
            .join(ExceptionItem, ExceptionItem.exception_id == RiskException.id)
            .where(
                ExceptionItem.application_id == application_id,
                ExceptionItem.issue_key == issue_key,
                RiskException.status == ExceptionStatus.APPROVED,
                RiskException.expires_on >= as_of,
            )
        )
        .scalars()
        .first()
    )


def unresolved_findings(db: Session, item: ExceptionItem) -> list[Finding]:
    # populate_existing: decisions are made on current status, never on a copy an older
    # part of the same session loaded before another transaction changed it.
    return list(
        db.execute(
            select(Finding)
            .join(AppVersion, Finding.app_version_id == AppVersion.id)
            .where(
                AppVersion.application_id == item.application_id,
                Finding.issue_key == item.issue_key,
                Finding.status != FindingStatus.FIXED,
            )
            .execution_options(populate_existing=True)
        )
        .scalars()
        .all()
    )


def _apply_effect(finding: Finding, exception: RiskException) -> None:
    if exception.exception_type == ExceptionType.RISK_ACCEPTANCE:
        finding.status = FindingStatus.RISK_ACCEPTED
        finding.residual_severity_tier = exception.residual_severity_tier
    else:
        finding.status = FindingStatus.SUPPRESSED
        finding.vex_status = VexStatus.NOT_AFFECTED
        finding.vex_justification = (
            exception.vex_justification.value if exception.vex_justification else None
        )


def _snapshot(finding: Finding) -> dict[str, object]:
    return {
        "status": finding.status.value,
        "residual_severity_tier": (
            finding.residual_severity_tier.value if finding.residual_severity_tier else None
        ),
        "vex_status": finding.vex_status.value,
        "due_date": finding.due_date.isoformat() if finding.due_date else None,
    }


def apply_to_finding(db: Session, finding: Finding, actor: str = SYSTEM_ACTOR) -> bool:
    """Applies an approved exception covering this Finding's issue, if any. Called for
    Findings created or reintroduced after the exception was approved."""
    if finding.status == FindingStatus.FIXED:
        return False
    version = db.get(AppVersion, finding.app_version_id)
    if version is None:
        return False
    exception = active_exception_for(db, version.application_id, finding.issue_key)
    if exception is None:
        return False
    before = _snapshot(finding)
    _apply_effect(finding, exception)
    sla.refresh_due_date(policy_service.get_effective_policy(db, _today()), finding)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="finding.exception_applied",
        entity_type="finding",
        entity_id=finding.id,
        before=before,
        after={**_snapshot(finding), "exception": exception.reference},
    )
    return True


def apply_exception(db: Session, exception: RiskException, actor: str) -> int:
    """Applies a just-approved exception to every unresolved Finding it covers."""
    policy = policy_service.get_effective_policy(db, _today())
    count = 0
    for item in exception.items:
        for finding in unresolved_findings(db, item):
            before = _snapshot(finding)
            _apply_effect(finding, exception)
            sla.refresh_due_date(policy, finding)
            record_audit(
                db,
                actor=actor,
                action="finding.exception_applied",
                entity_type="finding",
                entity_id=finding.id,
                before=before,
                after={**_snapshot(finding), "exception": exception.reference},
            )
            count += 1
    db.flush()
    return count


def release_exception(db: Session, exception: RiskException, actor: str) -> int:
    """Returns covered Findings to the open backlog with their original tier; the SLA
    anchor is unchanged, so the due date usually falls in the past (intended)."""
    policy = policy_service.get_effective_policy(db, _today())
    count = 0
    for item in exception.items:
        for finding in unresolved_findings(db, item):
            if finding.status not in (FindingStatus.RISK_ACCEPTED, FindingStatus.SUPPRESSED):
                continue
            before = _snapshot(finding)
            finding.status = FindingStatus.OPEN
            finding.residual_severity_tier = None
            if exception.exception_type != ExceptionType.RISK_ACCEPTANCE:
                finding.vex_status = VexStatus.AFFECTED
                finding.vex_justification = None
            sla.refresh_due_date(policy, finding)
            record_audit(
                db,
                actor=actor,
                action="finding.exception_released",
                entity_type="finding",
                entity_id=finding.id,
                before=before,
                after={**_snapshot(finding), "exception": exception.reference},
            )
            count += 1
    db.flush()
    return count
