"""Exception/Waiver workflow (Requirement.md FR-6.2): Dev/Tech Lead requests an
exception with a reason and expiry date, AppSec approves or rejects it, and an
expiry sweep auto-reopens the Finding the moment the waiver lapses."""

import logging
from datetime import UTC, date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.audit import record_audit
from app.models.finding import Finding, FindingStatus
from app.models.inventory import Application, AppVersion
from app.models.waiver import Waiver, WaiverStatus
from app.schemas.waiver import WaiverCreate

logger = logging.getLogger(__name__)


class WaiverConflictError(ValueError):
    """Raised when a Finding already has a Pending or Active waiver."""


def list_waivers_for_finding(db: Session, finding_id) -> list[Waiver]:  # type: ignore[no-untyped-def]
    stmt = select(Waiver).where(Waiver.finding_id == finding_id).order_by(Waiver.created_at.desc())
    return list(db.execute(stmt).scalars().all())


def get_waiver(db: Session, waiver_id) -> Waiver | None:  # type: ignore[no-untyped-def]
    return db.get(Waiver, waiver_id)


def request_waiver(db: Session, finding: Finding, payload: WaiverCreate, actor: str) -> Waiver:
    existing = db.execute(
        select(Waiver).where(
            Waiver.finding_id == finding.id,
            Waiver.status.in_([WaiverStatus.PENDING, WaiverStatus.ACTIVE]),
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise WaiverConflictError(
            "This Finding already has a pending or active waiver; resolve it first"
        )

    waiver = Waiver(
        finding_id=finding.id,
        requested_by=actor,
        reason=payload.reason,
        expiry_date=payload.expiry_date,
        status=WaiverStatus.PENDING,
    )
    db.add(waiver)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="waiver.request",
        entity_type="waiver",
        entity_id=waiver.id,
        after={
            "finding_id": str(finding.id),
            "reason": waiver.reason,
            "expiry_date": waiver.expiry_date.isoformat(),
        },
    )
    db.commit()
    db.refresh(waiver)
    return waiver


def approve_waiver(db: Session, waiver: Waiver, finding: Finding, actor: str) -> Waiver:
    before_status = finding.status
    waiver.status = WaiverStatus.ACTIVE
    waiver.approved_by = actor
    finding.status = FindingStatus.RISK_ACCEPTED
    record_audit(
        db,
        actor=actor,
        action="waiver.approve",
        entity_type="waiver",
        entity_id=waiver.id,
        after={"status": waiver.status.value, "finding_status": finding.status.value},
    )
    record_audit(
        db,
        actor=actor,
        action="finding.status_change_waiver_approved",
        entity_type="finding",
        entity_id=finding.id,
        before={"status": before_status.value},
        after={"status": finding.status.value},
    )
    db.commit()
    db.refresh(waiver)
    return waiver


def reject_waiver(db: Session, waiver: Waiver, actor: str) -> Waiver:
    waiver.status = WaiverStatus.REJECTED
    waiver.approved_by = actor
    record_audit(
        db,
        actor=actor,
        action="waiver.reject",
        entity_type="waiver",
        entity_id=waiver.id,
        after={"status": waiver.status.value},
    )
    db.commit()
    db.refresh(waiver)
    return waiver


def revoke_waiver(db: Session, waiver: Waiver, finding: Finding, actor: str) -> Waiver:
    """Early revoke of an ACTIVE waiver (e.g. the compensating justification no longer
    holds) — reopens the Finding immediately unless a later scan already fixed it."""
    before_status = finding.status
    waiver.status = WaiverStatus.REVOKED
    if finding.status == FindingStatus.RISK_ACCEPTED:
        finding.status = FindingStatus.OPEN
    record_audit(
        db,
        actor=actor,
        action="waiver.revoke",
        entity_type="waiver",
        entity_id=waiver.id,
        after={"status": waiver.status.value, "finding_status": finding.status.value},
    )
    if before_status != finding.status:
        record_audit(
            db,
            actor=actor,
            action="finding.status_change_waiver_revoked",
            entity_type="finding",
            entity_id=finding.id,
            before={"status": before_status.value},
            after={"status": finding.status.value},
        )
    db.commit()
    db.refresh(waiver)
    return waiver


class WaiverExpiryCheckResult:
    def __init__(self, expired_count: int, reopened_finding_count: int) -> None:
        self.expired_count = expired_count
        self.reopened_finding_count = reopened_finding_count


def check_expired_waivers(db: Session, today: date | None = None) -> WaiverExpiryCheckResult:
    """FR-6.2: when a Waiver's expiry_date is reached, auto-expire it and reopen the
    Finding it was covering (unless a later scan already marked it FIXED)."""
    as_of = today or datetime.now(UTC).date()
    active = (
        db.execute(
            select(Waiver)
            .where(Waiver.status == WaiverStatus.ACTIVE, Waiver.expiry_date <= as_of)
            .options(joinedload(Waiver.finding))
        )
        .unique()
        .scalars()
        .all()
    )

    reopened = 0
    for waiver in active:
        waiver.status = WaiverStatus.EXPIRED
        record_audit(
            db,
            actor="system",
            action="waiver.auto_expired",
            entity_type="waiver",
            entity_id=waiver.id,
            after={"status": waiver.status.value},
        )
        finding = waiver.finding
        if finding is not None and finding.status == FindingStatus.RISK_ACCEPTED:
            finding.status = FindingStatus.OPEN
            reopened += 1
            record_audit(
                db,
                actor="system",
                action="finding.status_change_waiver_expired",
                entity_type="finding",
                entity_id=finding.id,
                before={"status": "risk_accepted"},
                after={"status": "open"},
            )

    db.commit()
    logger.info("Waiver expiry sweep: %s expired, %s findings reopened", len(active), reopened)
    return WaiverExpiryCheckResult(expired_count=len(active), reopened_finding_count=reopened)


def application_for_finding(db: Session, finding: Finding) -> Application | None:
    """Resolves the owning Application for a Finding's data-scoping check (mirrors the
    join `findings.service._scoped_finding_query` already applies at read time)."""
    return db.execute(
        select(Application)
        .join(AppVersion, AppVersion.application_id == Application.id)
        .where(AppVersion.id == finding.app_version_id)
    ).scalar_one_or_none()
