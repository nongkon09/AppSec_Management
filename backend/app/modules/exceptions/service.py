"""Risk Exception workflow: Maker submits, Checkers decide (docs/risk-exception-design.md 3.4-3.5).

Nothing changes on a Finding until the request is fully approved; every step writes an
audit entry in the same transaction as the change it describes.
"""

import uuid
from collections.abc import Sequence
from datetime import UTC, date, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.audit import record_audit
from app.core.deps import CurrentUser
from app.models.finding import Finding, FindingStatus
from app.models.inventory import Application, AppVersion
from app.models.risk_exception import (
    ApprovalDecision,
    ExceptionApproval,
    ExceptionBypass,
    ExceptionItem,
    ExceptionStatus,
    RiskException,
)
from app.models.security_control import SecurityControl
from app.models.user import ApprovalLevel, Role
from app.modules.exceptions import coverage, rules
from app.modules.findings import service as findings_service
from app.modules.policy import service as policy_service
from app.schemas.risk_exception import BypassCreate, ExceptionCreate

SYSTEM_ACTOR = "system"
_OPEN_STATES = (ExceptionStatus.PENDING, ExceptionStatus.APPROVED)


class ExceptionError(ValueError):
    """The request is invalid (422)."""


class ExceptionConflictError(ValueError):
    """Another live exception already covers the same issue (409)."""


class ExceptionForbiddenError(PermissionError):
    """The current user may not perform this step (403)."""


def _today() -> date:
    return datetime.now(UTC).date()


def _load_options():  # type: ignore[no-untyped-def]
    return (
        selectinload(RiskException.items).selectinload(ExceptionItem.application),
        selectinload(RiskException.approvals),
        selectinload(RiskException.bypasses),
        selectinload(RiskException.controls),
    )


def _requirement(exception: RiskException) -> rules.ApprovalRequirement:
    return rules.ApprovalRequirement(
        exception.required_approvals, exception.required_min_level, exception.required_top_level
    )


def approve_refusal(exception: RiskException, current_user: CurrentUser) -> str | None:
    if exception.status != ExceptionStatus.PENDING:
        return "Only pending requests can be decided."
    approved_levels = [
        a.approver_level for a in exception.approvals if a.decision == ApprovalDecision.APPROVE
    ]
    return rules.checker_refusal(
        rules.CheckerContext(current_user.username, current_user.role, current_user.approval_level),
        requested_by=exception.requested_by,
        already_decided_by=[a.approver for a in exception.approvals],
        approved_levels=approved_levels,
        requirement=_requirement(exception),
        approving=True,
    )


def _next_reference(db: Session, today: date) -> str:
    prefix = f"EXC-{today.year}-"
    count = db.execute(
        select(func.count())
        .select_from(RiskException)
        .where(RiskException.reference.like(f"{prefix}%"))
    ).scalar_one()
    return f"{prefix}{count + 1:04d}"


def _request_findings(
    db: Session, current_user: CurrentUser, payload: ExceptionCreate
) -> list[Finding]:
    base = findings_service._scoped_finding_query(current_user)
    if payload.cve_id:
        if current_user.role != Role.APPSEC:
            raise ExceptionForbiddenError(
                "Only AppSec can request an exception for a CVE across applications."
            )
        stmt = base.where(Finding.cve_id == payload.cve_id, Finding.status != FindingStatus.FIXED)
        findings = list(db.execute(stmt).scalars().unique().all())
        if not findings:
            raise ExceptionError(f"No unresolved findings for {payload.cve_id}.")
        return findings
    wanted = set(payload.finding_ids)
    findings = list(db.execute(base.where(Finding.id.in_(wanted))).scalars().unique().all())
    if len(findings) != len(wanted):
        raise ExceptionError("One or more findings were not found.")
    return findings


def create_exception(
    db: Session, current_user: CurrentUser, payload: ExceptionCreate
) -> RiskException:
    if current_user.role not in rules.MAKER_ROLES:
        raise ExceptionForbiddenError("Your role cannot submit exception requests.")
    today = _today()
    findings = _request_findings(db, current_user, payload)

    # One item per (Application, issue); the first matching row is kept for display.
    items: dict[tuple[uuid.UUID, str], ExceptionItem] = {}
    for finding in findings:
        application = finding.app_version.application
        key = (application.id, finding.issue_key)
        if key not in items:
            component = finding.component.component_name if finding.component else None
            label = " · ".join(
                part for part in (finding.cve_id or finding.title, component) if part
            )
            items[key] = ExceptionItem(
                application_id=application.id,
                issue_key=finding.issue_key,
                origin_finding_id=finding.id,
                label=label[:1024],
            )

    conflict = (
        db.execute(
            select(RiskException.reference)
            .join(ExceptionItem, ExceptionItem.exception_id == RiskException.id)
            .where(
                RiskException.status.in_(_OPEN_STATES),
                or_(
                    *[
                        (ExceptionItem.application_id == app_id) & (ExceptionItem.issue_key == key)
                        for app_id, key in items
                    ]
                ),
            )
        )
        .scalars()
        .first()
    )
    if conflict:
        raise ExceptionConflictError(f"{conflict} already covers one of these issues.")

    covered = [f for item in items.values() for f in coverage.unresolved_findings(db, item)]
    if not covered:
        raise ExceptionError("Every selected finding is already fixed.")

    original = rules.worst([f.severity_tier for f in covered])
    kev = any(f.kev_flag for f in covered)

    controls = list(
        db.execute(select(SecurityControl).where(SecurityControl.id.in_(payload.control_ids)))
        .scalars()
        .all()
    )
    if len(controls) != len(set(payload.control_ids)):
        raise ExceptionError("One or more controls were not found.")
    unusable = [c.name for c in controls if not c.is_usable(today)]
    if unusable:
        raise ExceptionError(
            "These controls are inactive or past their review date: " + ", ".join(unusable)
        )

    errors = rules.residual_errors(original, payload.residual_severity_tier, kev, len(controls))
    policy = policy_service.get_effective_policy(db, today)
    anchor = min(f.sla_started_on for f in covered)
    sla_due = policy_service.compute_due_date(
        policy, payload.residual_severity_tier or original, anchor
    )
    errors += rules.expiry_errors(payload.exception_type, payload.expires_on, today, sla_due)
    if errors:
        raise ExceptionError(" ".join(errors))

    application_count = len({app_id for app_id, _ in items})
    requirement = rules.required_approvals(payload.exception_type, original, kev, application_count)

    exception = RiskException(
        reference=_next_reference(db, today),
        exception_type=payload.exception_type,
        status=ExceptionStatus.PENDING,
        requested_by=current_user.username,
        reason=payload.reason,
        evidence=payload.evidence,
        compensating_measures=payload.compensating_measures,
        vex_justification=payload.vex_justification,
        original_severity_tier=original,
        kev_involved=kev,
        residual_severity_tier=payload.residual_severity_tier,
        expires_on=payload.expires_on,
        required_approvals=requirement.count,
        required_min_level=requirement.min_level,
        required_top_level=requirement.top_level,
        items=list(items.values()),
        controls=controls,
    )
    db.add(exception)
    try:
        db.flush()
    except IntegrityError as exc:  # two submissions raced for the same reference number
        db.rollback()
        raise ExceptionConflictError("Please submit again.") from exc

    record_audit(
        db,
        actor=current_user.username,
        action="exception.submit",
        entity_type="risk_exception",
        entity_id=exception.id,
        after={
            "reference": exception.reference,
            "type": exception.exception_type.value,
            "items": [f"{i.application_id}:{i.issue_key}" for i in exception.items],
            "original_severity": original.value,
            "kev": kev,
            "residual_severity": (
                payload.residual_severity_tier.value if payload.residual_severity_tier else None
            ),
            "controls": [c.name for c in controls],
            "expires_on": payload.expires_on.isoformat(),
            "required_approvals": requirement.count,
            "required_min_level": requirement.min_level.value,
            "required_top_level": requirement.top_level.value,
            "reason": payload.reason,
        },
    )
    db.commit()
    return get_exception_by_id(db, exception.id)  # type: ignore[return-value]


def decide(
    db: Session,
    exception: RiskException,
    current_user: CurrentUser,
    *,
    approve: bool,
    comment: str | None,
) -> RiskException:
    if exception.status != ExceptionStatus.PENDING:
        raise ExceptionError("Only pending requests can be decided.")
    if not approve and not (comment and comment.strip()):
        raise ExceptionError("A reason is required to reject a request.")

    approved_levels = [
        a.approver_level for a in exception.approvals if a.decision == ApprovalDecision.APPROVE
    ]
    refusal = rules.checker_refusal(
        rules.CheckerContext(current_user.username, current_user.role, current_user.approval_level),
        requested_by=exception.requested_by,
        already_decided_by=[a.approver for a in exception.approvals],
        approved_levels=approved_levels,
        requirement=_requirement(exception),
        approving=approve,
    )
    if refusal:
        raise ExceptionForbiddenError(refusal)

    now = datetime.now(UTC)
    exception.approvals.append(
        ExceptionApproval(
            approver=current_user.username,
            approver_level=current_user.approval_level,
            decision=ApprovalDecision.APPROVE if approve else ApprovalDecision.REJECT,
            comment=comment,
            decided_at=now,
        )
    )

    if not approve:
        exception.status = ExceptionStatus.REJECTED
        exception.decided_at = now
        exception.ended_by = current_user.username
        exception.ended_reason = comment
        action = "exception.reject"
        applied = 0
    else:
        approved_levels.append(current_user.approval_level)
        if rules.is_fully_approved(approved_levels, _requirement(exception)):
            exception.status = ExceptionStatus.APPROVED
            exception.decided_at = now
            db.flush()
            applied = coverage.apply_exception(db, exception, actor=current_user.username)
            action = "exception.approve_final"
        else:
            applied = 0
            action = "exception.approve_partial"

    record_audit(
        db,
        actor=current_user.username,
        action=action,
        entity_type="risk_exception",
        entity_id=exception.id,
        after={
            "reference": exception.reference,
            "status": exception.status.value,
            "approver_level": current_user.approval_level.value,
            "comment": comment,
            "findings_changed": applied,
        },
    )
    db.commit()
    return get_exception_by_id(db, exception.id)  # type: ignore[return-value]


def withdraw(
    db: Session, exception: RiskException, current_user: CurrentUser, reason: str
) -> RiskException:
    if exception.requested_by != current_user.username:
        raise ExceptionForbiddenError("Only the requester can withdraw a request.")
    if exception.status != ExceptionStatus.PENDING:
        raise ExceptionError("Only pending requests can be withdrawn.")
    exception.status = ExceptionStatus.WITHDRAWN
    exception.ended_by = current_user.username
    exception.ended_reason = reason
    record_audit(
        db,
        actor=current_user.username,
        action="exception.withdraw",
        entity_type="risk_exception",
        entity_id=exception.id,
        after={"reference": exception.reference, "reason": reason},
    )
    db.commit()
    return get_exception_by_id(db, exception.id)  # type: ignore[return-value]


def revoke(
    db: Session, exception: RiskException, current_user: CurrentUser, reason: str
) -> RiskException:
    """Ends an approved exception early. A single AppSec member may do this: it only ever
    tightens control, returning the Findings to the open backlog."""
    if current_user.role != Role.APPSEC or current_user.approval_level == ApprovalLevel.NONE:
        raise ExceptionForbiddenError("Only AppSec approvers can revoke an exception.")
    if exception.status != ExceptionStatus.APPROVED:
        raise ExceptionError("Only approved exceptions can be revoked.")
    exception.status = ExceptionStatus.REVOKED
    exception.ended_by = current_user.username
    exception.ended_reason = reason
    released = coverage.release_exception(db, exception, actor=current_user.username)
    record_audit(
        db,
        actor=current_user.username,
        action="exception.revoke",
        entity_type="risk_exception",
        entity_id=exception.id,
        after={"reference": exception.reference, "reason": reason, "findings_reopened": released},
    )
    db.commit()
    return get_exception_by_id(db, exception.id)  # type: ignore[return-value]


def _owns_any_item(current_user: CurrentUser, exception: RiskException) -> bool:
    return any(item.application.owner_team == current_user.owner_team for item in exception.items)


def record_bypass(
    db: Session, exception: RiskException, current_user: CurrentUser, payload: BypassCreate
) -> RiskException:
    if current_user.role == Role.DEV_TEAM and not _owns_any_item(current_user, exception):
        raise ExceptionForbiddenError("This exception does not cover your team's applications.")
    if exception.status != ExceptionStatus.APPROVED or exception.expires_on < _today():
        raise ExceptionError(
            "A bypass can only be recorded against an approved, unexpired exception."
        )
    exception.bypasses.append(
        ExceptionBypass(
            tool=payload.tool.value,
            reference_url=payload.reference_url,
            note=payload.note,
            recorded_by=current_user.username,
            bypassed_at=datetime.now(UTC),
        )
    )
    record_audit(
        db,
        actor=current_user.username,
        action="exception.bypass_recorded",
        entity_type="risk_exception",
        entity_id=exception.id,
        after={
            "reference": exception.reference,
            "tool": payload.tool.value,
            "reference_url": payload.reference_url,
            "note": payload.note,
        },
    )
    db.commit()
    return get_exception_by_id(db, exception.id)  # type: ignore[return-value]


def sweep(db: Session, today: date | None = None) -> tuple[int, int, int]:
    """Daily job: expire, close exceptions whose issues are all fixed, and flag those
    citing a control that is no longer usable."""
    as_of = today or _today()
    approved = list(
        db.execute(
            select(RiskException)
            .where(RiskException.status == ExceptionStatus.APPROVED)
            .options(*_load_options())
            .execution_options(populate_existing=True)
        )
        .scalars()
        .unique()
        .all()
    )
    expired = closed = flagged = 0
    for exception in approved:
        if exception.expires_on < as_of:
            exception.status = ExceptionStatus.EXPIRED
            exception.ended_by = SYSTEM_ACTOR
            exception.ended_reason = "Expiry date reached"
            released = coverage.release_exception(db, exception, actor=SYSTEM_ACTOR)
            record_audit(
                db,
                actor=SYSTEM_ACTOR,
                action="exception.expired",
                entity_type="risk_exception",
                entity_id=exception.id,
                after={"reference": exception.reference, "findings_reopened": released},
            )
            expired += 1
            continue
        if not any(coverage.unresolved_findings(db, item) for item in exception.items):
            exception.status = ExceptionStatus.CLOSED
            exception.ended_by = SYSTEM_ACTOR
            exception.ended_reason = "All covered findings are fixed"
            record_audit(
                db,
                actor=SYSTEM_ACTOR,
                action="exception.closed",
                entity_type="risk_exception",
                entity_id=exception.id,
                after={"reference": exception.reference},
            )
            closed += 1
            continue
        stale = [c.name for c in exception.controls if not c.is_usable(as_of)]
        if stale and not exception.needs_review:
            exception.needs_review = True
            record_audit(
                db,
                actor=SYSTEM_ACTOR,
                action="exception.needs_review",
                entity_type="risk_exception",
                entity_id=exception.id,
                after={"reference": exception.reference, "controls": stale},
            )
            flagged += 1
    db.commit()
    return expired, closed, flagged


def _scoped_query(current_user: CurrentUser):  # type: ignore[no-untyped-def]
    stmt = select(RiskException)
    if current_user.role == Role.DEV_TEAM:
        team_items = (
            select(ExceptionItem.exception_id)
            .join(Application, Application.id == ExceptionItem.application_id)
            .where(Application.owner_team == (current_user.owner_team or ""))
        )
        stmt = stmt.where(RiskException.id.in_(team_items))
    return stmt


def get_exception_by_id(db: Session, exception_id: uuid.UUID) -> RiskException | None:
    db.expire_all()
    return (
        db.execute(
            select(RiskException).where(RiskException.id == exception_id).options(*_load_options())
        )
        .scalars()
        .unique()
        .one_or_none()
    )


def get_exception(
    db: Session, current_user: CurrentUser, exception_id: uuid.UUID
) -> RiskException | None:
    return (
        db.execute(
            _scoped_query(current_user)
            .where(RiskException.id == exception_id)
            .options(*_load_options())
        )
        .scalars()
        .unique()
        .one_or_none()
    )


def get_by_reference(
    db: Session, current_user: CurrentUser, reference: str
) -> RiskException | None:
    return (
        db.execute(
            _scoped_query(current_user)
            .where(RiskException.reference == reference.strip().upper())
            .options(*_load_options())
        )
        .scalars()
        .unique()
        .one_or_none()
    )


def list_exceptions(
    db: Session,
    current_user: CurrentUser,
    *,
    statuses: Sequence[ExceptionStatus] | None = None,
    awaiting_me: bool = False,
    mine: bool = False,
    application_id: uuid.UUID | None = None,
    finding_id: uuid.UUID | None = None,
    skip: int = 0,
    limit: int = 50,
) -> tuple[list[RiskException], int]:
    stmt = _scoped_query(current_user)
    if awaiting_me:
        stmt = stmt.where(RiskException.status == ExceptionStatus.PENDING)
    elif statuses:
        stmt = stmt.where(RiskException.status.in_(list(statuses)))
    if mine:
        stmt = stmt.where(RiskException.requested_by == current_user.username)
    if application_id is not None:
        stmt = stmt.where(
            RiskException.id.in_(
                select(ExceptionItem.exception_id).where(
                    ExceptionItem.application_id == application_id
                )
            )
        )
    if finding_id is not None:
        finding = db.get(Finding, finding_id)
        if finding is None:
            return [], 0
        version = db.get(AppVersion, finding.app_version_id)
        stmt = stmt.where(
            RiskException.id.in_(
                select(ExceptionItem.exception_id).where(
                    ExceptionItem.application_id == (version.application_id if version else None),
                    ExceptionItem.issue_key == finding.issue_key,
                )
            )
        )
    stmt = stmt.options(*_load_options()).order_by(RiskException.created_at.desc())
    rows = list(db.execute(stmt).scalars().unique().all())
    if awaiting_me:
        rows = [row for row in rows if approve_refusal(row, current_user) is None]
    return rows[skip : skip + limit], len(rows)
