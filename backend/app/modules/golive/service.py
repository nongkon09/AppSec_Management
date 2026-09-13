"""Go-Live Security Gate (Requirement.md FR-6.1, FR-6.3, FR-6.4).

FR-6.7 Break-glass (manual approval while the platform itself is down) is
deliberately out of scope for this pass — see the project plan's scope notes.
"""

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.models.finding import Finding, FindingSource, FindingStatus, SeverityTier
from app.models.inventory import Application, AppVersion
from app.models.pentest import GoLiveApproval, PentestProject, PentestStatus
from app.schemas.golive import GoLiveChecklist

# FR-6.1: only Critical/High Findings block Go-Live; Medium/Low never do.
_BLOCKING_SEVERITIES = (SeverityTier.CRITICAL, SeverityTier.HIGH)

_PENTEST_PASSING_STATUSES = (PentestStatus.REMEDIATION_VERIFICATION, PentestStatus.CLOSED)


class GoLiveNotReadyError(ValueError):
    """Raised when an approval is attempted while the checklist is not yet satisfied."""


def _blocking_count(db: Session, app_version_id: uuid.UUID, source: FindingSource) -> int:
    """A Finding blocks Go-Live only while it is OPEN — once a Waiver is approved it
    moves to RISK_ACCEPTED (see waivers.service.approve_waiver) and stops blocking,
    which is exactly FR-6.1's "or has an approved Waiver" clause."""
    return db.execute(
        select(func.count())
        .select_from(Finding)
        .where(
            Finding.app_version_id == app_version_id,
            Finding.source == source,
            Finding.severity_tier.in_(_BLOCKING_SEVERITIES),
            Finding.status == FindingStatus.OPEN,
        )
    ).scalar_one()


def _pentest_required(application: Application) -> bool:
    """FR-6.1.3: Critical business criticality, internet-facing, or PII/Financial data
    classification triggers a mandatory Pentest gate."""
    if application.criticality.value == "critical" or application.internet_facing:
        return True
    classification = (application.data_classification or "").lower()
    return "pii" in classification or "financial" in classification


def _latest_pentest_project(db: Session, app_version_id: uuid.UUID) -> PentestProject | None:
    return db.execute(
        select(PentestProject)
        .where(PentestProject.app_version_id == app_version_id)
        .order_by(PentestProject.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def compute_checklist(
    db: Session, app_version: AppVersion, application: Application
) -> GoLiveChecklist:
    sbom_blocking = _blocking_count(db, app_version.id, FindingSource.SBOM)
    sast_blocking = _blocking_count(db, app_version.id, FindingSource.SAST)
    pentest_blocking = _blocking_count(db, app_version.id, FindingSource.PENTEST)

    pentest_required = _pentest_required(application)
    if not pentest_required:
        pentest_pass = True
    else:
        project = _latest_pentest_project(db, app_version.id)
        pentest_pass = (
            project is not None
            and project.status in _PENTEST_PASSING_STATUSES
            and pentest_blocking == 0
        )

    sbom_pass = sbom_blocking == 0
    sast_pass = sast_blocking == 0

    return GoLiveChecklist(
        app_version_id=app_version.id,
        sbom_pass=sbom_pass,
        sbom_blocking_count=sbom_blocking,
        sast_pass=sast_pass,
        sast_blocking_count=sast_blocking,
        pentest_required=pentest_required,
        pentest_pass=pentest_pass,
        pentest_blocking_count=pentest_blocking if pentest_required else 0,
        ready=sbom_pass and sast_pass and pentest_pass,
    )


def approve_go_live(
    db: Session, app_version: AppVersion, application: Application, actor: str
) -> GoLiveApproval:
    """FR-6.3/6.4: re-checks the checklist server-side — a client can never be trusted
    to have an up-to-date view — and blocks the approval outright if it isn't ready."""
    checklist = compute_checklist(db, app_version, application)
    if not checklist.ready:
        raise GoLiveNotReadyError(
            "Go-Live checklist is not satisfied: "
            f"sbom_pass={checklist.sbom_pass}, sast_pass={checklist.sast_pass}, "
            f"pentest_pass={checklist.pentest_pass}"
        )

    approval = GoLiveApproval(
        app_version_id=app_version.id,
        sbom_pass=checklist.sbom_pass,
        sast_pass=checklist.sast_pass,
        pentest_pass=checklist.pentest_pass,
        approver=actor,
        is_break_glass=False,
    )
    db.add(approval)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="golive.approve",
        entity_type="go_live_approval",
        entity_id=approval.id,
        after={
            "app_version_id": str(app_version.id),
            "sbom_pass": checklist.sbom_pass,
            "sast_pass": checklist.sast_pass,
            "pentest_pass": checklist.pentest_pass,
        },
    )
    db.commit()
    db.refresh(approval)
    return approval


def list_go_live_history(db: Session, app_version_id: uuid.UUID) -> list[GoLiveApproval]:
    return list(
        db.execute(
            select(GoLiveApproval)
            .where(GoLiveApproval.app_version_id == app_version_id)
            .order_by(GoLiveApproval.created_at.desc())
        )
        .scalars()
        .all()
    )
