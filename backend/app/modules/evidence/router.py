"""Release Evidence Pack (docs/risk-exception-design.md 3.7, workflow W7).

Answers the audit question "during this period, which version ran where, what did its
scans find, and who approved letting what through" in one read-only document.
"""

import uuid
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from app.core.audit import record_audit
from app.core.db import get_db
from app.core.deps import CurrentUser, require_roles
from app.models.deployment import Deployment
from app.models.finding import Finding
from app.models.inventory import AppVersion
from app.models.risk_exception import ExceptionItem, ExceptionStatus, RiskException
from app.models.scan_result import ScanFinding, ScanResult
from app.models.user import Role
from app.modules.deployments.router import deployment_to_out
from app.modules.inventory import service as inventory_service
from app.schemas.evidence import (
    EvidenceApplication,
    EvidenceException,
    EvidencePack,
    EvidenceScan,
    EvidenceScanFinding,
)
from app.schemas.risk_exception import ExceptionApprovalOut, ExceptionBypassOut

router = APIRouter(tags=["evidence"])

_READERS = (Role.APPSEC, Role.AUDIT, Role.MANAGEMENT, Role.ADMIN, Role.DEV_TEAM)
_DEFAULT_DAYS = 90


def _scan_out(
    db: Session, scan: ScanResult, version_label: str, *, is_baseline: bool
) -> EvidenceScan:
    rows = db.execute(
        select(ScanFinding, Finding)
        .join(Finding, Finding.id == ScanFinding.finding_id)
        .where(ScanFinding.scan_result_id == scan.id)
        .order_by(Finding.issue_key)
    ).all()
    return EvidenceScan(
        id=scan.id,
        version_label=version_label,
        scanned_at=scan.scanned_at,
        is_manual_upload=scan.is_manual_upload,
        uploaded_by=scan.uploaded_by,
        source_tool=scan.source_tool,
        image_digest=scan.image_digest,
        commit_sha=scan.commit_sha,
        pipeline_run=scan.pipeline_run,
        sca_bom_imported_at=scan.sca_bom_imported_at,
        sbom_sha256=scan.sbom_sha256,
        sbom_available=bool(scan.sbom_path and Path(scan.sbom_path).exists()),
        is_baseline=is_baseline,
        findings=[
            EvidenceScanFinding(
                finding_id=finding.id,
                issue_key=finding.issue_key,
                label=finding.cve_id or finding.title or finding.issue_key,
                severity_at_scan=link.severity_tier,
                status_at_scan=link.status,
            )
            for link, finding in rows
        ],
    )


@router.get("/applications/{app_id}/evidence", response_model=EvidencePack)
def evidence_pack(
    app_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_READERS))],
    date_from: Annotated[date | None, Query()] = None,
    date_to: Annotated[date | None, Query()] = None,
) -> EvidencePack:
    application = inventory_service.get_application(db, current_user, app_id)
    if application is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    period_to = date_to or datetime.now(UTC).date()
    period_from = date_from or period_to - timedelta(days=_DEFAULT_DAYS)
    if period_from > period_to:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="date_from must not be after date_to",
        )
    start = datetime.combine(period_from, time.min, tzinfo=UTC)
    end = datetime.combine(period_to, time.max, tzinfo=UTC)

    deployments = list(
        db.execute(
            select(Deployment)
            .where(
                Deployment.application_id == app_id,
                Deployment.deployed_at <= end,
                or_(Deployment.ended_at.is_(None), Deployment.ended_at >= start),
            )
            .order_by(Deployment.deployed_at)
        )
        .scalars()
        .all()
    )

    versions = {
        v.id: v
        for v in db.execute(select(AppVersion).where(AppVersion.application_id == app_id))
        .scalars()
        .all()
    }
    scans_in_period = list(
        db.execute(
            select(ScanResult)
            .where(
                ScanResult.app_version_id.in_(list(versions)),
                ScanResult.scanned_at >= start,
                ScanResult.scanned_at <= end,
            )
            .order_by(ScanResult.scanned_at)
        )
        .scalars()
        .all()
    )
    scans = [
        _scan_out(db, scan, versions[scan.app_version_id].version_label, is_baseline=False)
        for scan in scans_in_period
    ]
    # What was already running when the period began: the last scan before it.
    for version_id in {d.app_version_id for d in deployments}:
        baseline = (
            db.execute(
                select(ScanResult)
                .where(ScanResult.app_version_id == version_id, ScanResult.scanned_at < start)
                .order_by(ScanResult.scanned_at.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        if baseline is not None:
            scans.insert(
                0, _scan_out(db, baseline, versions[version_id].version_label, is_baseline=True)
            )

    exceptions = list(
        db.execute(
            select(RiskException)
            .where(
                RiskException.id.in_(
                    select(ExceptionItem.exception_id).where(ExceptionItem.application_id == app_id)
                ),
                RiskException.created_at <= end,
                or_(
                    RiskException.status.in_([ExceptionStatus.PENDING, ExceptionStatus.APPROVED]),
                    RiskException.updated_at >= start,
                ),
            )
            .options(
                selectinload(RiskException.items),
                selectinload(RiskException.approvals),
                selectinload(RiskException.bypasses),
                selectinload(RiskException.controls),
            )
            .order_by(RiskException.created_at)
        )
        .scalars()
        .unique()
        .all()
    )

    record_audit(
        db,
        actor=current_user.username,
        action="evidence.export",
        entity_type="application",
        entity_id=app_id,
        after={"from": period_from.isoformat(), "to": period_to.isoformat()},
    )
    db.commit()

    return EvidencePack(
        application=EvidenceApplication(
            id=application.id,
            name=application.app_name,
            owner_team=application.owner_team,
            criticality=application.criticality.value,
            internet_facing=application.internet_facing,
        ),
        period_from=period_from,
        period_to=period_to,
        generated_at=datetime.now(UTC),
        generated_by=current_user.username,
        deployments=[deployment_to_out(d) for d in deployments],
        scans=scans,
        exceptions=[
            EvidenceException(
                reference=e.reference,
                exception_type=e.exception_type.value,
                status=e.status.value,
                requested_by=e.requested_by,
                created_at=e.created_at,
                reason=e.reason,
                original_severity_tier=e.original_severity_tier.value,
                residual_severity_tier=(
                    e.residual_severity_tier.value if e.residual_severity_tier else None
                ),
                expires_on=e.expires_on,
                covered=[item.label for item in e.items if item.application_id == app_id],
                controls=[c.name for c in e.controls],
                approvals=[ExceptionApprovalOut.model_validate(a) for a in e.approvals],
                bypasses=[ExceptionBypassOut.model_validate(b) for b in e.bypasses],
                is_legacy=e.is_legacy,
            )
            for e in exceptions
        ],
    )


@router.get("/scans/{scan_id}/sbom")
def download_scan_sbom(
    scan_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_READERS))],
) -> FileResponse:
    scan = db.get(ScanResult, scan_id)
    version = db.get(AppVersion, scan.app_version_id) if scan else None
    if (
        scan is None
        or version is None
        or inventory_service.get_application(db, current_user, version.application_id) is None
        or not scan.sbom_path
        or not Path(scan.sbom_path).exists()
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM not found")
    return FileResponse(
        scan.sbom_path,
        media_type="application/json",
        filename=f"sbom-{version.version_label}-{scan.sbom_sha256}.json",
    )
