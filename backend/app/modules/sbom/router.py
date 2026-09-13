import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, require_roles
from app.models.inventory import Application
from app.models.scan_result import ScanResult
from app.models.user import Role
from app.modules.sbom import service
from app.modules.sbom.parser import SbomFormatError
from app.schemas.sbom import (
    DependencyTrackSyncResult,
    IngestionHistoryOut,
    ManualSbomUploadResult,
    StaleCheckResult,
)

router = APIRouter(prefix="/sbom", tags=["sbom"])

# Section 3 RACI: pushing SBOM Generators into pipelines and running them for COTS
# intake is AppSec/DevOps work; System Admin covers the equivalent system-operator role
# in this platform's RBAC model (Section 4 has no separate DevOps role).
_INGESTION_OPERATORS = (Role.APPSEC, Role.ADMIN)


@router.post("/sync", response_model=DependencyTrackSyncResult)
def trigger_sync(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_INGESTION_OPERATORS))],
) -> DependencyTrackSyncResult:
    """FR-2.5/FR-3.1: manually trigger the pull-sync from the SCA platform. In a real
    deployment this also runs on a schedule (see app.core.scheduler); exposed here so
    AppSec/Admin can force an immediate refresh."""
    return service.sync_from_connector(db, actor=current_user.username)


@router.post("/upload", response_model=ManualSbomUploadResult, status_code=status.HTTP_201_CREATED)
async def upload_manual_sbom(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_INGESTION_OPERATORS))],
    application_id: Annotated[uuid.UUID, Form()],
    version_label: Annotated[str, Form()],
    file: Annotated[UploadFile, File()],
) -> ManualSbomUploadResult:
    """FR-2.6.1/2.6.2: COTS/Vendor manual SBOM upload — vendor-supplied CycloneDX/SPDX,
    or a file generated in-house from vendor-supplied source code. Either way it lands
    on an existing, already-registered Application (create one via FR-1 first)."""
    application = db.get(Application, application_id)
    if application is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")

    raw_bytes = await file.read()
    try:
        return service.ingest_manual_sbom(
            db,
            application=application,
            version_label=version_label,
            raw_bytes=raw_bytes,
            actor=current_user.username,
        )
    except SbomFormatError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.post("/stale-check", response_model=StaleCheckResult)
def trigger_stale_check(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(*_INGESTION_OPERATORS))],
) -> StaleCheckResult:
    """FR-2.4: manually trigger the staleness sweep (also runs on a schedule)."""
    return service.check_stale_versions(db)


@router.get("/ingestion-history", response_model=list[IngestionHistoryOut])
def get_ingestion_history(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(*_INGESTION_OPERATORS))],
    app_version_id: uuid.UUID,
) -> list[IngestionHistoryOut]:
    """FR-2.3: "Scan ล่าสุดเมื่อไหร่" — full ingestion history for one Application Version."""
    rows = (
        db.execute(
            select(ScanResult)
            .where(ScanResult.app_version_id == app_version_id)
            .order_by(ScanResult.scanned_at.desc())
        )
        .scalars()
        .all()
    )
    return [IngestionHistoryOut.model_validate(row) for row in rows]
