import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, get_current_user, require_roles
from app.models.finding import Finding
from app.models.user import Role
from app.modules.findings import service as findings_service
from app.modules.waivers import service
from app.modules.waivers.service import WaiverConflictError
from app.schemas.waiver import WaiverCreate, WaiverExpiryCheckOut, WaiverOut

router = APIRouter(tags=["waivers"])

# FR-6.2: Dev/Tech Lead (or AppSec) requests; only AppSec/Admin decide.
_REQUESTERS = (Role.DEV_TEAM, Role.APPSEC, Role.ADMIN)
_APPROVERS = (Role.APPSEC, Role.ADMIN)


@router.get("/findings/{finding_id}/waivers", response_model=list[WaiverOut])
def list_waivers(
    finding_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[WaiverOut]:
    finding = findings_service.get_finding(db, current_user, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return service.list_waivers_for_finding(db, finding_id)  # type: ignore[return-value]


@router.post(
    "/findings/{finding_id}/waivers", response_model=WaiverOut, status_code=status.HTTP_201_CREATED
)
def create_waiver(
    finding_id: uuid.UUID,
    payload: WaiverCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_REQUESTERS))],
) -> WaiverOut:
    finding = findings_service.get_finding(db, current_user, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    try:
        return service.request_waiver(  # type: ignore[return-value]
            db, finding, payload, actor=current_user.username
        )
    except WaiverConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


def _get_waiver_or_404(db: Session, waiver_id: uuid.UUID):  # type: ignore[no-untyped-def]
    waiver = service.get_waiver(db, waiver_id)
    if waiver is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Waiver not found")
    return waiver


@router.post("/waivers/{waiver_id}/approve", response_model=WaiverOut)
def approve_waiver(
    waiver_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_APPROVERS))],
) -> WaiverOut:
    waiver = _get_waiver_or_404(db, waiver_id)
    finding = db.get(Finding, waiver.finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return service.approve_waiver(db, waiver, finding, actor=current_user.username)  # type: ignore[return-value]


@router.post("/waivers/{waiver_id}/reject", response_model=WaiverOut)
def reject_waiver(
    waiver_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_APPROVERS))],
) -> WaiverOut:
    waiver = _get_waiver_or_404(db, waiver_id)
    return service.reject_waiver(db, waiver, actor=current_user.username)  # type: ignore[return-value]


@router.post("/waivers/{waiver_id}/revoke", response_model=WaiverOut)
def revoke_waiver(
    waiver_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_APPROVERS))],
) -> WaiverOut:
    waiver = _get_waiver_or_404(db, waiver_id)
    finding = db.get(Finding, waiver.finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return service.revoke_waiver(db, waiver, finding, actor=current_user.username)  # type: ignore[return-value]


@router.post("/waivers/expiry-check", response_model=WaiverExpiryCheckOut)
def trigger_expiry_check(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(*_APPROVERS))],
) -> WaiverExpiryCheckOut:
    """FR-6.2: manually trigger the auto-expiry sweep (also runs on a schedule)."""
    result = service.check_expired_waivers(db)
    return WaiverExpiryCheckOut(
        expired_count=result.expired_count, reopened_finding_count=result.reopened_finding_count
    )
