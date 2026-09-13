import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, get_current_user, require_roles
from app.models.inventory import Application, AppVersion
from app.models.user import Role
from app.modules.golive import service
from app.modules.golive.service import GoLiveNotReadyError
from app.schemas.golive import GoLiveApprovalOut, GoLiveChecklist

router = APIRouter(prefix="/app-versions", tags=["go-live"])

_APPROVERS = (Role.APPSEC, Role.ADMIN)


def _resolve_version_and_application(
    db: Session, current_user: CurrentUser, app_version_id: uuid.UUID
) -> tuple[AppVersion, Application]:
    """Section 4 scoping: a Dev Team user may only see the Go-Live Gate for a Version
    belonging to an Application their team owns (mirrors `inventory.service.get_application`)."""
    version = db.get(AppVersion, app_version_id)
    if version is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Application version not found"
        )
    application = db.get(Application, version.application_id)
    if application is None or (
        current_user.role == Role.DEV_TEAM and application.owner_team != current_user.owner_team
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Application version not found"
        )
    return version, application


@router.get("/{app_version_id}/go-live-checklist", response_model=GoLiveChecklist)
def get_go_live_checklist(
    app_version_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> GoLiveChecklist:
    version, application = _resolve_version_and_application(db, current_user, app_version_id)
    return service.compute_checklist(db, version, application)


@router.post("/{app_version_id}/go-live-approve", response_model=GoLiveApprovalOut)
def approve_go_live(
    app_version_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_APPROVERS))],
) -> GoLiveApprovalOut:
    version, application = _resolve_version_and_application(db, current_user, app_version_id)
    try:
        return service.approve_go_live(  # type: ignore[return-value]
            db, version, application, actor=current_user.username
        )
    except GoLiveNotReadyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.get("/{app_version_id}/go-live-history", response_model=list[GoLiveApprovalOut])
def get_go_live_history(
    app_version_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[GoLiveApprovalOut]:
    _resolve_version_and_application(db, current_user, app_version_id)
    return service.list_go_live_history(db, app_version_id)  # type: ignore[return-value]
