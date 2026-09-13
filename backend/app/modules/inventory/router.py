import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, get_current_user, require_roles
from app.models.user import Role
from app.modules.inventory import service
from app.schemas.inventory import (
    ApplicationCreate,
    ApplicationOut,
    ApplicationUpdate,
    AppVersionCreate,
    AppVersionOut,
    PaginatedApplications,
)

router = APIRouter(prefix="/applications", tags=["inventory"])


@router.get("", response_model=PaginatedApplications)
def list_applications(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    skip: int = 0,
    limit: int = 50,
) -> PaginatedApplications:
    items, total = service.list_applications(db, current_user, skip=skip, limit=limit)
    return PaginatedApplications(items=items, total=total)  # type: ignore[arg-type]


@router.post("", response_model=ApplicationOut, status_code=status.HTTP_201_CREATED)
def create_application(
    payload: ApplicationCreate,
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(Role.APPSEC, Role.ADMIN))],
) -> ApplicationOut:
    return service.create_application(db, payload)  # type: ignore[return-value]


@router.get("/{app_id}", response_model=ApplicationOut)
def get_application(
    app_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> ApplicationOut:
    app = service.get_application(db, current_user, app_id)
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    return app  # type: ignore[return-value]


@router.patch("/{app_id}", response_model=ApplicationOut)
def update_application(
    app_id: uuid.UUID,
    payload: ApplicationUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(Role.APPSEC, Role.ADMIN))],
) -> ApplicationOut:
    app = service.get_application(db, current_user, app_id)
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    return service.update_application(db, app, payload)  # type: ignore[return-value]


@router.get("/{app_id}/versions", response_model=list[AppVersionOut])
def list_versions(
    app_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> list[AppVersionOut]:
    app = service.get_application(db, current_user, app_id)
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    return service.list_app_versions(db, app_id)  # type: ignore[return-value]


@router.post(
    "/{app_id}/versions", response_model=AppVersionOut, status_code=status.HTTP_201_CREATED
)
def create_version(
    app_id: uuid.UUID,
    payload: AppVersionCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(Role.APPSEC, Role.ADMIN))],
) -> AppVersionOut:
    app = service.get_application(db, current_user, app_id)
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Application not found")
    return service.create_app_version(db, app, payload)  # type: ignore[return-value]
