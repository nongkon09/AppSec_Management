import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import CurrentUser, require_roles
from app.models.user import Role
from app.modules.users import service
from app.schemas.user import PaginatedUsers, PasswordReset, UserCreate, UserOut, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])

# Section 4: "System Admin | จัดการ User/Role ..." — user administration is Admin-only,
# not shared with AppSec (which owns Policy/Waiver, a separate responsibility).
_USER_ADMIN = (Role.ADMIN,)


@router.get("", response_model=PaginatedUsers)
def list_users(
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(*_USER_ADMIN))],
    skip: int = 0,
    limit: int = 50,
) -> PaginatedUsers:
    items, total = service.list_users(db, skip=skip, limit=limit)
    return PaginatedUsers(items=items, total=total)  # type: ignore[arg-type]


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_USER_ADMIN))],
) -> UserOut:
    if service.username_or_email_taken(db, username=payload.username, email=payload.email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with this username or email already exists",
        )
    user = service.create_user(db, payload, actor=current_user.username)
    return user  # type: ignore[return-value]


@router.get("/{user_id}", response_model=UserOut)
def get_user(
    user_id: uuid.UUID,
    db: Annotated[Session, Depends(get_db)],
    _current_user: Annotated[CurrentUser, Depends(require_roles(*_USER_ADMIN))],
) -> UserOut:
    user = service.get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user  # type: ignore[return-value]


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_USER_ADMIN))],
) -> UserOut:
    user = service.get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if payload.email is not None and payload.email != user.email:
        if service.username_or_email_taken(
            db, username=user.username, email=payload.email, exclude_id=user.id
        ):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use")
    try:
        updated = service.update_user(db, user, payload, actor=current_user.username)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return updated  # type: ignore[return-value]


@router.post("/{user_id}/reset-password", response_model=UserOut)
def reset_password(
    user_id: uuid.UUID,
    payload: PasswordReset,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_roles(*_USER_ADMIN))],
) -> UserOut:
    user = service.get_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    try:
        updated = service.reset_password(db, user, payload, actor=current_user.username)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return updated  # type: ignore[return-value]
