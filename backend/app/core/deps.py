from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import decode_access_token
from app.models.user import Role, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


class CurrentUser:
    """Lightweight representation of the authenticated principal, decoded from the JWT."""

    def __init__(self, username: str, role: Role, owner_team: str | None):
        self.username = username
        self.role = role
        self.owner_team = owner_team


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> CurrentUser:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_error
    except PyJWTError as exc:
        raise credentials_error from exc

    user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
    if user is None:
        raise credentials_error
    return CurrentUser(username=user.username, role=user.role, owner_team=user.owner_team)


def require_roles(*allowed_roles: Role):
    """FastAPI dependency factory enforcing RBAC per Requirement.md Section 4."""

    def _check(current_user: Annotated[CurrentUser, Depends(get_current_user)]) -> CurrentUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action",
            )
        return current_user

    return _check
