from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jwt import PyJWTError
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.security import decode_access_token
from app.models.user import ApprovalLevel, Role, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

# The CI/CD service account may only record deployments and check an exception reference
# before a bypass. Enforced here, once, so a new read endpoint cannot leak data to it by
# forgetting a role check (fail closed).
_PIPELINE_ALLOWED = (
    ("POST", "/api/v1/deployments"),
    ("GET", "/api/v1/exceptions/by-reference/"),
    ("GET", "/api/v1/auth/me"),
)


def _pipeline_may_call(request: Request) -> bool:
    path = request.url.path
    return any(
        request.method == method and (path == prefix or path.startswith(prefix))
        for method, prefix in _PIPELINE_ALLOWED
    )


class CurrentUser:
    """Lightweight representation of the authenticated principal, decoded from the JWT."""

    def __init__(
        self,
        username: str,
        role: Role,
        owner_team: str | None,
        approval_level: ApprovalLevel = ApprovalLevel.NONE,
    ):
        self.username = username
        self.role = role
        self.owner_team = owner_team
        self.approval_level = approval_level


def get_current_user(
    request: Request,
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
    # An Entra ID account whose groups no longer map to any role loses access at once,
    # even with a token issued before the change.
    if user is None or user.role is None:
        raise credentials_error
    if user.role == Role.PIPELINE and not _pipeline_may_call(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The pipeline account can only record deployments and check exceptions",
        )
    return CurrentUser(
        username=user.username,
        role=user.role,
        owner_team=user.owner_team,
        approval_level=user.approval_level,
    )


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
