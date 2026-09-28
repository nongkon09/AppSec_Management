import logging
import secrets
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.db import get_db
from app.core.deps import CurrentUser, get_current_user
from app.core.security import create_access_token, verify_password
from app.models.user import AuthSource, Role, User
from app.modules.directory import entra, signin
from app.schemas.auth import Token, UserOut

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)

# With local sign-in switched off, these accounts keep a password: the System Admin as
# break-glass when Entra ID is unreachable, and the CI/CD service account.
_ALWAYS_LOCAL = (Role.ADMIN, Role.PIPELINE)


def _issue(user: User) -> str:
    assert user.role is not None
    return create_access_token(
        subject=user.username, role=user.role.value, owner_team=user.owner_team
    )


@router.post("/login", response_model=Token)
def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
) -> Token:
    """Local username/password login. Entra ID accounts sign in through /auth/sso/login."""
    user = db.query(User).filter(User.username == form_data.username).first()
    if (
        not user
        or not user.is_active
        or user.role is None
        or user.auth_source != AuthSource.LOCAL
        or not user.hashed_password
        or not verify_password(form_data.password, user.hashed_password)
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not get_settings().local_login_enabled and user.role not in _ALWAYS_LOCAL:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sign in with Microsoft",
        )
    user.last_login_at = datetime.now(UTC)
    db.commit()
    return Token(access_token=_issue(user))


@router.get("/me", response_model=UserOut)
def read_current_user(
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    user = db.query(User).filter(User.username == current_user.username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


class SsoConfig(BaseModel):
    """Public: what the login page should offer."""

    enabled: bool
    local_login_enabled: bool


@router.get("/sso/config", response_model=SsoConfig)
def sso_config() -> SsoConfig:
    settings = get_settings()
    return SsoConfig(
        enabled=settings.entra_enabled, local_login_enabled=settings.local_login_enabled
    )


def _cookie_secure() -> bool:
    return get_settings().api_base_url.startswith("https://")


def _back_to_app(fragment: str) -> str:
    return f"{get_settings().app_public_url.rstrip('/')}/login/sso#{fragment}"


@router.get("/sso/login")
def sso_login() -> RedirectResponse:
    """Start sign-in with Microsoft: remember state/nonce/PKCE in a cookie, then go."""
    if not get_settings().entra_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SSO is not set up")
    flow = entra.new_flow()
    response = RedirectResponse(entra.authorization_url(flow), status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        entra.FLOW_COOKIE,
        entra.encode_flow(flow),
        max_age=entra.FLOW_MAX_AGE_SECONDS,
        httponly=True,
        secure=_cookie_secure(),
        samesite="lax",
        path="/api/v1/auth/sso",
    )
    return response


@router.get("/sso/callback")
def sso_callback(
    db: Annotated[Session, Depends(get_db)],
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    sso_flow: Annotated[str | None, Cookie()] = None,
) -> RedirectResponse:
    """Microsoft sends the browser back here. The platform token is handed to the app in
    the URL fragment, which browsers never send to a server or write to access logs."""
    if not get_settings().entra_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SSO is not set up")
    try:
        if error:
            logger.info("Entra sign-in returned %s: %s", error, error_description)
            reason = "cancelled" if error == "access_denied" else "sso_failed"
            raise signin.SignInRefused(reason, error)
        flow = entra.decode_flow(sso_flow)
        if not code or not state or not secrets.compare_digest(state, flow.state):
            raise entra.EntraError("state does not match this browser's sign-in")
        tokens = entra.exchange_code(code, flow.verifier)
        claims = entra.validate_id_token(str(tokens.get("id_token", "")), flow.nonce)
        user = signin.sign_in(db, claims)
        target = _back_to_app(f"token={_issue(user)}")
    except signin.SignInRefused as refused:
        logger.info("Entra sign-in refused (%s): %s", refused.code, refused)
        target = _back_to_app(f"error={refused.code}")
    except entra.EntraError as exc:
        logger.warning("Entra sign-in failed: %s", exc)
        target = _back_to_app("error=sso_failed")
    response = RedirectResponse(target, status_code=status.HTTP_302_FOUND)
    response.delete_cookie(entra.FLOW_COOKIE, path="/api/v1/auth/sso")
    return response
