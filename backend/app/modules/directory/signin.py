"""Sign-in with Entra ID: find or create the account, refresh its app roles and groups
from the verified token, and decide its role from the mappings."""

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.config import get_settings
from app.models.user import AuthSource, User
from app.modules.directory import service

logger = logging.getLogger(__name__)
ACTOR = "entra-sso"


class SignInRefused(Exception):
    """`code` is shown to the user as a plain-language reason on the login page."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def _username(claims: dict[str, Any]) -> str:
    value = claims.get("preferred_username") or claims.get("upn") or claims.get("email")
    if not value:
        raise SignInRefused("sso_failed", "token has no preferred_username/upn/email")
    return str(value).strip().lower()


def _find(db: Session, oid: str, username: str) -> User | None:
    user = db.execute(select(User).where(User.entra_object_id == oid)).scalar_one_or_none()
    if user is not None:
        return user
    user = db.execute(
        select(User).where(func.lower(User.username) == username)
    ).scalar_one_or_none()
    if user is None:
        return None
    if user.auth_source != AuthSource.ENTRA or user.entra_object_id:
        # Never take over a local account (or another Entra account) by name alone.
        raise SignInRefused("local_conflict", f"username {username} belongs to another account")
    user.entra_object_id = oid  # an account SCIM created before its first sign-in
    return user


def sign_in(db: Session, claims: dict[str, Any]) -> User:
    oid = str(claims["oid"])
    username = _username(claims)
    user = _find(db, oid, username)
    created = False
    if user is None:
        if not get_settings().entra_jit_provisioning:
            raise SignInRefused("not_provisioned", f"{username} has not been provisioned")
        email = str(claims.get("email") or username).lower()
        if db.execute(select(User).where(func.lower(User.email) == email)).first():
            raise SignInRefused("local_conflict", f"email {email} belongs to another account")
        user = User(
            username=username,
            email=email,
            full_name=str(claims.get("name") or username),
            hashed_password=None,
            role=None,
            auth_source=AuthSource.ENTRA,
            entra_object_id=oid,
            directory_roles=[],
            is_active=True,
        )
        db.add(user)
        db.flush()
        created = True
    if claims.get("name"):
        user.full_name = str(claims["name"])

    user.directory_roles = [str(role) for role in claims.get("roles", [])]
    if "groups" in claims:
        service.set_user_groups(db, user, [str(g) for g in claims["groups"]])
    elif "groups" in (claims.get("_claim_names") or {}):
        # Group overage (>200 groups): the token cannot list them. Keep what SCIM sent.
        logger.warning("Entra token for %s has group overage; using SCIM memberships", username)
    granted = service.apply_access(db, user, ACTOR)

    if not user.is_active:
        db.commit()
        raise SignInRefused("inactive", f"{username} is disabled")
    if granted is None:
        if created:
            db.rollback()  # do not keep an account that cannot do anything
        else:
            db.commit()
        raise SignInRefused("not_assigned", f"{username} matches no role mapping")

    if created:
        record_audit(
            db,
            actor=ACTOR,
            action="user.create",
            entity_type="user",
            entity_id=user.id,
            after={
                "username": user.username,
                "auth_source": "entra",
                "role": user.role.value if user.role else None,
                "owner_team": user.owner_team,
                "approval_level": user.approval_level.value,
            },
        )
    user.last_login_at = datetime.now(UTC)
    db.commit()
    db.refresh(user)
    return user
