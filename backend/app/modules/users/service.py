"""User/Role management (Requirement.md Section 4: System Admin responsibility).

Local username/password administration — the auth stub this platform ships until SSO
(SAML2/OIDC linked to the organization's AD, Section 7 NFR) replaces it. Every change is
audited (FR-11.1: user/role changes are exactly the kind of significant action that must
be traceable).
"""

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.core.security import hash_password
from app.models.user import Role, User
from app.schemas.user import PasswordReset, UserCreate, UserUpdate


def list_users(db: Session, *, skip: int = 0, limit: int = 50) -> tuple[list[User], int]:
    total = db.execute(select(func.count()).select_from(User)).scalar_one()
    items = (
        db.execute(select(User).order_by(User.username).offset(skip).limit(limit)).scalars().all()
    )
    return list(items), total


def get_user(db: Session, user_id: uuid.UUID) -> User | None:
    return db.get(User, user_id)


def username_or_email_taken(
    db: Session, *, username: str, email: str, exclude_id: uuid.UUID | None = None
) -> bool:
    """True if some *other* user already has this username or email.

    A count check, not `scalar_one_or_none()`: the OR condition can legitimately match
    two different rows at once (e.g. on update, one row via its own unchanged username
    and a second, different row via the target email) — `scalar_one_or_none()` would
    raise `MultipleResultsFound` on that, when what the caller actually wants is a plain
    yes/no. `exclude_id` lets an update check for conflicts with *other* accounts without
    tripping over the row being updated matching itself by username.
    """
    stmt = (
        select(func.count())
        .select_from(User)
        .where((User.username == username) | (User.email == email))
    )
    if exclude_id is not None:
        stmt = stmt.where(User.id != exclude_id)
    return db.execute(stmt).scalar_one() > 0


def create_user(db: Session, payload: UserCreate, actor: str) -> User:
    user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        role=payload.role,
        owner_team=payload.owner_team,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.flush()
    record_audit(
        db,
        actor=actor,
        action="user.create",
        entity_type="user",
        entity_id=user.id,
        after={
            "username": user.username,
            "role": user.role.value,
            "owner_team": user.owner_team,
            "is_active": user.is_active,
        },
    )
    db.commit()
    db.refresh(user)
    return user


def update_user(db: Session, user: User, payload: UserUpdate, actor: str) -> User:
    before = {
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role.value,
        "owner_team": user.owner_team,
        "is_active": user.is_active,
    }
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(user, field, value)

    # Section 4 fail-closed rule: a Dev Team account with no OwnerTeam sees nothing by
    # design (deps.py), so the combination must never be saved even via a partial update.
    if user.role == Role.DEV_TEAM and not user.owner_team:
        raise ValueError("owner_team is required for the Development Team role")

    after = {
        "full_name": user.full_name,
        "email": user.email,
        "role": user.role.value,
        "owner_team": user.owner_team,
        "is_active": user.is_active,
    }
    record_audit(
        db,
        actor=actor,
        action="user.update",
        entity_type="user",
        entity_id=user.id,
        before=before,
        after=after,
    )
    db.commit()
    db.refresh(user)
    return user


def reset_password(db: Session, user: User, payload: PasswordReset, actor: str) -> User:
    user.hashed_password = hash_password(payload.new_password)
    record_audit(
        db,
        actor=actor,
        action="user.reset_password",
        entity_type="user",
        entity_id=user.id,
        after={"username": user.username},
    )
    db.commit()
    db.refresh(user)
    return user
