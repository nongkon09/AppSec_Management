import enum
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class Role(enum.StrEnum):
    """RBAC roles per Requirement.md Section 4 (Users & Access)."""

    APPSEC = "appsec"  # Security Team - full access
    DEV_TEAM = "dev_team"  # Development Team / Tech Lead - scoped by owner_team
    LEGAL = "legal"  # Legal / Compliance - License Compliance module
    MANAGEMENT = "management"  # Management / Product Owner - read-only summary
    AUDIT = "audit"  # Compliance / Audit - read-only + export
    ADMIN = "admin"  # System Admin - user/integration configuration
    PIPELINE = "pipeline"  # CI/CD service account - may only record deployments


class ApprovalLevel(enum.StrEnum):
    """Who may act as Checker on a risk decision (docs/risk-exception-design.md 3.5)."""

    NONE = "none"
    L1 = "l1"  # AppSec analyst
    L2 = "l2"  # AppSec lead
    L3 = "l3"  # CISO / risk executive


APPROVAL_LEVEL_RANK = {
    ApprovalLevel.NONE: 0,
    ApprovalLevel.L1: 1,
    ApprovalLevel.L2: 2,
    ApprovalLevel.L3: 3,
}


class AuthSource(enum.StrEnum):
    """Where an account is managed. Entra ID accounts get their role from the directory
    (app roles / groups through RoleMapping) and sign in through Microsoft, never with a
    local password (docs/entra-id.md)."""

    LOCAL = "local"
    ENTRA = "entra"


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # None for Entra ID accounts: they only sign in through Microsoft.
    hashed_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # None when an Entra ID account matches no role mapping: it exists (SCIM created it)
    # but may not sign in until a directory group or app role grants it access.
    role: Mapped[Role | None] = mapped_column(Enum(Role, name="user_role"), nullable=True)
    # Only meaningful for DEV_TEAM role: scopes visibility to Applications owned by this team
    # (Requirement.md Section 4 note: "Role-based Data Scoping ตาม OwnerTeam/Business Unit")
    owner_team: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    approval_level: Mapped[ApprovalLevel] = mapped_column(
        Enum(ApprovalLevel, name="approval_level"), nullable=False, default=ApprovalLevel.NONE
    )
    auth_source: Mapped[AuthSource] = mapped_column(
        Enum(AuthSource, name="auth_source"), nullable=False, default=AuthSource.LOCAL
    )
    # Entra ID object id (the token's `oid`), fixed for the life of the account.
    entra_object_id: Mapped[str | None] = mapped_column(
        String(64), unique=True, index=True, nullable=True
    )
    # SCIM `externalId` as the provisioning service sends it (mailNickname by default).
    scim_external_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # App role values assigned to the account in Entra ID, from SCIM or the last sign-in.
    directory_roles: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
