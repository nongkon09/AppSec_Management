import enum

from sqlalchemy import Boolean, Enum, String
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


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role, name="user_role"), nullable=False)
    # Only meaningful for DEV_TEAM role: scopes visibility to Applications owned by this team
    # (Requirement.md Section 4 note: "Role-based Data Scoping ตาม OwnerTeam/Business Unit")
    owner_team: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    approval_level: Mapped[ApprovalLevel] = mapped_column(
        Enum(ApprovalLevel, name="approval_level"), nullable=False, default=ApprovalLevel.NONE
    )
