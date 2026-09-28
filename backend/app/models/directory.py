"""Entra ID directory data: groups synced by SCIM and the mappings that turn app roles
or group membership into a platform role (docs/entra-id.md)."""

import enum
import uuid

from sqlalchemy import Enum, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.db_types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.user import ApprovalLevel, Role


class DirectoryGroup(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An Entra ID group, created by SCIM or first seen in a sign-in token."""

    __tablename__ = "directory_groups"

    # The Entra object id: SCIM sends it as externalId, tokens list it in `groups`.
    external_id: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    # Unknown until SCIM sends it; a group seen only in a token has no name.
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)


class DirectoryGroupMember(Base):
    __tablename__ = "directory_group_members"

    group_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("directory_groups.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )


class MappingKind(enum.StrEnum):
    APP_ROLE = "app_role"  # value = the app role's value, e.g. "AppSec.Lead"
    GROUP = "group"  # value = the group's Entra object id


class RoleMapping(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One rule: holders of this app role / members of this group get this access."""

    __tablename__ = "role_mappings"
    __table_args__ = (UniqueConstraint("kind", "value", name="uq_role_mapping_kind_value"),)

    kind: Mapped[MappingKind] = mapped_column(
        Enum(MappingKind, name="mapping_kind"), nullable=False
    )
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[Role] = mapped_column(Enum(Role, name="user_role"), nullable=False)
    approval_level: Mapped[ApprovalLevel] = mapped_column(
        Enum(ApprovalLevel, name="approval_level"), nullable=False, default=ApprovalLevel.NONE
    )
    owner_team: Mapped[str | None] = mapped_column(String(255), nullable=True)
