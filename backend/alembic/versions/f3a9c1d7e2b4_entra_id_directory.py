"""entra id directory

Accounts can now be managed by Entra ID: sign-in through Microsoft (OIDC), provisioning
through SCIM, and a role resolved from app roles or group membership via role_mappings.
An Entra account has no local password and, until a mapping matches, no role.

Revision ID: f3a9c1d7e2b4
Revises: d2f6a8c31e57
Create Date: 2026-09-28 16:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from app.db_types import GUID

revision: str = "f3a9c1d7e2b4"
down_revision: str | None = "d2f6a8c31e57"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

# SQLAlchemy stores enum member names, so the labels are upper case.
ROLES = ("APPSEC", "DEV_TEAM", "LEGAL", "MANAGEMENT", "AUDIT", "ADMIN", "PIPELINE")
LEVELS = ("NONE", "L1", "L2", "L3")


def upgrade() -> None:
    auth_source = sa.Enum("LOCAL", "ENTRA", name="auth_source")
    mapping_kind = sa.Enum("APP_ROLE", "GROUP", name="mapping_kind")
    auth_source.create(op.get_bind(), checkfirst=True)
    mapping_kind.create(op.get_bind(), checkfirst=True)
    user_role = postgresql.ENUM(*ROLES, name="user_role", create_type=False)
    approval_level = postgresql.ENUM(*LEVELS, name="approval_level", create_type=False)

    op.alter_column("users", "hashed_password", existing_type=sa.String(255), nullable=True)
    op.alter_column("users", "role", existing_type=user_role, nullable=True)
    op.add_column(
        "users",
        sa.Column(
            "auth_source",
            postgresql.ENUM("LOCAL", "ENTRA", name="auth_source", create_type=False),
            nullable=False,
            server_default="LOCAL",
        ),
    )
    op.add_column("users", sa.Column("entra_object_id", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("scim_external_id", sa.String(length=255), nullable=True))
    op.add_column(
        "users", sa.Column("directory_roles", sa.JSON(), nullable=False, server_default="[]")
    )
    op.add_column("users", sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_users_entra_object_id", "users", ["entra_object_id"], unique=True)

    op.create_table(
        "directory_groups",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_directory_groups_external_id", "directory_groups", ["external_id"], unique=True
    )
    op.create_table(
        "directory_group_members",
        sa.Column(
            "group_id",
            GUID(),
            sa.ForeignKey("directory_groups.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "user_id", GUID(), sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
        ),
    )
    op.create_table(
        "role_mappings",
        sa.Column("id", GUID(), primary_key=True),
        sa.Column(
            "kind",
            postgresql.ENUM("APP_ROLE", "GROUP", name="mapping_kind", create_type=False),
            nullable=False,
        ),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("role", user_role, nullable=False),
        sa.Column("approval_level", approval_level, nullable=False, server_default="NONE"),
        sa.Column("owner_team", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("kind", "value", name="uq_role_mapping_kind_value"),
    )


def downgrade() -> None:
    op.drop_table("role_mappings")
    op.drop_table("directory_group_members")
    op.drop_index("ix_directory_groups_external_id", table_name="directory_groups")
    op.drop_table("directory_groups")
    op.drop_index("ix_users_entra_object_id", table_name="users")
    for column in (
        "last_login_at",
        "directory_roles",
        "scim_external_id",
        "entra_object_id",
        "auth_source",
    ):
        op.drop_column("users", column)
    # Directory-only accounts have no password or role; they cannot survive the downgrade.
    op.execute("DELETE FROM users WHERE hashed_password IS NULL OR role IS NULL")
    op.alter_column("users", "role", nullable=False)
    op.alter_column("users", "hashed_password", nullable=False)
    sa.Enum(name="mapping_kind").drop(op.get_bind(), checkfirst=True)
    sa.Enum(name="auth_source").drop(op.get_bind(), checkfirst=True)
