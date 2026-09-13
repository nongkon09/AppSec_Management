"""policy sets and finding backlog fields

Adds the versioned Severity/SLA PolicySet table (Requirement.md FR-4.4, FR-5.1) and
re-shapes `findings` so SAST and Pentest findings share one backlog with SBOM findings
(FR-6.5.6): the anchor moves from Component to AppVersion, `component_id`/`cve_id`
become nullable, and the SLA/remediation/VEX tracking columns are added.

`findings` is recreated rather than altered. It cannot hold meaningful rows yet — SBOM
ingestion (FR-2/FR-3) is not implemented, and pre-existing rows have no `app_version_id`
to back-fill from — and recreating avoids the ALTER COLUMN type change from a free-text
`source` (lowercase values) to a native enum, which no dialect can cast cleanly. The
dependent `tickets` and `waivers` tables are dropped and recreated unchanged because they
reference `findings.id`.

Revision ID: ed804b338ac7
Revises: 2c89fea45c0f
Create Date: 2026-09-13 16:45:19.131145

"""

from collections.abc import Sequence

import sqlalchemy as sa
import app.db_types
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "ed804b338ac7"
down_revision: str | None = "2c89fea45c0f"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

# On PostgreSQL an enum type is a standalone object with a lifecycle of its own, and
# rebuilding a table that uses one is awkward by default: `op.create_table` emits
# CREATE TYPE with checkfirst=False (so it fails if the type survived the DROP TABLE),
# while Alembic's `pg_enum` memo — shared across every revision in one `upgrade` run —
# makes it skip types an earlier revision already created (so it fails the other way,
# with "type does not exist", once this revision has dropped them).
#
# Attaching the types to their own MetaData takes create_table out of the picture
# entirely: no CREATE TYPE is emitted for them, and this revision creates and drops them
# explicitly below. Those calls are no-ops on dialects without native enums (SQLite
# renders a VARCHAR + CHECK constraint instead).
_ENUM_METADATA = sa.MetaData()

FINDING_SOURCE = sa.Enum("SBOM", "SAST", "PENTEST", name="finding_source", metadata=_ENUM_METADATA)
FINDING_STATUS = sa.Enum(
    "OPEN",
    "FIXED",
    "RISK_ACCEPTED",
    "SUPPRESSED",
    name="finding_status",
    metadata=_ENUM_METADATA,
)
SEVERITY_TIER = sa.Enum(
    "CRITICAL", "HIGH", "MEDIUM", "LOW", name="severity_tier", metadata=_ENUM_METADATA
)
VEX_STATUS = sa.Enum(
    "AFFECTED",
    "NOT_AFFECTED",
    "FIXED",
    "UNDER_INVESTIGATION",
    name="vex_status",
    metadata=_ENUM_METADATA,
)
WAIVER_STATUS = sa.Enum(
    "ACTIVE", "EXPIRED", "REVOKED", name="waiver_status", metadata=_ENUM_METADATA
)

# Carried over from the initial schema; still needed after a downgrade.
_LEGACY_ENUMS = (SEVERITY_TIER, VEX_STATUS, WAIVER_STATUS)
# Introduced by this revision, so these are the only types downgrade may remove.
_NEW_ENUMS = (FINDING_SOURCE, FINDING_STATUS)


def _create_enum_types(enum_types: Sequence[sa.Enum]) -> None:
    """checkfirst keeps this safe whether the type survived an earlier revision or not."""
    bind = op.get_bind()
    for enum_type in enum_types:
        enum_type.create(bind, checkfirst=True)


def _create_tickets() -> None:
    op.create_table(
        "tickets",
        sa.Column("finding_id", app.db_types.GUID(), nullable=False),
        sa.Column("external_system", sa.String(length=64), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("id", app.db_types.GUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def _create_waivers() -> None:
    op.create_table(
        "waivers",
        sa.Column("finding_id", app.db_types.GUID(), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expiry_date", sa.Date(), nullable=False),
        sa.Column("status", WAIVER_STATUS, nullable=False),
        sa.Column("id", app.db_types.GUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )


def upgrade() -> None:
    op.create_table(
        "policy_sets",
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("effective_from", sa.Date(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("severity_rules", sa.JSON(), nullable=False),
        sa.Column("sla_days", sa.JSON(), nullable=False),
        sa.Column("downgrade_dev_scope_findings", sa.Boolean(), nullable=False),
        sa.Column("auto_ticket_dev_scope_findings", sa.Boolean(), nullable=False),
        sa.Column("id", app.db_types.GUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_policy_sets_effective_from"), "policy_sets", ["effective_from"], unique=False
    )
    op.create_index(op.f("ix_policy_sets_version"), "policy_sets", ["version"], unique=True)

    op.drop_table("waivers")
    op.drop_table("tickets")
    op.drop_index(op.f("ix_findings_cve_id"), table_name="findings")
    op.drop_table("findings")
    _create_enum_types(_LEGACY_ENUMS + _NEW_ENUMS)

    op.create_table(
        "findings",
        sa.Column("app_version_id", app.db_types.GUID(), nullable=False),
        sa.Column("component_id", app.db_types.GUID(), nullable=True),
        sa.Column("pentest_project_id", app.db_types.GUID(), nullable=True),
        sa.Column("source", FINDING_SOURCE, nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("kev_flag", sa.Boolean(), nullable=False),
        sa.Column("severity_tier", SEVERITY_TIER, nullable=False),
        sa.Column("status", FINDING_STATUS, nullable=False),
        sa.Column("vex_status", VEX_STATUS, nullable=False),
        sa.Column("vex_justification", sa.String(length=128), nullable=True),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("policy_version", sa.Integer(), nullable=True),
        sa.Column("fixed_version", sa.String(length=255), nullable=True),
        sa.Column("reference_url", sa.String(length=1024), nullable=True),
        sa.Column("remediation_plan", sa.Text(), nullable=True),
        sa.Column("remediation_plan_updated_by", sa.String(length=255), nullable=True),
        sa.Column("remediation_plan_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "first_detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", app.db_types.GUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["app_version_id"], ["app_versions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["component_id"], ["components.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["pentest_project_id"], ["pentest_projects.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "app_version_id", "component_id", "cve_id", name="uq_finding_version_component_cve"
        ),
    )
    op.create_index(
        op.f("ix_findings_app_version_id"), "findings", ["app_version_id"], unique=False
    )
    op.create_index(op.f("ix_findings_component_id"), "findings", ["component_id"], unique=False)
    op.create_index(op.f("ix_findings_cve_id"), "findings", ["cve_id"], unique=False)
    op.create_index(op.f("ix_findings_due_date"), "findings", ["due_date"], unique=False)
    op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)

    _create_tickets()
    _create_waivers()


def downgrade() -> None:
    op.drop_table("waivers")
    op.drop_table("tickets")
    op.drop_index(op.f("ix_findings_status"), table_name="findings")
    op.drop_index(op.f("ix_findings_due_date"), table_name="findings")
    op.drop_index(op.f("ix_findings_cve_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_component_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_app_version_id"), table_name="findings")
    op.drop_table("findings")
    # The two Finding enums exist only in this revision's schema.
    for enum_type in _NEW_ENUMS:
        enum_type.drop(op.get_bind(), checkfirst=True)
    _create_enum_types(_LEGACY_ENUMS)

    op.create_table(
        "findings",
        sa.Column("component_id", app.db_types.GUID(), nullable=False),
        sa.Column("cve_id", sa.String(length=64), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("kev_flag", sa.Boolean(), nullable=False),
        sa.Column("severity_tier", SEVERITY_TIER, nullable=False),
        sa.Column("vex_status", VEX_STATUS, nullable=False),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("id", app.db_types.GUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["component_id"], ["components.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_findings_cve_id"), "findings", ["cve_id"], unique=False)
    _create_tickets()
    _create_waivers()

    op.drop_index(op.f("ix_policy_sets_version"), table_name="policy_sets")
    op.drop_index(op.f("ix_policy_sets_effective_from"), table_name="policy_sets")
    op.drop_table("policy_sets")
