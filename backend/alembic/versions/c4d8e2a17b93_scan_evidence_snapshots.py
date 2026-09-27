"""scan evidence snapshots

Scan snapshots for audit (docs/risk-exception-design.md 3.7): pipeline evidence on
scan_results (tool, image digest, commit, pipeline run, SBOM hash/file, SCA import time)
and scan_findings, the findings each scan reported, frozen at scan time.

Revision ID: c4d8e2a17b93
Revises: b7e3c91d4f20
Create Date: 2026-09-27 15:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "c4d8e2a17b93"
down_revision: str | None = "b7e3c91d4f20"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

_COLUMNS = (
    ("source_tool", sa.String(length=64)),
    ("image_digest", sa.String(length=255)),
    ("commit_sha", sa.String(length=64)),
    ("pipeline_run", sa.String(length=255)),
    ("sca_bom_imported_at", sa.DateTime(timezone=True)),
    ("sbom_sha256", sa.String(length=64)),
    ("sbom_path", sa.String(length=1024)),
)


def upgrade() -> None:
    for name, column_type in _COLUMNS:
        op.add_column("scan_results", sa.Column(name, column_type, nullable=True))
    op.create_table(
        "scan_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_result_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scan_results.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "finding_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("severity_tier", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.UniqueConstraint("scan_result_id", "finding_id", name="uq_scan_finding"),
    )
    op.create_index("ix_scan_findings_scan_result_id", "scan_findings", ["scan_result_id"])
    op.create_index("ix_scan_findings_finding_id", "scan_findings", ["finding_id"])


def downgrade() -> None:
    op.drop_table("scan_findings")
    for name, _ in reversed(_COLUMNS):
        op.drop_column("scan_results", name)
