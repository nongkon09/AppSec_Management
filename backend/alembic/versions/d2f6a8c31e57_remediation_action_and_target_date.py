"""remediation action and target date

A remediation plan now records how the team will fix a finding and by when, alongside
the free-text plan.

Revision ID: d2f6a8c31e57
Revises: c4d8e2a17b93
Create Date: 2026-09-28 10:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d2f6a8c31e57"
down_revision: str | None = "c4d8e2a17b93"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("remediation_action", sa.String(length=32), nullable=True))
    op.add_column("findings", sa.Column("remediation_target_date", sa.Date(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "remediation_target_date")
    op.drop_column("findings", "remediation_action")
