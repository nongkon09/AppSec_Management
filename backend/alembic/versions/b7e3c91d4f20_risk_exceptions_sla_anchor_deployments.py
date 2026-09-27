"""risk exceptions, SLA anchor, active versions, deployments, control library

See docs/risk-exception-design.md sections 3 and 5.1.

- findings: issue_key + sla_started_on (inherited per Application issue) + residual tier;
  due dates are recomputed from the anchor, which also undoes the old bug where every
  Dependency-Track sync pushed the due date forward to "today + SLA".
- app_versions.is_active: latest ingested version per Application (no deployments yet).
- users.approval_level (+ role PIPELINE); existing AppSec users start at L2.
- waivers -> risk_exceptions (is_legacy = true: they never had four-eye review).

Revision ID: b7e3c91d4f20
Revises: 8602860317fd
Create Date: 2026-09-27 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b7e3c91d4f20"
down_revision: str | None = "8602860317fd"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None

# SQLAlchemy persists enum member NAMES (upper case) in these Postgres types.
_ENUMS = {
    "approval_level": ("NONE", "L1", "L2", "L3"),
    "deployment_environment": ("PRODUCTION", "STAGING", "DEV"),
    "deployment_source": ("PIPELINE", "MANUAL"),
    "exception_type": ("RISK_ACCEPTANCE", "FALSE_POSITIVE", "NOT_AFFECTED"),
    "exception_status": (
        "PENDING",
        "APPROVED",
        "REJECTED",
        "WITHDRAWN",
        "EXPIRED",
        "REVOKED",
        "CLOSED",
    ),
    "approval_decision": ("APPROVE", "REJECT"),
    "vex_justification": (
        "CODE_NOT_PRESENT",
        "CODE_NOT_REACHABLE",
        "REQUIRES_CONFIGURATION",
        "REQUIRES_DEPENDENCY",
        "REQUIRES_ENVIRONMENT",
        "PROTECTED_BY_COMPILER",
        "PROTECTED_AT_RUNTIME",
        "PROTECTED_AT_PERIMETER",
        "PROTECTED_BY_MITIGATING_CONTROL",
    ),
    "control_category": ("NETWORK", "APPLICATION", "MONITORING", "PROCESS"),
    "control_effectiveness": ("LOW", "MEDIUM", "HIGH"),
}


def _enum(name: str) -> postgresql.ENUM:
    return postgresql.ENUM(*_ENUMS.get(name, ()), name=name, create_type=False)


def _guid() -> postgresql.UUID:
    return postgresql.UUID(as_uuid=True)


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    ]


def upgrade() -> None:
    bind = op.get_bind()

    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'PIPELINE'")

    for name, values in _ENUMS.items():
        postgresql.ENUM(*values, name=name).create(bind, checkfirst=True)

    # --- users -----------------------------------------------------------------------
    op.add_column(
        "users",
        sa.Column("approval_level", _enum("approval_level"), nullable=False, server_default="NONE"),
    )
    op.execute("UPDATE users SET approval_level = 'L2' WHERE role = 'APPSEC'")

    # --- app_versions.is_active --------------------------------------------------------
    op.add_column(
        "app_versions",
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute(
        """
        UPDATE app_versions SET is_active = true
        WHERE id IN (
            SELECT DISTINCT ON (application_id) id FROM app_versions
            ORDER BY application_id, last_ingested_at DESC NULLS LAST, created_at DESC
        )
        """
    )

    # --- findings: issue identity, SLA anchor, residual tier ------------------------------
    op.add_column("findings", sa.Column("issue_key", sa.String(length=1024), nullable=True))
    op.add_column("findings", sa.Column("sla_started_on", sa.Date(), nullable=True))
    op.add_column(
        "findings", sa.Column("residual_severity_tier", _enum("severity_tier"), nullable=True)
    )
    # Mirrors app.models.finding.build_issue_key / purl_package: the package is the purl
    # without version, qualifiers and subpath, falling back to the component name.
    op.execute(
        """
        UPDATE findings f SET issue_key = left(
            CASE f.source::text
                WHEN 'SBOM' THEN 'sbom:' || coalesce(
                    (SELECT nullif(lower(trim(regexp_replace(
                         split_part(split_part(c.purl, '#', 1), '?', 1), '@[^@]*$', ''))), '')
                     FROM components c WHERE c.id = f.component_id),
                    (SELECT lower(trim(c.component_name))
                     FROM components c WHERE c.id = f.component_id),
                    ''
                ) || ':' || lower(trim(coalesce(f.cve_id, f.title, '')))
                WHEN 'PENTEST' THEN 'pentest:' || coalesce(f.pentest_project_id::text, 'None')
                    || ':' || lower(trim(coalesce(f.cve_id, f.title, '')))
                ELSE lower(f.source::text) || ':' || lower(trim(coalesce(f.cve_id, f.title, '')))
            END, 1024)
        """
    )
    op.execute("UPDATE findings SET sla_started_on = first_detected_at::date")
    op.execute(
        """
        WITH anchors AS (
            SELECT v.application_id, f.issue_key, min(f.first_detected_at)::date AS started
            FROM findings f JOIN app_versions v ON v.id = f.app_version_id
            WHERE f.status <> 'FIXED'
            GROUP BY v.application_id, f.issue_key
        )
        UPDATE findings f SET sla_started_on = a.started
        FROM app_versions v, anchors a
        WHERE v.id = f.app_version_id AND a.application_id = v.application_id
          AND a.issue_key = f.issue_key AND f.status <> 'FIXED'
        """
    )
    op.alter_column("findings", "issue_key", nullable=False)
    op.alter_column("findings", "sla_started_on", nullable=False)
    op.create_index("ix_findings_issue_key", "findings", ["issue_key"])

    # Recompute due dates from the anchor with the policy in force today (fixes the
    # "due date slides forward on every sync" bug).
    sla_days = bind.execute(
        sa.text(
            "SELECT sla_days FROM policy_sets WHERE effective_from <= current_date "
            "ORDER BY effective_from DESC, version DESC LIMIT 1"
        )
    ).scalar_one_or_none()
    if sla_days is not None:
        for tier in ("critical", "high", "medium", "low"):
            days = sla_days.get(tier)
            if days is None:
                op.execute(
                    f"UPDATE findings SET due_date = NULL WHERE severity_tier = '{tier.upper()}'"
                )
            else:
                op.execute(
                    f"UPDATE findings SET due_date = sla_started_on + {int(days)} "
                    f"WHERE severity_tier = '{tier.upper()}'"
                )

    # --- deployments -------------------------------------------------------------------
    op.create_table(
        "deployments",
        sa.Column("id", _guid(), primary_key=True),
        sa.Column(
            "application_id",
            _guid(),
            sa.ForeignKey("applications.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "app_version_id",
            _guid(),
            sa.ForeignKey("app_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("environment", _enum("deployment_environment"), nullable=False),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("image_digest", sa.String(length=255), nullable=True),
        sa.Column("reference_url", sa.String(length=1024), nullable=True),
        sa.Column("source", _enum("deployment_source"), nullable=False),
        sa.Column("recorded_by", sa.String(length=255), nullable=False),
        *_timestamps(),
    )
    op.create_index("ix_deployments_application_id", "deployments", ["application_id"])
    op.create_index("ix_deployments_app_version_id", "deployments", ["app_version_id"])

    # --- control library ----------------------------------------------------------------
    op.create_table(
        "security_controls",
        sa.Column("id", _guid(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False, unique=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", _enum("control_category"), nullable=False),
        sa.Column("owner", sa.String(length=255), nullable=False),
        sa.Column("evidence_url", sa.String(length=1024), nullable=True),
        sa.Column("effectiveness", _enum("control_effectiveness"), nullable=False),
        sa.Column("review_due_on", sa.Date(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        *_timestamps(),
    )

    # --- risk exceptions ----------------------------------------------------------------
    op.create_table(
        "risk_exceptions",
        sa.Column("id", _guid(), primary_key=True),
        sa.Column("reference", sa.String(length=32), nullable=False, unique=True),
        sa.Column("exception_type", _enum("exception_type"), nullable=False),
        sa.Column("status", _enum("exception_status"), nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("compensating_measures", sa.Text(), nullable=True),
        sa.Column("vex_justification", _enum("vex_justification"), nullable=True),
        sa.Column("original_severity_tier", _enum("severity_tier"), nullable=False),
        sa.Column("kev_involved", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("residual_severity_tier", _enum("severity_tier"), nullable=True),
        sa.Column("expires_on", sa.Date(), nullable=False),
        sa.Column("required_approvals", sa.Integer(), nullable=False),
        sa.Column("required_min_level", _enum("approval_level"), nullable=False),
        sa.Column("required_top_level", _enum("approval_level"), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_by", sa.String(length=255), nullable=True),
        sa.Column("ended_reason", sa.Text(), nullable=True),
        sa.Column("is_legacy", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("needs_review", sa.Boolean(), nullable=False, server_default=sa.false()),
        *_timestamps(),
    )
    op.create_index("ix_risk_exceptions_reference", "risk_exceptions", ["reference"])
    op.create_index("ix_risk_exceptions_status", "risk_exceptions", ["status"])
    op.create_index("ix_risk_exceptions_requested_by", "risk_exceptions", ["requested_by"])

    op.create_table(
        "exception_items",
        sa.Column("id", _guid(), primary_key=True),
        sa.Column(
            "exception_id",
            _guid(),
            sa.ForeignKey("risk_exceptions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "application_id",
            _guid(),
            sa.ForeignKey("applications.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("issue_key", sa.String(length=1024), nullable=False),
        sa.Column(
            "origin_finding_id",
            _guid(),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("label", sa.String(length=1024), nullable=False),
        sa.UniqueConstraint(
            "exception_id", "application_id", "issue_key", name="uq_exception_item_issue"
        ),
    )
    op.create_index("ix_exception_items_exception_id", "exception_items", ["exception_id"])
    op.create_index("ix_exception_items_application_id", "exception_items", ["application_id"])
    op.create_index("ix_exception_items_issue_key", "exception_items", ["issue_key"])

    op.create_table(
        "exception_approvals",
        sa.Column("id", _guid(), primary_key=True),
        sa.Column(
            "exception_id",
            _guid(),
            sa.ForeignKey("risk_exceptions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("approver", sa.String(length=255), nullable=False),
        sa.Column("approver_level", _enum("approval_level"), nullable=False),
        sa.Column("decision", _enum("approval_decision"), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("exception_id", "approver", name="uq_exception_approval_approver"),
    )
    op.create_index("ix_exception_approvals_exception_id", "exception_approvals", ["exception_id"])

    op.create_table(
        "exception_bypasses",
        sa.Column("id", _guid(), primary_key=True),
        sa.Column(
            "exception_id",
            _guid(),
            sa.ForeignKey("risk_exceptions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tool", sa.String(length=64), nullable=False),
        sa.Column("reference_url", sa.String(length=1024), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("recorded_by", sa.String(length=255), nullable=False),
        sa.Column("bypassed_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_exception_bypasses_exception_id", "exception_bypasses", ["exception_id"])

    op.create_table(
        "exception_controls",
        sa.Column(
            "exception_id",
            _guid(),
            sa.ForeignKey("risk_exceptions.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "control_id",
            _guid(),
            sa.ForeignKey("security_controls.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
    )

    _migrate_waivers(bind)

    op.drop_table("waivers")
    op.execute("DROP TYPE IF EXISTS waiver_status")


def _migrate_waivers(bind: sa.engine.Connection) -> None:
    """Each Waiver becomes a legacy risk-acceptance exception covering its Finding's issue.
    Approval requirements follow the new matrix, so a still-pending legacy request must
    now pass four-eye review; historical approvers are recorded at level NONE because
    their level at the time is unknown."""
    status_map = {
        "PENDING": "PENDING",
        "ACTIVE": "APPROVED",
        "REJECTED": "REJECTED",
        "EXPIRED": "EXPIRED",
        "REVOKED": "REVOKED",
    }
    rows = (
        bind.execute(
            sa.text(
                """
            SELECT w.id, w.requested_by, w.approved_by, w.reason, w.expiry_date,
                   w.status::text AS status, w.created_at, w.updated_at,
                   f.id AS finding_id, f.issue_key, f.severity_tier::text AS tier,
                   f.kev_flag, f.cve_id, f.title, v.application_id
            FROM waivers w
            JOIN findings f ON f.id = w.finding_id
            JOIN app_versions v ON v.id = f.app_version_id
            ORDER BY w.created_at
            """
            )
        )
        .mappings()
        .all()
    )

    counters: dict[int, int] = {}
    for row in rows:
        year = row["created_at"].year
        counters[year] = counters.get(year, 0) + 1
        reference = f"EXC-{year}-{counters[year]:04d}"
        if row["tier"] == "CRITICAL" or row["kev_flag"]:
            required = (2, "L2", "L3")
        elif row["tier"] == "HIGH":
            required = (1, "L2", "L2")
        else:
            required = (1, "L1", "L1")
        status = status_map[row["status"]]
        exception_id = bind.execute(
            sa.text(
                """
                INSERT INTO risk_exceptions (
                    id, reference, exception_type, status, requested_by, reason,
                    original_severity_tier, kev_involved, expires_on, required_approvals,
                    required_min_level, required_top_level, decided_at, ended_by,
                    is_legacy, needs_review, created_at, updated_at
                ) VALUES (
                    gen_random_uuid(), :reference, 'RISK_ACCEPTANCE', :status, :requested_by,
                    :reason, :tier, :kev, :expires_on, :count, :min_level, :top_level,
                    :decided_at, :ended_by, true, false, :created_at, :updated_at
                ) RETURNING id
                """
            ),
            {
                "reference": reference,
                "status": status,
                "requested_by": row["requested_by"],
                "reason": row["reason"],
                "tier": row["tier"],
                "kev": row["kev_flag"],
                "expires_on": row["expiry_date"],
                "count": required[0],
                "min_level": required[1],
                "top_level": required[2],
                "decided_at": row["updated_at"] if status != "PENDING" else None,
                "ended_by": row["approved_by"] if status in ("REJECTED", "REVOKED") else None,
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            },
        ).scalar_one()
        bind.execute(
            sa.text(
                """
                INSERT INTO exception_items
                    (id, exception_id, application_id, issue_key, origin_finding_id, label)
                VALUES (gen_random_uuid(), :exception_id, :application_id, :issue_key,
                        :finding_id, :label)
                """
            ),
            {
                "exception_id": exception_id,
                "application_id": row["application_id"],
                "issue_key": row["issue_key"],
                "finding_id": row["finding_id"],
                "label": (row["cve_id"] or row["title"] or row["issue_key"])[:1024],
            },
        )
        if row["approved_by"] and status != "PENDING":
            bind.execute(
                sa.text(
                    """
                    INSERT INTO exception_approvals
                        (id, exception_id, approver, approver_level, decision, comment, decided_at)
                    VALUES (gen_random_uuid(), :exception_id, :approver, 'NONE', :decision,
                            'Migrated from single-approver waiver', :decided_at)
                    """
                ),
                {
                    "exception_id": exception_id,
                    "approver": row["approved_by"],
                    "decision": "REJECT" if status == "REJECTED" else "APPROVE",
                    "decided_at": row["updated_at"],
                },
            )


def downgrade() -> None:
    """Best-effort: restores the waivers table from risk-acceptance exceptions (first item
    only) and drops everything this revision added. Exceptions of other types, control
    links, deployments and approval history are lost."""
    bind = op.get_bind()
    postgresql.ENUM(
        "PENDING", "ACTIVE", "REJECTED", "EXPIRED", "REVOKED", name="waiver_status"
    ).create(bind, checkfirst=True)
    op.create_table(
        "waivers",
        sa.Column("id", _guid(), primary_key=True),
        sa.Column(
            "finding_id",
            _guid(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("requested_by", sa.String(length=255), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expiry_date", sa.Date(), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(name="waiver_status", create_type=False),
            nullable=False,
            server_default="PENDING",
        ),
        *_timestamps(),
    )
    op.execute(
        """
        INSERT INTO waivers (id, finding_id, requested_by, approved_by, reason, expiry_date,
                             status, created_at, updated_at)
        SELECT e.id, i.origin_finding_id, e.requested_by,
               (SELECT a.approver FROM exception_approvals a WHERE a.exception_id = e.id
                ORDER BY a.decided_at DESC LIMIT 1),
               e.reason, e.expires_on,
               (CASE e.status::text
                    WHEN 'APPROVED' THEN 'ACTIVE' WHEN 'CLOSED' THEN 'EXPIRED'
                    WHEN 'WITHDRAWN' THEN 'REJECTED' ELSE e.status::text END)::waiver_status,
               e.created_at, e.updated_at
        FROM risk_exceptions e
        JOIN LATERAL (
            SELECT origin_finding_id FROM exception_items
            WHERE exception_id = e.id AND origin_finding_id IS NOT NULL LIMIT 1
        ) i ON true
        WHERE e.exception_type::text = 'RISK_ACCEPTANCE'
        """
    )

    for table in (
        "exception_controls",
        "exception_bypasses",
        "exception_approvals",
        "exception_items",
        "risk_exceptions",
        "security_controls",
        "deployments",
    ):
        op.drop_table(table)

    op.drop_index("ix_findings_issue_key", table_name="findings")
    op.drop_column("findings", "residual_severity_tier")
    op.drop_column("findings", "sla_started_on")
    op.drop_column("findings", "issue_key")
    op.drop_column("app_versions", "is_active")
    op.drop_column("users", "approval_level")

    for name in _ENUMS:
        op.execute(f"DROP TYPE IF EXISTS {name}")
    # user_role keeps 'PIPELINE': Postgres cannot drop an enum value in place; no row
    # uses it after downgrade unless a pipeline user was created, which must be removed
    # first.
