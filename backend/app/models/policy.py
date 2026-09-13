from datetime import date
from typing import Any

from sqlalchemy import JSON, Boolean, Date, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class PolicySet(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Versioned, effective-dated Severity + SLA policy (Requirement.md FR-4.4, FR-5.1).

    Thresholds and SLA day counts must never be hardcoded (FR-4.4, FR-5.1) and every
    configuration change must be traceable to the version that was in force when a
    decision was made (Section 7, NFR Auditability: "ทุก Configuration ... ต้องมี
    Versioning และ Effective Date"). Rows are therefore immutable: changing a policy
    publishes a new version rather than editing the previous one.
    """

    __tablename__ = "policy_sets"

    version: Mapped[int] = mapped_column(Integer, unique=True, index=True, nullable=False)
    effective_from: Mapped[date] = mapped_column(Date, index=True, nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # FR-4.1: ordered rule list combining CVSS + EPSS + CISA KEV. First match wins.
    # Shape is validated by app.schemas.policy.SeverityRule on write.
    severity_rules: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    # FR-5.1: remediation days per severity tier; null means best-effort (no due date).
    sla_days: Mapped[dict[str, int | None]] = mapped_column(JSON, nullable=False)

    # FR-4.2: dependency scope handling for `development`-only dependencies.
    downgrade_dev_scope_findings: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    auto_ticket_dev_scope_findings: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
