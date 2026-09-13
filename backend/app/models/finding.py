import uuid
from datetime import date, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.db_types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.component import Component
    from app.models.inventory import AppVersion


class SeverityTier(StrEnum):
    """Requirement.md FR-4.4: Severity Tiers, thresholds are Policy-configurable (FR-5.1)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Ordered most→least severe; used for the FR-4.2 dev-scope downgrade and for sorting.
SEVERITY_ORDER: tuple[SeverityTier, ...] = (
    SeverityTier.CRITICAL,
    SeverityTier.HIGH,
    SeverityTier.MEDIUM,
    SeverityTier.LOW,
)


class FindingSource(StrEnum):
    """Scan types tracked by the platform (Requirement.md Section 2.1)."""

    SBOM = "sbom"
    SAST = "sast"
    PENTEST = "pentest"


class FindingStatus(StrEnum):
    """Backlog lifecycle state (Requirement.md FR-5.4, FR-7.5, FR-8)."""

    OPEN = "open"
    FIXED = "fixed"  # FR-7.5: verified gone by a later SBOM re-scan
    RISK_ACCEPTED = "risk_accepted"  # FR-7.6: covered by an approved Waiver
    SUPPRESSED = "suppressed"  # FR-8: VEX not_affected


class VexStatus(StrEnum):
    """Requirement.md FR-8.1."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Requirement.md Section 8 FINDING entity (FR-3.3, FR-4).

    Anchored on `app_version_id` rather than on Component, because Findings from
    SAST and Pentest have no SBOM Component but must still land in the same backlog
    and SLA calculation (FR-6.5.6).
    """

    __tablename__ = "findings"
    __table_args__ = (
        # FR-3.2 delta matching re-runs continuously against the same inventory;
        # one CVE per component per version must not accumulate duplicates.
        UniqueConstraint(
            "app_version_id", "component_id", "cve_id", name="uq_finding_version_component_cve"
        ),
    )

    app_version_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("app_versions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Set for SBOM/SCA findings only; null for SAST and Pentest findings.
    component_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("components.id", ondelete="CASCADE"), nullable=True, index=True
    )
    # FR-6.5.6: links a Pentest finding back to the engagement that produced it.
    pentest_project_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("pentest_projects.id", ondelete="SET NULL"), nullable=True
    )

    source: Mapped[FindingSource] = mapped_column(
        Enum(FindingSource, name="finding_source"), nullable=False, default=FindingSource.SBOM
    )
    # Null for Pentest/SAST findings that are not tied to a public CVE.
    cve_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # Human-readable vulnerability name — mandatory input for Pentest findings (FR-6.5.5).
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev_flag: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    severity_tier: Mapped[SeverityTier] = mapped_column(
        Enum(SeverityTier, name="severity_tier"), nullable=False, default=SeverityTier.MEDIUM
    )
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus, name="finding_status"),
        nullable=False,
        default=FindingStatus.OPEN,
        index=True,
    )
    vex_status: Mapped[VexStatus] = mapped_column(
        Enum(VexStatus, name="vex_status"), nullable=False, default=VexStatus.AFFECTED
    )
    # FR-8.1: VEX justification code, e.g. component_not_present, compensating_control.
    vex_justification: Mapped[str | None] = mapped_column(String(128), nullable=True)

    due_date: Mapped[date | None] = mapped_column(Date, nullable=True, index=True)
    # FR-5.2 / NFR Auditability: which PolicySet version produced severity_tier + due_date.
    policy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # FR-7.3: attached to the outbound ITSM ticket alongside the current version.
    fixed_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reference_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # FR-10.2: Dev Team fills in / updates their remediation plan.
    remediation_plan: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation_plan_updated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remediation_plan_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    first_detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    component: Mapped["Component | None"] = relationship(back_populates="findings")
    app_version: Mapped["AppVersion"] = relationship(back_populates="findings")

    def is_overdue(self, today: date) -> bool:
        """FR-5.4 Overdue vs Within SLA. Only open Findings can breach an SLA."""
        return (
            self.status == FindingStatus.OPEN
            and self.due_date is not None
            and self.due_date < today
        )
