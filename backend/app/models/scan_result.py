import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.db_types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ScanResult(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Requirement.md Section 8 SCAN_RESULT entity (FR-2 ingestion history,
    FR-6.5 pentest upload), extended into a scan snapshot for audit evidence
    (docs/risk-exception-design.md 3.7). Rows are never edited after insert."""

    __tablename__ = "scan_results"

    app_version_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("app_versions.id", ondelete="CASCADE"), nullable=False
    )
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)  # sbom/sast/pentest
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    result_status: Mapped[str] = mapped_column(String(64), nullable=False, default="completed")
    is_manual_upload: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    uploaded_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    report_file_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    validity_expiry_date: Mapped[date | None] = mapped_column(Date, nullable=True)

    # Evidence linking this scan to what was built and deployed.
    source_tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pipeline_run: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # When the SCA platform received the SBOM this snapshot reflects.
    sca_bom_imported_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    sbom_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sbom_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)


class ScanFinding(UUIDPrimaryKeyMixin, Base):
    """Which Findings a scan reported, frozen at scan time (append-only)."""

    __tablename__ = "scan_findings"
    __table_args__ = (UniqueConstraint("scan_result_id", "finding_id", name="uq_scan_finding"),)

    scan_result_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Tier and status as they were when scanned, not as they are now.
    severity_tier: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
