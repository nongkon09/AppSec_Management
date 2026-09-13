import uuid
from datetime import datetime

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.db_types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ScanResult(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Requirement.md Section 8 SCAN_RESULT entity (FR-2 ingestion history,
    FR-6.5 pentest upload)."""

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
    validity_expiry_date: Mapped[Date | None] = mapped_column(Date, nullable=True)
