import uuid
from datetime import date
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import Date, Enum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.db_types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.finding import Finding


class WaiverStatus(StrEnum):
    """FR-6.2 lifecycle: PENDING -> ACTIVE (approved) or REJECTED; ACTIVE -> EXPIRED
    (auto, expiry_date reached) or REVOKED (early admin/AppSec revoke)."""

    PENDING = "pending"
    ACTIVE = "active"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Waiver(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Requirement.md FR-6.2 / FR-8: Exception/Waiver Workflow."""

    __tablename__ = "waivers"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    requested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expiry_date: Mapped[date] = mapped_column(Date, nullable=False)
    status: Mapped[WaiverStatus] = mapped_column(
        Enum(WaiverStatus, name="waiver_status"), nullable=False, default=WaiverStatus.PENDING
    )

    finding: Mapped["Finding"] = relationship()
