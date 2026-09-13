from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.mixins import UUIDPrimaryKeyMixin


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """Requirement.md FR-11: Audit Trail & Traceability (immutable log of critical actions)."""

    __tablename__ = "audit_logs"

    action: Mapped[str] = mapped_column(String(255), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)  # user or system identifier
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    before_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    after_value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Set client-side so entries written in the same second stay distinguishable and
    # keep their real order: SQLite's CURRENT_TIMESTAMP only resolves to one second,
    # which would make the FR-11.2 export order arbitrary. server_default remains as a
    # fallback for any row inserted outside the ORM.
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, server_default=func.now()
    )
