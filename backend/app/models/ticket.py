import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.db_types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class Ticket(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Requirement.md FR-7: ITSM/Ticketing cross-reference (Jira/SDP/ServiceNow).

    `connector_id` ties a Ticket back to the `IntegrationConnector` configuration that
    created it (FR-7.4 cross-reference: Finding ID <-> external ticket <-> which
    connector). It is nullable because a connector can be edited or removed after the
    fact without breaking the historical record of tickets it already created.
    """

    __tablename__ = "tickets"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    connector_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("integration_connectors.id", ondelete="SET NULL"), nullable=True
    )
    external_system: Mapped[str] = mapped_column(String(64), nullable=False)  # jira/sdp/servicenow
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="open")
    # FR-7.7: retry/error visibility for a failed create/update/close call.
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
