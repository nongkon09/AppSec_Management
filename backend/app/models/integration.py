from enum import StrEnum

from sqlalchemy import JSON, Boolean, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ConnectorType(StrEnum):
    """Requirement.md FR-7.1: connector types this platform ships out of the box.
    New destinations plug in without touching Core (FR-7 note) by adding one more
    `TicketConnector` implementation and a new value here."""

    JIRA = "jira"
    SERVICE_DESK_PLUS = "service_desk_plus"
    GENERIC_WEBHOOK = "generic_webhook"


class IntegrationConnector(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Requirement.md FR-7: one configured ITSM destination (Admin-managed, Section 4:
    "System Admin ... Integration Connector Configuration").

    `routing_severities` is FR-7.2's Routing Policy expressed per connector rather than
    as a separate table: a Finding at a given Severity Tier is routed to every enabled
    connector whose list includes that tier, which is what lets Critical fire into both
    an ITSM system and Jira at once (FR-7.2's default policy) with no join table.
    """

    __tablename__ = "integration_connectors"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    connector_type: Mapped[ConnectorType] = mapped_column(
        Enum(ConnectorType, name="connector_type"), nullable=False
    )
    base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    # Never returned in full over the API (schemas.integration masks it) — this stores
    # what CI/CD's own secrets belong in a vault for (NFR Security), but FR-7's Connector
    # Configuration is explicitly something Admin manages *through this platform*, unlike
    # the read-only Dependency-Track key FR-2.7.4 keeps in an env var.
    auth_token: Mapped[str] = mapped_column(String(1024), nullable=False)
    # Connector-specific settings: Jira {"project_key", "issue_type"}, SDP
    # {"category", "subcategory"}, generic webhook {"headers": {...}}.
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # FR-4.4-style tier strings ("critical"/"high"/"medium"/"low"); empty = manual-only,
    # never auto-routed (FR-7.8's manual path still works via this connector).
    routing_severities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
