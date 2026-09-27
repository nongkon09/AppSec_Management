import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.db_types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.finding import Finding


class AppType(StrEnum):
    """Requirement.md FR-1.1 / Section 2.1 In Scope application types."""

    IN_HOUSE = "in_house"
    COTS = "cots"
    MOBILE = "mobile"
    API = "api"


class Criticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Environment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEV = "dev"


class Application(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Requirement.md FR-1: Application Inventory Management."""

    __tablename__ = "applications"

    app_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    app_type: Mapped[AppType] = mapped_column(Enum(AppType, name="app_type"), nullable=False)
    owner_team: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    tech_lead_contact: Mapped[str | None] = mapped_column(String(255), nullable=True)
    business_unit: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality: Mapped[Criticality] = mapped_column(
        Enum(Criticality, name="criticality"), nullable=False, default=Criticality.MEDIUM
    )
    environment: Mapped[Environment] = mapped_column(
        Enum(Environment, name="environment"), nullable=False, default=Environment.PRODUCTION
    )
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    data_classification: Mapped[str | None] = mapped_column(String(255), nullable=True)

    repo_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    jira_project_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sdp_category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_email: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # FR-1.5: Auto-created Applications need explicit ownership confirmation by AppSec.
    ownership_confirmed: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    versions: Mapped[list["AppVersion"]] = relationship(
        back_populates="application", cascade="all, delete-orphan"
    )


class AppVersion(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Requirement.md FR-1.2 / Section 8 APP_VERSION entity."""

    __tablename__ = "app_versions"

    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    version_label: Mapped[str] = mapped_column(String(255), nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    environment: Mapped[Environment] = mapped_column(
        Enum(Environment, name="version_environment"),
        nullable=False,
        default=Environment.PRODUCTION,
    )
    is_current_production: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_ingested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # FR-2.4: flagged when no new SBOM ingested within configured threshold (default 90 days)
    is_stale: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # In use: has an open Deployment, or (for an Application with no deployment records
    # at all) is its most recently ingested version. Backlog and SLA figures count
    # Findings of active versions only.
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    application: Mapped[Application] = relationship(back_populates="versions")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="app_version", cascade="all, delete-orphan"
    )
