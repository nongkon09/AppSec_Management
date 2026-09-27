import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.db_types import GUID
from app.models.inventory import Application, AppVersion, Environment
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class DeploymentSource(StrEnum):
    PIPELINE = "pipeline"
    MANUAL = "manual"


class Deployment(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Which version ran in which environment, and when (docs/risk-exception-design.md 3.3).

    Rows are never edited after the fact except to close them: a new deployment to the
    same Application and environment sets `ended_at` on the previous one.
    """

    __tablename__ = "deployments"

    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    app_version_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("app_versions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    environment: Mapped[Environment] = mapped_column(
        Enum(Environment, name="deployment_environment"), nullable=False
    )
    deployed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    image_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reference_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    source: Mapped[DeploymentSource] = mapped_column(
        Enum(DeploymentSource, name="deployment_source"), nullable=False
    )
    recorded_by: Mapped[str] = mapped_column(String(255), nullable=False)

    application: Mapped[Application] = relationship()
    app_version: Mapped[AppVersion] = relationship()
