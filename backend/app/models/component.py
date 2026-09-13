import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.db_types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.finding import Finding


class Component(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Requirement.md Section 8 COMPONENT entity (populated from SBOM ingestion, FR-2)."""

    __tablename__ = "components"

    app_version_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("app_versions.id", ondelete="CASCADE"), nullable=False
    )
    component_name: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    license: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # FR-4.2: production vs development dependency scope
    scope: Mapped[str] = mapped_column(String(32), nullable=False, default="production")
    purl: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="component", cascade="all, delete-orphan"
    )
