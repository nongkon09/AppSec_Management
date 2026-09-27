from datetime import date
from enum import StrEnum

from sqlalchemy import Boolean, Column, Date, Enum, ForeignKey, String, Table, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.db_types import GUID
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin


class ControlCategory(StrEnum):
    NETWORK = "network"
    APPLICATION = "application"
    MONITORING = "monitoring"
    PROCESS = "process"


class ControlEffectiveness(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SecurityControl(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An organisational control that can justify a lower residual severity
    (docs/risk-exception-design.md 3.6). A control past its review date cannot be cited
    by new exceptions and flags existing ones for review."""

    __tablename__ = "security_controls"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[ControlCategory] = mapped_column(
        Enum(ControlCategory, name="control_category"), nullable=False
    )
    owner: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    effectiveness: Mapped[ControlEffectiveness] = mapped_column(
        Enum(ControlEffectiveness, name="control_effectiveness"), nullable=False
    )
    review_due_on: Mapped[date] = mapped_column(Date, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    def is_usable(self, today: date) -> bool:
        return self.is_active and self.review_due_on >= today


exception_controls = Table(
    "exception_controls",
    Base.metadata,
    Column(
        "exception_id",
        GUID(),
        ForeignKey("risk_exceptions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "control_id",
        GUID(),
        ForeignKey("security_controls.id", ondelete="RESTRICT"),
        primary_key=True,
    ),
)
