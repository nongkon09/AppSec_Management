"""Risk Exception register with Maker-Checker approval (docs/risk-exception-design.md 3.4-3.5).

Replaces the single-approver Waiver. An exception covers issues, not rows: each item is an
(Application, issue key) pair, so a build that re-surfaces the same vulnerability is
covered without a new request.
"""

import uuid
from datetime import date, datetime
from enum import StrEnum
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.db_types import GUID
from app.models.finding import ISSUE_KEY_MAX_LENGTH, SeverityTier
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from app.models.security_control import exception_controls
from app.models.user import ApprovalLevel

if TYPE_CHECKING:
    from app.models.inventory import Application
    from app.models.security_control import SecurityControl


class ExceptionType(StrEnum):
    RISK_ACCEPTANCE = "risk_acceptance"
    FALSE_POSITIVE = "false_positive"
    NOT_AFFECTED = "not_affected"


class ExceptionStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CLOSED = "closed"


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class VexJustification(StrEnum):
    """CycloneDX / OpenVEX justification vocabulary."""

    CODE_NOT_PRESENT = "code_not_present"
    CODE_NOT_REACHABLE = "code_not_reachable"
    REQUIRES_CONFIGURATION = "requires_configuration"
    REQUIRES_DEPENDENCY = "requires_dependency"
    REQUIRES_ENVIRONMENT = "requires_environment"
    PROTECTED_BY_COMPILER = "protected_by_compiler"
    PROTECTED_AT_RUNTIME = "protected_at_runtime"
    PROTECTED_AT_PERIMETER = "protected_at_perimeter"
    PROTECTED_BY_MITIGATING_CONTROL = "protected_by_mitigating_control"


class RiskException(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "risk_exceptions"

    # Human reference DevOps quotes before a manual bypass, e.g. EXC-2026-0042.
    reference: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    exception_type: Mapped[ExceptionType] = mapped_column(
        Enum(ExceptionType, name="exception_type"), nullable=False
    )
    status: Mapped[ExceptionStatus] = mapped_column(
        Enum(ExceptionStatus, name="exception_status"),
        nullable=False,
        default=ExceptionStatus.PENDING,
        index=True,
    )

    requested_by: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    compensating_measures: Mapped[str | None] = mapped_column(Text, nullable=True)
    vex_justification: Mapped[VexJustification | None] = mapped_column(
        Enum(VexJustification, name="vex_justification"), nullable=True
    )

    # Worst policy tier among the covered issues when the request was made.
    original_severity_tier: Mapped[SeverityTier] = mapped_column(
        Enum(SeverityTier, name="severity_tier"), nullable=False
    )
    kev_involved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    residual_severity_tier: Mapped[SeverityTier | None] = mapped_column(
        Enum(SeverityTier, name="severity_tier"), nullable=True
    )
    # Risk acceptance: valid through this date. False positive / not affected: review date.
    expires_on: Mapped[date] = mapped_column(Date, nullable=False)

    # Frozen at submission so a later change to the matrix cannot move the goalposts.
    required_approvals: Mapped[int] = mapped_column(Integer, nullable=False)
    required_min_level: Mapped[ApprovalLevel] = mapped_column(
        Enum(ApprovalLevel, name="approval_level"), nullable=False
    )
    required_top_level: Mapped[ApprovalLevel] = mapped_column(
        Enum(ApprovalLevel, name="approval_level"), nullable=False
    )

    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ended_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Migrated from the single-approver Waiver: never went through four-eye review.
    is_legacy: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # A cited control passed its review date after approval.
    needs_review: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    items: Mapped[list["ExceptionItem"]] = relationship(
        back_populates="exception", cascade="all, delete-orphan"
    )
    approvals: Mapped[list["ExceptionApproval"]] = relationship(
        back_populates="exception",
        cascade="all, delete-orphan",
        order_by="ExceptionApproval.decided_at",
    )
    bypasses: Mapped[list["ExceptionBypass"]] = relationship(
        back_populates="exception",
        cascade="all, delete-orphan",
        order_by="ExceptionBypass.bypassed_at",
    )
    controls: Mapped[list["SecurityControl"]] = relationship(secondary=exception_controls)


class ExceptionItem(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "exception_items"
    __table_args__ = (
        UniqueConstraint(
            "exception_id", "application_id", "issue_key", name="uq_exception_item_issue"
        ),
    )

    exception_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("risk_exceptions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    application_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False, index=True
    )
    issue_key: Mapped[str] = mapped_column(String(ISSUE_KEY_MAX_LENGTH), nullable=False, index=True)
    # Snapshot for display: the row the request was raised from, and a readable label.
    origin_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True
    )
    label: Mapped[str] = mapped_column(String(1024), nullable=False)

    exception: Mapped[RiskException] = relationship(back_populates="items")
    application: Mapped["Application"] = relationship()


class ExceptionApproval(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "exception_approvals"
    __table_args__ = (
        UniqueConstraint("exception_id", "approver", name="uq_exception_approval_approver"),
    )

    exception_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("risk_exceptions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    approver: Mapped[str] = mapped_column(String(255), nullable=False)
    approver_level: Mapped[ApprovalLevel] = mapped_column(
        Enum(ApprovalLevel, name="approval_level"), nullable=False
    )
    decision: Mapped[ApprovalDecision] = mapped_column(
        Enum(ApprovalDecision, name="approval_decision"), nullable=False
    )
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    exception: Mapped[RiskException] = relationship(back_populates="approvals")


class ExceptionBypass(UUIDPrimaryKeyMixin, Base):
    """DevOps' record that they let a blocked build/deploy through on this exception."""

    __tablename__ = "exception_bypasses"

    exception_id: Mapped[uuid.UUID] = mapped_column(
        GUID(), ForeignKey("risk_exceptions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool: Mapped[str] = mapped_column(String(64), nullable=False)
    reference_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    recorded_by: Mapped[str] = mapped_column(String(255), nullable=False)
    bypassed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    exception: Mapped[RiskException] = relationship(back_populates="bypasses")
