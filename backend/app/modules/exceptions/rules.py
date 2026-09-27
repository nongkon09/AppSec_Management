"""Pure decision rules for risk exceptions (docs/risk-exception-design.md 3.4-3.5).

Kept free of database access so every rule can be unit-tested exhaustively and read by
an auditor in one place.
"""

from dataclasses import dataclass
from datetime import date

from app.models.finding import SeverityTier
from app.models.risk_exception import ExceptionType
from app.models.user import APPROVAL_LEVEL_RANK, ApprovalLevel, Role

SEVERITY_RANK = {
    SeverityTier.CRITICAL: 0,
    SeverityTier.HIGH: 1,
    SeverityTier.MEDIUM: 2,
    SeverityTier.LOW: 3,
}
MAX_RESIDUAL_DROP = 2
# False positive / not affected decisions must be re-confirmed at least yearly.
MAX_REVIEW_DAYS = 365

MAKER_ROLES = (Role.DEV_TEAM, Role.APPSEC)
CHECKER_ROLES = (Role.APPSEC, Role.MANAGEMENT)


@dataclass(frozen=True)
class ApprovalRequirement:
    count: int
    # Every approver must hold at least this level ...
    min_level: ApprovalLevel
    # ... and at least one of them must hold this level.
    top_level: ApprovalLevel


def worst(tiers: list[SeverityTier]) -> SeverityTier:
    return min(tiers, key=lambda tier: SEVERITY_RANK[tier])


def required_approvals(
    exception_type: ExceptionType,
    original: SeverityTier,
    kev: bool,
    application_count: int,
) -> ApprovalRequirement:
    if application_count > 1:
        return ApprovalRequirement(2, ApprovalLevel.L2, ApprovalLevel.L3)
    if exception_type == ExceptionType.RISK_ACCEPTANCE:
        if original == SeverityTier.CRITICAL or kev:
            return ApprovalRequirement(2, ApprovalLevel.L2, ApprovalLevel.L3)
        if original == SeverityTier.HIGH:
            return ApprovalRequirement(1, ApprovalLevel.L2, ApprovalLevel.L2)
        return ApprovalRequirement(1, ApprovalLevel.L1, ApprovalLevel.L1)
    if original == SeverityTier.CRITICAL or kev:
        return ApprovalRequirement(1, ApprovalLevel.L2, ApprovalLevel.L2)
    return ApprovalRequirement(1, ApprovalLevel.L1, ApprovalLevel.L1)


def residual_errors(
    original: SeverityTier,
    residual: SeverityTier | None,
    kev: bool,
    control_count: int,
) -> list[str]:
    """Bounds on how far compensating controls may lower a risk-acceptance tier."""
    if residual is None:
        return []
    errors: list[str] = []
    drop = SEVERITY_RANK[residual] - SEVERITY_RANK[original]
    if drop < 0:
        errors.append("Residual severity cannot be higher than the original severity.")
    if drop > MAX_RESIDUAL_DROP:
        errors.append(f"Residual severity can be at most {MAX_RESIDUAL_DROP} tiers lower.")
    if kev and SEVERITY_RANK[residual] > SEVERITY_RANK[SeverityTier.HIGH]:
        errors.append("A CISA KEV vulnerability cannot be lowered below High.")
    if drop > 0 and control_count == 0:
        errors.append("Lowering the severity requires at least one compensating control.")
    return errors


def level_at_least(level: ApprovalLevel, required: ApprovalLevel) -> bool:
    return APPROVAL_LEVEL_RANK[level] >= APPROVAL_LEVEL_RANK[required]


@dataclass(frozen=True)
class CheckerContext:
    username: str
    role: Role
    level: ApprovalLevel


def checker_refusal(
    checker: CheckerContext,
    *,
    requested_by: str,
    already_decided_by: list[str],
    approved_levels: list[ApprovalLevel],
    requirement: ApprovalRequirement,
    approving: bool,
) -> str | None:
    """Why this user may not decide on the request, or None if they may.

    Separation of duties: the maker never checks their own request, one person counts
    once, admins configure the system but do not judge risk, and the last open approval
    slot is reserved for the required top level so a second lower-level approval cannot
    use it up.
    """
    if checker.role == Role.ADMIN:
        return "Administrators cannot approve or reject risk decisions."
    if checker.role not in CHECKER_ROLES:
        return "Your role cannot approve or reject risk decisions."
    if checker.username == requested_by:
        return "You cannot decide on a request you submitted."
    if checker.username in already_decided_by:
        return "You have already decided on this request."
    if not level_at_least(checker.level, requirement.min_level):
        return f"This request needs approvers at level {requirement.min_level.value} or above."
    if approving:
        has_top = any(level_at_least(level, requirement.top_level) for level in approved_levels)
        remaining = requirement.count - len(approved_levels)
        if (
            not has_top
            and remaining == 1
            and not level_at_least(checker.level, requirement.top_level)
        ):
            return f"The remaining approval must come from level {requirement.top_level.value}."
    return None


def is_fully_approved(
    approved_levels: list[ApprovalLevel], requirement: ApprovalRequirement
) -> bool:
    return len(approved_levels) >= requirement.count and any(
        level_at_least(level, requirement.top_level) for level in approved_levels
    )


def expiry_errors(
    exception_type: ExceptionType,
    expires_on: date,
    today: date,
    sla_due: date | None,
) -> list[str]:
    if expires_on < today:
        return ["The expiry date cannot be in the past."]
    if exception_type == ExceptionType.RISK_ACCEPTANCE:
        if sla_due is not None and expires_on > sla_due:
            return [
                f"A risk acceptance must expire by the SLA due date ({sla_due.isoformat()}). "
                "Propose a justified residual severity to get a longer window."
            ]
        return []
    if (expires_on - today).days > MAX_REVIEW_DAYS:
        return [f"The review date must be within {MAX_REVIEW_DAYS} days."]
    return []
