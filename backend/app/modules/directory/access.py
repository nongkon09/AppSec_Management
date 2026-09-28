"""Turning Entra ID app roles and group membership into one platform role.

Pure functions, no database, so the precedence rules can be tested exhaustively and read
by an auditor in one place (docs/entra-id.md, "How a role is decided").
"""

from dataclasses import dataclass

from app.models.directory import MappingKind
from app.models.user import APPROVAL_LEVEL_RANK, ApprovalLevel, Role

# An account holds exactly one role, so when several mappings match, the broadest wins.
# The CI/CD service account is local-only and never comes from the directory.
ROLE_PRECEDENCE: tuple[Role, ...] = (
    Role.ADMIN,
    Role.APPSEC,
    Role.MANAGEMENT,
    Role.AUDIT,
    Role.LEGAL,
    Role.DEV_TEAM,
)
MAPPABLE_ROLES = frozenset(ROLE_PRECEDENCE)
# Only these roles act as Checkers (docs/risk-exception-design.md 3.5).
CHECKER_ROLES = frozenset({Role.APPSEC, Role.MANAGEMENT})


@dataclass(frozen=True)
class Rule:
    kind: MappingKind
    value: str
    role: Role
    approval_level: ApprovalLevel
    owner_team: str | None


@dataclass(frozen=True)
class Access:
    role: Role
    approval_level: ApprovalLevel
    owner_team: str | None
    # The rules that granted it, for the user page and the audit trail.
    matched: tuple[str, ...]


def rule_errors(role: Role, approval_level: ApprovalLevel, owner_team: str | None) -> list[str]:
    errors = []
    if role not in MAPPABLE_ROLES:
        errors.append("The CI/CD service account role cannot come from Entra ID.")
    if role == Role.DEV_TEAM and not (owner_team or "").strip():
        errors.append("A Development Team mapping needs an owner team.")
    if approval_level != ApprovalLevel.NONE and role not in CHECKER_ROLES:
        errors.append("Only AppSec and Management mappings can carry an approval level.")
    return errors


def _matches(rule: Rule, app_roles: set[str], group_ids: set[str]) -> bool:
    if rule.kind == MappingKind.APP_ROLE:
        return rule.value.casefold() in app_roles
    return rule.value.casefold() in group_ids


def resolve(rules: list[Rule], app_roles: list[str], group_ids: list[str]) -> Access | None:
    """The access an account gets, or None when nothing matches (it may not sign in).

    - Role: the highest in ROLE_PRECEDENCE among matching rules.
    - Approval level: the highest among matching rules *for that role*.
    - Owner team: from the matching rules for that role; if several teams match, the
      first alphabetically, so the result never depends on row order.
    """
    roles = {value.casefold() for value in app_roles}
    groups = {value.casefold() for value in group_ids}
    matching = [rule for rule in rules if _matches(rule, roles, groups)]
    matching = [rule for rule in matching if rule.role in MAPPABLE_ROLES]
    if not matching:
        return None
    role = min((rule.role for rule in matching), key=ROLE_PRECEDENCE.index)
    winners = [rule for rule in matching if rule.role == role]
    level = max(
        (rule.approval_level for rule in winners), key=lambda level: APPROVAL_LEVEL_RANK[level]
    )
    teams = sorted({rule.owner_team for rule in winners if rule.owner_team})
    return Access(
        role=role,
        approval_level=level if role in CHECKER_ROLES else ApprovalLevel.NONE,
        owner_team=teams[0] if role == Role.DEV_TEAM and teams else None,
        matched=tuple(sorted(f"{rule.kind.value}:{rule.value}" for rule in winners)),
    )
