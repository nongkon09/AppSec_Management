"""Severity & SLA policy engine (Requirement.md FR-4, FR-5, Section 12).

The tiering thresholds and SLA day counts live entirely in data (PolicySet rows), so
AppSec changes them through the Policy Configuration screen without a code change
(FR-4.4, FR-5.1). Each published PolicySet is immutable and effective-dated, and every
Finding records the version that tiered it, so a past decision can always be replayed
against the policy that was in force at the time (FR-5.2, NFR Auditability).
"""

from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import record_audit
from app.models.finding import SEVERITY_ORDER, SeverityTier
from app.models.policy import PolicySet
from app.schemas.policy import PolicySetCreate, SeverityRule, SeverityRuleCondition, SlaDays

SYSTEM_ACTOR = "system"
DEVELOPMENT_SCOPE = "development"

# Section 12 defaults. Presented as a proposal only — AppSec is expected to confirm or
# override them in the Policy Configuration screen (FR-5.1, Section 14).
DEFAULT_SEVERITY_RULES: list[SeverityRule] = [
    # FR-4.1: "KEV = True → Critical (ไม่ว่า CVSS เท่าไหร่)"
    SeverityRule(
        name="cisa-kev-actively-exploited",
        when=SeverityRuleCondition(kev=True),
        tier=SeverityTier.CRITICAL,
    ),
    SeverityRule(
        name="high-epss-and-critical-cvss",
        when=SeverityRuleCondition(epss_min=0.3, cvss_min=9.0),
        tier=SeverityTier.CRITICAL,
    ),
    SeverityRule(
        name="high-epss-and-high-cvss",
        when=SeverityRuleCondition(epss_min=0.3, cvss_min=7.0),
        tier=SeverityTier.HIGH,
    ),
    SeverityRule(
        name="cvss-band-high",
        when=SeverityRuleCondition(cvss_min=7.0),
        tier=SeverityTier.HIGH,
    ),
    SeverityRule(
        name="cvss-band-medium",
        when=SeverityRuleCondition(cvss_min=4.0),
        tier=SeverityTier.MEDIUM,
    ),
    # Unconditional catch-all: every Finding must resolve to a tier (see
    # PolicySetCreate._require_catch_all).
    SeverityRule(name="cvss-band-low", when=SeverityRuleCondition(), tier=SeverityTier.LOW),
]

DEFAULT_SLA_DAYS = SlaDays()


class SeverityDecision:
    """Outcome of running one Finding through the rule engine."""

    def __init__(
        self,
        tier: SeverityTier,
        matched_rule: str,
        *,
        downgraded_for_dev_scope: bool = False,
    ) -> None:
        self.tier = tier
        self.matched_rule = matched_rule
        self.downgraded_for_dev_scope = downgraded_for_dev_scope


def _condition_matches(
    condition: dict[str, float | bool | None],
    *,
    cvss: float | None,
    epss: float | None,
    kev_flag: bool,
) -> bool:
    """All conditions that are set must hold. An unset metric never satisfies a
    threshold on that metric, so a Finding with no CVSS score falls through to the
    catch-all rule rather than silently matching a band."""
    kev = condition.get("kev")
    if kev is not None and bool(kev) != kev_flag:
        return False

    cvss_min, cvss_max = condition.get("cvss_min"), condition.get("cvss_max")
    if cvss_min is not None and (cvss is None or cvss < float(cvss_min)):
        return False
    if cvss_max is not None and (cvss is None or cvss > float(cvss_max)):
        return False

    epss_min, epss_max = condition.get("epss_min"), condition.get("epss_max")
    if epss_min is not None and (epss is None or epss < float(epss_min)):
        return False
    if epss_max is not None and (epss is None or epss > float(epss_max)):
        return False

    return True


def _downgrade_one_tier(tier: SeverityTier) -> SeverityTier:
    index = SEVERITY_ORDER.index(tier)
    return SEVERITY_ORDER[min(index + 1, len(SEVERITY_ORDER) - 1)]


def evaluate_severity(
    policy: PolicySet,
    *,
    cvss: float | None,
    epss: float | None,
    kev_flag: bool,
    scope: str = "production",
) -> SeverityDecision:
    """FR-4.1 tiering (CVSS + EPSS + KEV, first matching rule wins) plus the FR-4.2
    dependency-scope adjustment. Per FR-4.5, Application business context deliberately
    plays no part here."""
    for rule in policy.severity_rules:
        condition = rule.get("when") or {}
        if _condition_matches(condition, cvss=cvss, epss=epss, kev_flag=kev_flag):
            tier = SeverityTier(rule["tier"])
            matched = str(rule.get("name", "unnamed"))
            break
    else:
        # Publishing enforces a catch-all rule, so this only guards hand-edited rows.
        tier, matched = SeverityTier.LOW, "fallback-no-rule-matched"

    if scope == DEVELOPMENT_SCOPE and policy.downgrade_dev_scope_findings:
        downgraded = _downgrade_one_tier(tier)
        if downgraded != tier:
            return SeverityDecision(downgraded, matched, downgraded_for_dev_scope=True)

    return SeverityDecision(tier, matched)


def sla_days_for_tier(policy: PolicySet, tier: SeverityTier) -> int | None:
    """FR-5.1: remediation window per tier. None = best-effort, no due date."""
    value = policy.sla_days.get(tier.value)
    return int(value) if value is not None else None


def compute_due_date(
    policy: PolicySet, tier: SeverityTier, detected_on: date | None = None
) -> date | None:
    """FR-5.2: Due Date from the SLA policy effective when the vulnerability was found."""
    days = sla_days_for_tier(policy, tier)
    if days is None:
        return None
    return (detected_on or datetime.now(UTC).date()) + timedelta(days=days)


def ensure_default_policy(db: Session) -> PolicySet:
    """Publish the Section 12 default policy as version 1 if none exists yet, so a fresh
    deployment can tier Findings before AppSec has configured anything."""
    existing = db.execute(
        select(PolicySet).order_by(PolicySet.version.desc()).limit(1)
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    policy = PolicySet(
        version=1,
        effective_from=date(1970, 1, 1),
        created_by=SYSTEM_ACTOR,
        notes="Default Severity/SLA policy seeded from Requirement.md Section 12.",
        severity_rules=[rule.model_dump(exclude_none=True) for rule in DEFAULT_SEVERITY_RULES],
        sla_days=DEFAULT_SLA_DAYS.model_dump(),
    )
    db.add(policy)
    # Flush first: the primary key is assigned by the column default at flush time, so
    # reading policy.id before this would record the audit entry against "None".
    db.flush()
    record_audit(
        db,
        actor=SYSTEM_ACTOR,
        action="policy.seed_default",
        entity_type="policy_set",
        entity_id=policy.id,
        after={"version": 1},
    )
    db.commit()
    db.refresh(policy)
    return policy


def get_effective_policy(db: Session, on: date | None = None) -> PolicySet:
    """The policy in force on `on` — the highest version whose effective_from has
    arrived (FR-5.2). Future-dated versions are ignored until their date."""
    as_of = on or datetime.now(UTC).date()
    policy = db.execute(
        select(PolicySet)
        .where(PolicySet.effective_from <= as_of)
        .order_by(PolicySet.effective_from.desc(), PolicySet.version.desc())
        .limit(1)
    ).scalar_one_or_none()
    if policy is None:
        return ensure_default_policy(db)
    return policy


def get_policy_by_version(db: Session, version: int) -> PolicySet | None:
    return db.execute(select(PolicySet).where(PolicySet.version == version)).scalar_one_or_none()


def list_policies(db: Session) -> list[PolicySet]:
    return list(db.execute(select(PolicySet).order_by(PolicySet.version.desc())).scalars().all())


def create_policy_set(db: Session, payload: PolicySetCreate, actor: str) -> PolicySet:
    """Publish a new immutable policy version (FR-5.1 + NFR Auditability)."""
    ensure_default_policy(db)
    current_max = db.execute(
        select(PolicySet.version).order_by(PolicySet.version.desc()).limit(1)
    ).scalar_one()
    previous = get_effective_policy(db)

    policy = PolicySet(
        version=current_max + 1,
        effective_from=payload.effective_from,
        created_by=actor,
        notes=payload.notes,
        severity_rules=[rule.model_dump(exclude_none=True) for rule in payload.severity_rules],
        sla_days=payload.sla_days.model_dump(),
        downgrade_dev_scope_findings=payload.downgrade_dev_scope_findings,
        auto_ticket_dev_scope_findings=payload.auto_ticket_dev_scope_findings,
    )
    db.add(policy)
    db.flush()  # assigns policy.id before it is referenced by the audit entry
    record_audit(
        db,
        actor=actor,
        action="policy.publish_version",
        entity_type="policy_set",
        entity_id=policy.id,
        before={
            "version": previous.version,
            "sla_days": previous.sla_days,
            "severity_rules": previous.severity_rules,
        },
        after={
            "version": policy.version,
            "effective_from": policy.effective_from.isoformat(),
            "sla_days": policy.sla_days,
            "severity_rules": policy.severity_rules,
        },
    )
    db.commit()
    db.refresh(policy)
    return policy
