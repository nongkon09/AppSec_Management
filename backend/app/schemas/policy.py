import uuid
from datetime import date

from pydantic import BaseModel, Field, model_validator

from app.models.finding import SeverityTier


class SeverityRuleCondition(BaseModel):
    """Predicate over a Finding's CVSS / EPSS / KEV attributes (Requirement.md FR-4.1).

    Every field that is set must hold for the rule to match; an empty condition
    matches everything and therefore acts as the catch-all fallback. Per FR-4.5 no
    Application business attribute (Criticality / Internet-facing / Data Classification)
    may appear here — Severity is derived from CVSS + EPSS + KEV only.
    """

    kev: bool | None = None
    cvss_min: float | None = Field(default=None, ge=0.0, le=10.0)
    cvss_max: float | None = Field(default=None, ge=0.0, le=10.0)
    epss_min: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_max: float | None = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check_bounds(self) -> "SeverityRuleCondition":
        if (
            self.cvss_min is not None
            and self.cvss_max is not None
            and self.cvss_min > self.cvss_max
        ):
            raise ValueError("cvss_min must not be greater than cvss_max")
        if (
            self.epss_min is not None
            and self.epss_max is not None
            and self.epss_min > self.epss_max
        ):
            raise ValueError("epss_min must not be greater than epss_max")
        return self


class SeverityRule(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    when: SeverityRuleCondition = Field(default_factory=SeverityRuleCondition)
    tier: SeverityTier


class SlaDays(BaseModel):
    """Remediation days per tier (Requirement.md FR-5.1 / Section 12 defaults).

    `None` means best-effort with no due date — the Section 12 default for Low.
    """

    critical: int | None = Field(default=7, ge=0, le=3650)
    high: int | None = Field(default=30, ge=0, le=3650)
    medium: int | None = Field(default=90, ge=0, le=3650)
    low: int | None = Field(default=None, ge=0, le=3650)


class PolicySetCreate(BaseModel):
    effective_from: date
    severity_rules: list[SeverityRule] = Field(min_length=1)
    sla_days: SlaDays = Field(default_factory=SlaDays)
    downgrade_dev_scope_findings: bool = True
    auto_ticket_dev_scope_findings: bool = False
    notes: str | None = None

    @model_validator(mode="after")
    def _require_catch_all(self) -> "PolicySetCreate":
        """A rule set that can leave a Finding untiered is a misconfiguration, so the
        last rule must be an unconditional catch-all."""
        last = self.severity_rules[-1]
        if last.when.model_dump(exclude_none=True):
            raise ValueError(
                "the last severity rule must be an unconditional catch-all "
                "(empty 'when') so every Finding resolves to a tier"
            )
        return self


class PolicySetOut(BaseModel):
    id: uuid.UUID
    version: int
    effective_from: date
    created_by: str
    notes: str | None
    severity_rules: list[SeverityRule]
    sla_days: SlaDays
    downgrade_dev_scope_findings: bool
    auto_ticket_dev_scope_findings: bool

    model_config = {"from_attributes": True}


class SeverityEvaluationRequest(BaseModel):
    """Dry-run input for the rule engine, so AppSec can see what a policy would do
    before publishing it (FR-4.1 Configurable Rule Engine)."""

    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    kev_flag: bool = False
    scope: str = "production"
    policy_version: int | None = None


class SeverityEvaluationResult(BaseModel):
    severity_tier: SeverityTier
    matched_rule: str
    downgraded_for_dev_scope: bool
    policy_version: int
    sla_days: int | None
    due_date: date | None
