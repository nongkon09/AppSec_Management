"""Decision rules for risk exceptions (docs/risk-exception-design.md 3.4-3.5)."""

from datetime import date, timedelta

import pytest

from app.models.finding import SeverityTier
from app.models.risk_exception import ExceptionType
from app.models.user import ApprovalLevel, Role
from app.modules.exceptions import rules

RA = ExceptionType.RISK_ACCEPTANCE
FP = ExceptionType.FALSE_POSITIVE
L1, L2, L3, NONE = ApprovalLevel.L1, ApprovalLevel.L2, ApprovalLevel.L3, ApprovalLevel.NONE


@pytest.mark.parametrize(
    ("exception_type", "tier", "kev", "apps", "expected"),
    [
        (RA, SeverityTier.LOW, False, 1, (1, L1, L1)),
        (RA, SeverityTier.MEDIUM, False, 1, (1, L1, L1)),
        (RA, SeverityTier.HIGH, False, 1, (1, L2, L2)),
        (RA, SeverityTier.CRITICAL, False, 1, (2, L2, L3)),
        (RA, SeverityTier.MEDIUM, True, 1, (2, L2, L3)),  # KEV counts as Critical
        (FP, SeverityTier.HIGH, False, 1, (1, L1, L1)),
        (FP, SeverityTier.CRITICAL, False, 1, (1, L2, L2)),
        (FP, SeverityTier.LOW, True, 1, (1, L2, L2)),
        (FP, SeverityTier.LOW, False, 3, (2, L2, L3)),  # organisation-wide
        (RA, SeverityTier.LOW, False, 2, (2, L2, L3)),
    ],
)
def test_approval_matrix(exception_type, tier, kev, apps, expected):
    requirement = rules.required_approvals(exception_type, tier, kev, apps)
    assert (requirement.count, requirement.min_level, requirement.top_level) == expected


class TestResidualBounds:
    def test_no_residual_is_always_fine(self):
        assert rules.residual_errors(SeverityTier.CRITICAL, None, True, 0) == []

    def test_two_tier_drop_with_control_is_allowed(self):
        assert rules.residual_errors(SeverityTier.CRITICAL, SeverityTier.MEDIUM, False, 1) == []

    def test_three_tier_drop_is_refused(self):
        assert rules.residual_errors(SeverityTier.CRITICAL, SeverityTier.LOW, False, 1)

    def test_kev_cannot_go_below_high(self):
        errors = rules.residual_errors(SeverityTier.CRITICAL, SeverityTier.MEDIUM, True, 2)
        assert any("KEV" in e for e in errors)
        assert rules.residual_errors(SeverityTier.CRITICAL, SeverityTier.HIGH, True, 1) == []

    def test_lowering_needs_a_control(self):
        errors = rules.residual_errors(SeverityTier.HIGH, SeverityTier.MEDIUM, False, 0)
        assert any("control" in e for e in errors)

    def test_residual_cannot_raise_the_tier(self):
        assert rules.residual_errors(SeverityTier.MEDIUM, SeverityTier.HIGH, False, 0)


def _refusal(
    checker, *, requested_by="dev.alpha", decided=(), approved=(), req=(2, L2, L3), approving=True
):
    return rules.checker_refusal(
        rules.CheckerContext(*checker),
        requested_by=requested_by,
        already_decided_by=list(decided),
        approved_levels=list(approved),
        requirement=rules.ApprovalRequirement(*req),
        approving=approving,
    )


class TestSeparationOfDuties:
    def test_maker_cannot_approve_own_request(self):
        assert "submitted" in _refusal(("appsec.lead", Role.APPSEC, L3), requested_by="appsec.lead")

    def test_admin_cannot_decide_even_with_a_level(self):
        assert "Administrators" in _refusal(("sysadmin", Role.ADMIN, L3))

    def test_dev_team_cannot_decide(self):
        assert _refusal(("dev.beta", Role.DEV_TEAM, L3)) is not None

    def test_one_person_counts_once(self):
        assert "already" in _refusal(("appsec.lead", Role.APPSEC, L2), decided=["appsec.lead"])

    def test_level_below_minimum_is_refused(self):
        assert _refusal(("appsec.analyst", Role.APPSEC, L1)) is not None

    def test_last_slot_is_reserved_for_top_level(self):
        # One L2 already approved; a second L2 would fill the count without any L3.
        assert "l3" in _refusal(("appsec.other", Role.APPSEC, L2), approved=[L2])
        assert _refusal(("mgmt.exec", Role.MANAGEMENT, L3), approved=[L2]) is None

    def test_a_lower_approver_may_still_reject(self):
        assert _refusal(("appsec.other", Role.APPSEC, L2), approved=[L2], approving=False) is None

    def test_top_level_first_leaves_the_slot_open_to_min_level(self):
        assert _refusal(("appsec.lead", Role.APPSEC, L2), approved=[L3]) is None


def test_full_approval_needs_count_and_top_level():
    requirement = rules.ApprovalRequirement(2, L2, L3)
    assert not rules.is_fully_approved([L2], requirement)
    assert not rules.is_fully_approved([L2, L2], requirement)
    assert rules.is_fully_approved([L2, L3], requirement)


class TestExpiry:
    today = date(2026, 10, 1)

    def test_past_expiry_is_refused(self):
        assert rules.expiry_errors(RA, self.today - timedelta(days=1), self.today, None)

    def test_risk_acceptance_must_end_by_sla_due(self):
        due = self.today + timedelta(days=10)
        assert rules.expiry_errors(RA, due, self.today, due) == []
        assert rules.expiry_errors(RA, due + timedelta(days=1), self.today, due)

    def test_overdue_issue_gets_one_sla_period_from_today(self):
        past_due = self.today - timedelta(days=57)
        assert rules.acceptance_deadline(past_due, self.today, 30) == self.today + timedelta(
            days=30
        )

    def test_on_time_issue_keeps_its_sla_due(self):
        due = self.today + timedelta(days=5)
        assert rules.acceptance_deadline(due, self.today, 30) == due
        assert rules.acceptance_deadline(None, self.today, None) is None

    def test_best_effort_tier_has_no_cap(self):
        assert rules.expiry_errors(RA, self.today + timedelta(days=900), self.today, None) == []

    def test_false_positive_review_within_a_year(self):
        assert rules.expiry_errors(FP, self.today + timedelta(days=365), self.today, None) == []
        assert rules.expiry_errors(FP, self.today + timedelta(days=366), self.today, None)
