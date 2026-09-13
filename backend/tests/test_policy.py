"""Severity & SLA policy engine tests (Requirement.md FR-4, FR-5, Section 12)."""

from datetime import UTC, date, datetime, timedelta

import pytest

from app.models.finding import SeverityTier
from app.models.policy import PolicySet
from app.models.user import Role
from app.modules.policy import service
from app.schemas.policy import PolicySetCreate, SeverityRule, SeverityRuleCondition, SlaDays


@pytest.fixture
def default_policy(db_session) -> PolicySet:
    return service.ensure_default_policy(db_session)


class TestSeverityRuleEngine:
    """FR-4.1: tier from CVSS + EPSS + CISA KEV, first matching rule wins."""

    @pytest.mark.parametrize(
        ("cvss", "epss", "kev", "expected"),
        [
            # FR-4.1: KEV overrides the CVSS band entirely, however low the score.
            (2.0, 0.0, True, SeverityTier.CRITICAL),
            (10.0, 0.97, True, SeverityTier.CRITICAL),
            # EPSS >= 0.3 with CVSS >= 9.0 → Critical even without KEV.
            (9.1, 0.35, False, SeverityTier.CRITICAL),
            # EPSS >= 0.3 with CVSS >= 7.0 → High.
            (7.5, 0.42, False, SeverityTier.HIGH),
            # Plain CVSS bands (Section 12).
            (8.9, 0.01, False, SeverityTier.HIGH),
            (7.0, 0.0, False, SeverityTier.HIGH),
            (6.9, 0.01, False, SeverityTier.MEDIUM),
            (4.0, 0.0, False, SeverityTier.MEDIUM),
            (3.9, 0.0, False, SeverityTier.LOW),
            (0.0, 0.0, False, SeverityTier.LOW),
            # A high CVSS alone does not reach Critical — that needs KEV or high EPSS.
            (9.8, 0.02, False, SeverityTier.HIGH),
        ],
    )
    def test_default_policy_tiering(self, default_policy, cvss, epss, kev, expected):
        decision = service.evaluate_severity(default_policy, cvss=cvss, epss=epss, kev_flag=kev)
        assert decision.tier == expected

    def test_missing_cvss_falls_through_to_catch_all(self, default_policy):
        """A Finding with no score must not match a CVSS band by accident."""
        decision = service.evaluate_severity(default_policy, cvss=None, epss=None, kev_flag=False)
        assert decision.tier == SeverityTier.LOW
        assert decision.matched_rule == "cvss-band-low"

    def test_missing_cvss_still_critical_when_kev(self, default_policy):
        decision = service.evaluate_severity(default_policy, cvss=None, epss=None, kev_flag=True)
        assert decision.tier == SeverityTier.CRITICAL

    def test_matched_rule_is_reported(self, default_policy):
        decision = service.evaluate_severity(default_policy, cvss=5.0, epss=0.0, kev_flag=True)
        assert decision.matched_rule == "cisa-kev-actively-exploited"


class TestDependencyScope:
    """FR-4.2: development-only dependencies are de-prioritised by one tier."""

    def test_development_scope_downgrades_one_tier(self, default_policy):
        decision = service.evaluate_severity(
            default_policy, cvss=7.5, epss=0.0, kev_flag=False, scope="development"
        )
        assert decision.tier == SeverityTier.MEDIUM
        assert decision.downgraded_for_dev_scope is True

    def test_low_cannot_be_downgraded_further(self, default_policy):
        decision = service.evaluate_severity(
            default_policy, cvss=1.0, epss=0.0, kev_flag=False, scope="development"
        )
        assert decision.tier == SeverityTier.LOW
        assert decision.downgraded_for_dev_scope is False

    def test_production_scope_is_not_downgraded(self, default_policy):
        decision = service.evaluate_severity(
            default_policy, cvss=7.5, epss=0.0, kev_flag=False, scope="production"
        )
        assert decision.tier == SeverityTier.HIGH
        assert decision.downgraded_for_dev_scope is False

    def test_downgrade_can_be_switched_off_by_policy(self, db_session):
        policy = service.create_policy_set(
            db_session,
            PolicySetCreate(
                effective_from=datetime.now(UTC).date(),
                severity_rules=service.DEFAULT_SEVERITY_RULES,
                downgrade_dev_scope_findings=False,
            ),
            actor="appsec.lead",
        )
        decision = service.evaluate_severity(
            policy, cvss=7.5, epss=0.0, kev_flag=False, scope="development"
        )
        assert decision.tier == SeverityTier.HIGH


class TestSlaDueDate:
    """FR-5.1/FR-5.2: due date from the SLA policy in force when the CVE was found."""

    @pytest.mark.parametrize(
        ("tier", "expected_days"),
        [
            (SeverityTier.CRITICAL, 7),
            (SeverityTier.HIGH, 30),
            (SeverityTier.MEDIUM, 90),
        ],
    )
    def test_due_date_uses_section_12_defaults(self, default_policy, tier, expected_days):
        detected_on = date(2026, 9, 1)
        assert service.compute_due_date(
            default_policy, tier, detected_on
        ) == detected_on + timedelta(days=expected_days)

    def test_low_tier_has_no_due_date(self, default_policy):
        """Section 12: Low is best-effort / next sprint, so it carries no SLA date."""
        assert service.compute_due_date(default_policy, SeverityTier.LOW, date(2026, 9, 1)) is None

    def test_sla_days_are_configurable_without_code_change(self, db_session):
        policy = service.create_policy_set(
            db_session,
            PolicySetCreate(
                effective_from=datetime.now(UTC).date(),
                severity_rules=service.DEFAULT_SEVERITY_RULES,
                sla_days=SlaDays(critical=3, high=14, medium=45, low=180),
            ),
            actor="appsec.lead",
        )
        detected_on = date(2026, 9, 1)
        assert service.compute_due_date(policy, SeverityTier.CRITICAL, detected_on) == date(
            2026, 9, 4
        )
        assert service.compute_due_date(policy, SeverityTier.LOW, detected_on) == date(2027, 2, 28)


class TestEffectiveDating:
    """NFR Auditability: versions are immutable and selected by effective date."""

    def test_default_policy_is_created_once(self, db_session):
        first = service.ensure_default_policy(db_session)
        second = service.ensure_default_policy(db_session)
        assert first.id == second.id
        assert first.version == 1

    def test_new_version_increments_and_supersedes(self, db_session):
        service.ensure_default_policy(db_session)
        published = service.create_policy_set(
            db_session,
            PolicySetCreate(
                effective_from=datetime.now(UTC).date(),
                severity_rules=service.DEFAULT_SEVERITY_RULES,
                sla_days=SlaDays(critical=5),
            ),
            actor="appsec.lead",
        )
        assert published.version == 2
        assert service.get_effective_policy(db_session).version == 2

    def test_future_dated_version_is_not_yet_effective(self, db_session):
        service.ensure_default_policy(db_session)
        service.create_policy_set(
            db_session,
            PolicySetCreate(
                effective_from=datetime.now(UTC).date() + timedelta(days=30),
                severity_rules=service.DEFAULT_SEVERITY_RULES,
                sla_days=SlaDays(critical=1),
            ),
            actor="appsec.lead",
        )
        today_policy = service.get_effective_policy(db_session)
        assert today_policy.version == 1
        assert service.sla_days_for_tier(today_policy, SeverityTier.CRITICAL) == 7

        future_policy = service.get_effective_policy(
            db_session, datetime.now(UTC).date() + timedelta(days=31)
        )
        assert future_policy.version == 2
        assert service.sla_days_for_tier(future_policy, SeverityTier.CRITICAL) == 1

    def test_audit_entries_reference_the_real_policy_id(
        self, db_session, client, make_user, auth_headers
    ):
        """FR-11.2: an audit entry has to be traceable back to the row it describes, so
        entity_id must be the PolicySet's id — not "None" from reading it before flush."""
        seeded = service.ensure_default_policy(db_session)
        published = service.create_policy_set(
            db_session,
            PolicySetCreate(
                effective_from=datetime.now(UTC).date(),
                severity_rules=service.DEFAULT_SEVERITY_RULES,
            ),
            actor="appsec.lead",
        )

        make_user("audit.viewer", Role.AUDIT)
        logs = client.get(
            "/api/v1/audit-logs",
            headers=auth_headers("audit.viewer"),
            params={"entity_type": "policy_set"},
        ).json()

        entity_ids = {item["entity_id"] for item in logs["items"]}
        assert entity_ids == {str(seeded.id), str(published.id)}
        assert "None" not in entity_ids

    def test_publishing_writes_an_audit_entry(self, db_session, client, make_user, auth_headers):
        """FR-11.1: a policy change records actor plus before/after values."""
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")
        resp = client.post(
            "/api/v1/policies",
            headers=headers,
            json={
                "effective_from": datetime.now(UTC).date().isoformat(),
                "severity_rules": [
                    {"name": "catch-all", "when": {}, "tier": "medium"},
                ],
                "sla_days": {"critical": 2, "high": 10, "medium": 40, "low": None},
            },
        )
        assert resp.status_code == 201, resp.text

        audit = client.get(
            "/api/v1/audit-logs", headers=headers, params={"entity_type": "policy_set"}
        )
        assert audit.status_code == 200
        actions = [item["action"] for item in audit.json()["items"]]
        assert "policy.publish_version" in actions
        published = next(
            item for item in audit.json()["items"] if item["action"] == "policy.publish_version"
        )
        assert published["actor"] == "appsec.lead"
        assert published["before_value"]["sla_days"]["critical"] == 7
        assert published["after_value"]["sla_days"]["critical"] == 2


class TestPolicyValidation:
    def test_rule_set_without_catch_all_is_rejected(self):
        with pytest.raises(ValueError, match="catch-all"):
            PolicySetCreate(
                effective_from=datetime.now(UTC).date(),
                severity_rules=[
                    SeverityRule(
                        name="only-high-cvss",
                        when=SeverityRuleCondition(cvss_min=7.0),
                        tier=SeverityTier.HIGH,
                    )
                ],
            )

    def test_inverted_cvss_bounds_are_rejected(self):
        with pytest.raises(ValueError, match="cvss_min"):
            SeverityRuleCondition(cvss_min=9.0, cvss_max=4.0)

    def test_out_of_range_epss_is_rejected(self):
        with pytest.raises(ValueError):
            SeverityRuleCondition(epss_min=1.5)


class TestPolicyApi:
    def test_dev_team_cannot_publish_policy(self, client, make_user, auth_headers):
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.post(
            "/api/v1/policies",
            headers=auth_headers("dev.alpha"),
            json={
                "effective_from": datetime.now(UTC).date().isoformat(),
                "severity_rules": [{"name": "catch-all", "when": {}, "tier": "low"}],
            },
        )
        assert resp.status_code == 403

    def test_dev_team_can_read_effective_policy(self, client, make_user, auth_headers):
        """FR-10.2: Dev Teams need the SLA numbers behind their own Findings."""
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.get("/api/v1/policies/effective", headers=auth_headers("dev.alpha"))
        assert resp.status_code == 200
        assert resp.json()["sla_days"]["critical"] == 7

    def test_appsec_sees_version_history(self, client, make_user, auth_headers):
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")
        client.post(
            "/api/v1/policies",
            headers=headers,
            json={
                "effective_from": datetime.now(UTC).date().isoformat(),
                "severity_rules": [{"name": "catch-all", "when": {}, "tier": "low"}],
            },
        )
        resp = client.get("/api/v1/policies", headers=headers)
        assert resp.status_code == 200
        versions = [item["version"] for item in resp.json()]
        assert versions == [2, 1]

    def test_evaluate_endpoint_dry_runs_the_rule_engine(self, client, make_user, auth_headers):
        make_user("appsec.lead", Role.APPSEC)
        resp = client.post(
            "/api/v1/policies/evaluate",
            headers=auth_headers("appsec.lead"),
            json={"cvss": 4.5, "epss": 0.01, "kev_flag": True},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["severity_tier"] == "critical"
        assert body["matched_rule"] == "cisa-kev-actively-exploited"
        assert body["sla_days"] == 7

    def test_evaluate_unknown_version_returns_404(self, client, make_user, auth_headers):
        make_user("appsec.lead", Role.APPSEC)
        resp = client.post(
            "/api/v1/policies/evaluate",
            headers=auth_headers("appsec.lead"),
            json={"cvss": 5.0, "policy_version": 99},
        )
        assert resp.status_code == 404
