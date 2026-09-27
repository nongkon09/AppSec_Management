"""Risk exception workflow through the API.

See docs/risk-exception-design.md 3.4-3.5 and docs/workflows.md W3-W6.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.integrations.sca_connector import SCAComponent, SCAFinding, SCAProject
from app.models.audit import AuditLog
from app.models.finding import Finding, FindingStatus, SeverityTier
from app.models.user import ApprovalLevel, Role
from app.modules.exceptions import service as exceptions_service
from app.modules.policy import service as policy_service
from app.modules.sbom import service as sbom_service
from tests.test_dependency_track import FakeThreatIntel
from tests.test_sbom import FakeConnector

TODAY = datetime.now(UTC).date()
LOG4J_PURL = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


@pytest.fixture
def people(make_user):
    make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
    make_user("dev.beta", Role.DEV_TEAM, owner_team="Team Beta")
    make_user("appsec.lead", Role.APPSEC, approval_level=ApprovalLevel.L2)
    make_user("appsec.other", Role.APPSEC, approval_level=ApprovalLevel.L2)
    make_user("appsec.analyst", Role.APPSEC, approval_level=ApprovalLevel.L1)
    make_user("mgmt.exec", Role.MANAGEMENT, approval_level=ApprovalLevel.L3)
    make_user("sysadmin", Role.ADMIN, approval_level=ApprovalLevel.L3)
    make_user("ci.pipeline", Role.PIPELINE)


@pytest.fixture
def log4j(make_application, make_version, make_component, make_finding, db_session):
    application = make_application(app_name="Payment Gateway", owner_team="Team Alpha")
    version = make_version(application, version_label="1.0.0")
    component = make_component(version, component_name="log4j-core")
    component.purl = LOG4J_PURL
    db_session.commit()
    return make_finding(
        version, component=component, severity_tier=SeverityTier.CRITICAL, kev_flag=True
    )


@pytest.fixture
def control(client, people, auth_headers):
    resp = client.post(
        "/api/v1/controls",
        json={
            "name": "WAF virtual patch for JNDI lookups",
            "category": "network",
            "owner": "Network Security",
            "effectiveness": "high",
            "review_due_on": (TODAY + timedelta(days=180)).isoformat(),
        },
        headers=auth_headers("appsec.lead"),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _submit(client, auth_headers, user, **body):
    return client.post("/api/v1/exceptions", json=body, headers=auth_headers(user))


def _risk_acceptance(finding, control_id=None, **extra):
    body = {
        "exception_type": "risk_acceptance",
        "finding_ids": [str(finding.id)],
        "reason": "Vendor patch lands next sprint; JNDI blocked at the WAF meanwhile.",
        "residual_severity_tier": "high",
        "control_ids": [control_id] if control_id else [],
        "expires_on": (TODAY + timedelta(days=20)).isoformat(),
    }
    body.update(extra)
    return body


def _decide(client, auth_headers, user, exception_id, action="approve", comment="Checked"):
    return client.post(
        f"/api/v1/exceptions/{exception_id}/{action}",
        json={"comment": comment},
        headers=auth_headers(user),
    )


class TestMakerChecker:
    def test_critical_needs_two_approvers_one_of_them_l3(
        self, client, auth_headers, people, log4j, control, db_session
    ):
        resp = _submit(client, auth_headers, "dev.alpha", **_risk_acceptance(log4j, control["id"]))
        assert resp.status_code == 201, resp.text
        exc = resp.json()
        assert exc["status"] == "pending"
        assert exc["reference"] == f"EXC-{TODAY.year}-0001"
        assert (
            exc["required_approvals"],
            exc["required_min_level"],
            exc["required_top_level"],
        ) == (
            2,
            "l2",
            "l3",
        )
        assert exc["original_severity_tier"] == "critical" and exc["kev_involved"] is True

        assert _decide(client, auth_headers, "dev.alpha", exc["id"]).status_code == 403
        assert _decide(client, auth_headers, "sysadmin", exc["id"]).status_code == 403

        first = _decide(client, auth_headers, "appsec.lead", exc["id"])
        assert first.status_code == 200 and first.json()["status"] == "pending"
        db_session.refresh(log4j)
        assert log4j.status == FindingStatus.OPEN  # nothing changes before full approval

        blocked = _decide(client, auth_headers, "appsec.other", exc["id"])
        assert blocked.status_code == 403 and "l3" in blocked.json()["detail"]

        final = _decide(client, auth_headers, "mgmt.exec", exc["id"])
        assert final.status_code == 200 and final.json()["status"] == "approved"

        db_session.refresh(log4j)
        policy = policy_service.get_effective_policy(db_session)
        assert log4j.status == FindingStatus.RISK_ACCEPTED
        assert log4j.residual_severity_tier == SeverityTier.HIGH
        assert log4j.severity_tier == SeverityTier.CRITICAL  # original kept
        assert log4j.due_date == policy_service.compute_due_date(
            policy, SeverityTier.HIGH, log4j.sla_started_on
        )
        actions = {row.action for row in db_session.query(AuditLog).all()}
        assert {
            "exception.submit",
            "exception.approve_partial",
            "exception.approve_final",
        } <= actions
        assert "finding.exception_applied" in actions

    def test_reject_needs_a_reason_and_ends_the_request(
        self, client, auth_headers, people, log4j, control
    ):
        exc = _submit(
            client, auth_headers, "dev.alpha", **_risk_acceptance(log4j, control["id"])
        ).json()
        assert (
            _decide(
                client, auth_headers, "appsec.lead", exc["id"], "reject", comment=""
            ).status_code
            == 422
        )
        resp = _decide(
            client,
            auth_headers,
            "appsec.lead",
            exc["id"],
            "reject",
            comment="WAF rule not deployed",
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"
        assert resp.json()["ended_reason"] == "WAF rule not deployed"
        assert _decide(client, auth_headers, "mgmt.exec", exc["id"]).status_code == 422

    def test_only_the_maker_can_withdraw(self, client, auth_headers, people, log4j, control):
        exc = _submit(
            client, auth_headers, "dev.alpha", **_risk_acceptance(log4j, control["id"])
        ).json()
        other = client.post(
            f"/api/v1/exceptions/{exc['id']}/withdraw",
            json={"reason": "not mine"},
            headers=auth_headers("appsec.lead"),
        )
        assert other.status_code == 403
        mine = client.post(
            f"/api/v1/exceptions/{exc['id']}/withdraw",
            json={"reason": "fixed instead"},
            headers=auth_headers("dev.alpha"),
        )
        assert mine.status_code == 200 and mine.json()["status"] == "withdrawn"

    def test_awaiting_me_lists_only_requests_i_can_approve(
        self, client, auth_headers, people, log4j, control
    ):
        _submit(client, auth_headers, "dev.alpha", **_risk_acceptance(log4j, control["id"]))
        for user, expected in (("appsec.lead", 1), ("appsec.analyst", 0), ("dev.alpha", 0)):
            resp = client.get("/api/v1/exceptions?awaiting_me=true", headers=auth_headers(user))
            assert resp.json()["total"] == expected, user


class TestValidation:
    def test_lowering_severity_without_a_control_is_refused(
        self, client, auth_headers, people, log4j
    ):
        resp = _submit(client, auth_headers, "dev.alpha", **_risk_acceptance(log4j))
        assert resp.status_code == 422 and "control" in resp.json()["detail"]

    def test_kev_cannot_drop_below_high(self, client, auth_headers, people, log4j, control):
        resp = _submit(
            client,
            auth_headers,
            "dev.alpha",
            **_risk_acceptance(log4j, control["id"], residual_severity_tier="medium"),
        )
        assert resp.status_code == 422 and "KEV" in resp.json()["detail"]

    def test_expiry_cannot_outlast_the_sla(self, client, auth_headers, people, log4j, control):
        resp = _submit(
            client,
            auth_headers,
            "dev.alpha",
            **_risk_acceptance(
                log4j, control["id"], expires_on=(TODAY + timedelta(days=400)).isoformat()
            ),
        )
        assert resp.status_code == 422 and "SLA due date" in resp.json()["detail"]

    def test_stale_control_cannot_be_cited(self, client, auth_headers, people, log4j, control):
        client.patch(
            f"/api/v1/controls/{control['id']}",
            json={"review_due_on": (TODAY - timedelta(days=1)).isoformat()},
            headers=auth_headers("appsec.lead"),
        )
        resp = _submit(client, auth_headers, "dev.alpha", **_risk_acceptance(log4j, control["id"]))
        assert resp.status_code == 422 and "review date" in resp.json()["detail"]

    def test_second_live_request_for_the_same_issue_conflicts(
        self, client, auth_headers, people, log4j, control
    ):
        _submit(client, auth_headers, "dev.alpha", **_risk_acceptance(log4j, control["id"]))
        resp = _submit(client, auth_headers, "dev.alpha", **_risk_acceptance(log4j, control["id"]))
        assert resp.status_code == 409

    def test_other_teams_findings_are_invisible(self, client, auth_headers, people, log4j, control):
        resp = _submit(client, auth_headers, "dev.beta", **_risk_acceptance(log4j, control["id"]))
        assert resp.status_code == 422  # not found in their scope


class TestFalsePositive:
    def test_false_positive_suppresses_and_records_vex(
        self, client, auth_headers, people, make_application, make_version, make_finding, db_session
    ):
        application = make_application(app_name="Portal", owner_team="Team Alpha")
        finding = make_finding(
            make_version(application),
            severity_tier=SeverityTier.MEDIUM,
            kev_flag=False,
            cve_id="CVE-2020-8203",
        )
        exc = _submit(
            client,
            auth_headers,
            "dev.alpha",
            exception_type="false_positive",
            finding_ids=[str(finding.id)],
            reason="The vulnerable lodash function is never imported by this service.",
            vex_justification="code_not_reachable",
            expires_on=(TODAY + timedelta(days=180)).isoformat(),
        ).json()
        assert exc["required_approvals"] == 1 and exc["required_min_level"] == "l1"
        resp = _decide(client, auth_headers, "appsec.analyst", exc["id"])
        assert resp.json()["status"] == "approved"
        db_session.refresh(finding)
        assert finding.status == FindingStatus.SUPPRESSED
        assert finding.vex_status.value == "not_affected"
        assert finding.vex_justification == "code_not_reachable"


def _approved_risk_acceptance(client, auth_headers, finding, control_id):
    exc = _submit(client, auth_headers, "dev.alpha", **_risk_acceptance(finding, control_id)).json()
    _decide(client, auth_headers, "appsec.lead", exc["id"])
    return _decide(client, auth_headers, "mgmt.exec", exc["id"]).json()


class TestLifecycle:
    def test_new_version_inherits_the_exception_and_sla_anchor(
        self, client, auth_headers, people, log4j, control, db_session
    ):
        _approved_risk_acceptance(client, auth_headers, log4j, control["id"])
        anchor = log4j.sla_started_on

        component = SCAComponent(
            name="log4j-core", version="2.14.1", license=None, purl=LOG4J_PURL, scope="production"
        )
        connector = FakeConnector(
            projects=[SCAProject(external_id="p2", name="Payment Gateway", version="1.1.0")],
            components={"p2": [component]},
            findings={
                "p2": [
                    SCAFinding(
                        component_purl=LOG4J_PURL,
                        component_name="log4j-core",
                        component_version="2.14.1",
                        cve_id="CVE-2021-44228",
                        cvss=10.0,
                        epss=0.97,
                        kev_flag=True,
                    )
                ]
            },
        )
        sbom_service.sync_from_connector(
            db_session, connector=connector, threat_intel=FakeThreatIntel(kev=set(), epss={})
        )

        new_row = (
            db_session.query(Finding)
            .filter(Finding.issue_key == log4j.issue_key, Finding.id != log4j.id)
            .one()
        )
        assert new_row.status == FindingStatus.RISK_ACCEPTED
        assert new_row.residual_severity_tier == SeverityTier.HIGH
        assert new_row.sla_started_on == anchor

    def test_expiry_returns_findings_to_the_backlog(
        self, client, auth_headers, people, log4j, control, db_session
    ):
        exc = _approved_risk_acceptance(client, auth_headers, log4j, control["id"])
        expired, _, _ = exceptions_service.sweep(db_session, today=TODAY + timedelta(days=21))
        assert expired == 1
        db_session.refresh(log4j)
        assert log4j.status == FindingStatus.OPEN
        assert log4j.residual_severity_tier is None
        detail = client.get(f"/api/v1/exceptions/{exc['id']}", headers=auth_headers("appsec.lead"))
        assert detail.json()["status"] == "expired"

    def test_revoke_is_appsec_only_and_reopens(
        self, client, auth_headers, people, log4j, control, db_session
    ):
        exc = _approved_risk_acceptance(client, auth_headers, log4j, control["id"])
        denied = client.post(
            f"/api/v1/exceptions/{exc['id']}/revoke",
            json={"reason": "please"},
            headers=auth_headers("dev.alpha"),
        )
        assert denied.status_code == 403
        resp = client.post(
            f"/api/v1/exceptions/{exc['id']}/revoke",
            json={"reason": "WAF rule was removed in the last change window"},
            headers=auth_headers("appsec.analyst"),
        )
        assert resp.status_code == 200 and resp.json()["status"] == "revoked"
        db_session.refresh(log4j)
        assert log4j.status == FindingStatus.OPEN

    def test_closed_when_every_covered_finding_is_fixed(
        self, client, auth_headers, people, log4j, control, db_session
    ):
        _approved_risk_acceptance(client, auth_headers, log4j, control["id"])
        log4j.status = FindingStatus.FIXED
        db_session.commit()
        _, closed, _ = exceptions_service.sweep(db_session)
        assert closed == 1


class TestBypassAndReference:
    def test_devops_checks_reference_and_records_bypass(
        self, client, auth_headers, people, log4j, control
    ):
        exc = _submit(
            client, auth_headers, "dev.alpha", **_risk_acceptance(log4j, control["id"])
        ).json()
        pending = client.post(
            f"/api/v1/exceptions/{exc['id']}/bypasses",
            json={"tool": "harbor"},
            headers=auth_headers("dev.alpha"),
        )
        assert pending.status_code == 422  # not approved yet

        _decide(client, auth_headers, "appsec.lead", exc["id"])
        _decide(client, auth_headers, "mgmt.exec", exc["id"])

        lookup = client.get(
            f"/api/v1/exceptions/by-reference/{exc['reference'].lower()}",
            headers=auth_headers("ci.pipeline"),
        )
        assert lookup.status_code == 200 and lookup.json()["status"] == "approved"

        other_team = client.post(
            f"/api/v1/exceptions/{exc['id']}/bypasses",
            json={"tool": "harbor"},
            headers=auth_headers("dev.beta"),
        )
        assert other_team.status_code == 404  # outside their scope entirely

        resp = client.post(
            f"/api/v1/exceptions/{exc['id']}/bypasses",
            json={"tool": "harbor", "reference_url": "https://ci.example/run/42", "note": "prod"},
            headers=auth_headers("dev.alpha"),
        )
        assert resp.status_code == 201
        assert resp.json()["bypasses"][0]["tool"] == "harbor"

    def test_pipeline_account_cannot_read_the_backlog(self, client, auth_headers, people):
        assert (
            client.get("/api/v1/findings", headers=auth_headers("ci.pipeline")).status_code == 403
        )
        assert (
            client.get("/api/v1/exceptions", headers=auth_headers("ci.pipeline")).status_code == 403
        )


class TestOrganisationWide:
    def test_cve_request_covers_every_application_and_needs_l3(
        self, client, auth_headers, people, make_application, make_version, make_finding, db_session
    ):
        for name, team in (("App A", "Team Alpha"), ("App B", "Team Beta")):
            make_finding(
                make_version(make_application(app_name=name, owner_team=team)),
                severity_tier=SeverityTier.MEDIUM,
                kev_flag=False,
                cve_id="CVE-2024-0001",
            )
        denied = _submit(
            client,
            auth_headers,
            "dev.alpha",
            exception_type="not_affected",
            cve_id="CVE-2024-0001",
            reason="Only affects Windows hosts; we run Linux everywhere.",
            vex_justification="requires_environment",
            expires_on=(TODAY + timedelta(days=90)).isoformat(),
        )
        assert denied.status_code == 403

        exc = _submit(
            client,
            auth_headers,
            "appsec.lead",
            exception_type="not_affected",
            cve_id="CVE-2024-0001",
            reason="Only affects Windows hosts; we run Linux everywhere.",
            vex_justification="requires_environment",
            expires_on=(TODAY + timedelta(days=90)).isoformat(),
        ).json()
        assert len(exc["items"]) == 2
        assert (exc["required_approvals"], exc["required_top_level"]) == (2, "l3")
        _decide(client, auth_headers, "appsec.other", exc["id"])
        assert _decide(client, auth_headers, "mgmt.exec", exc["id"]).json()["status"] == "approved"
        statuses = {f.status for f in db_session.query(Finding).all()}
        assert statuses == {FindingStatus.SUPPRESSED}
