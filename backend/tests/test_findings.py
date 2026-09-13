"""Finding backlog tests (Requirement.md FR-5.4, FR-6.5.6, FR-10.2, Section 4 scoping)."""

from datetime import UTC, datetime, timedelta

from app.models.finding import FindingSource, FindingStatus, SeverityTier
from app.models.user import Role

YESTERDAY = datetime.now(UTC).date() - timedelta(days=1)
NEXT_WEEK = datetime.now(UTC).date() + timedelta(days=7)


class TestBacklogListing:
    def test_backlog_is_ordered_by_severity_then_due_date(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        application = make_application()
        version = make_version(application)
        make_finding(version, severity_tier=SeverityTier.MEDIUM, cve_id="CVE-3", due_date=NEXT_WEEK)
        make_finding(
            version, severity_tier=SeverityTier.CRITICAL, cve_id="CVE-1", due_date=NEXT_WEEK
        )
        make_finding(version, severity_tier=SeverityTier.HIGH, cve_id="CVE-2", due_date=YESTERDAY)

        make_user("appsec.lead", Role.APPSEC)
        resp = client.get("/api/v1/findings", headers=auth_headers("appsec.lead"))
        assert resp.status_code == 200
        assert [item["cve_id"] for item in resp.json()["items"]] == ["CVE-1", "CVE-2", "CVE-3"]

    def test_row_carries_the_full_drilldown_chain(
        self,
        client,
        make_user,
        auth_headers,
        make_application,
        make_version,
        make_component,
        make_finding,
    ):
        """FR-10.5: Application → Version → Component is available without extra calls."""
        application = make_application(app_name="Customer Web Portal")
        version = make_version(application, version_label="2026.9.1")
        component = make_component(version)
        make_finding(version, component=component, due_date=NEXT_WEEK)

        make_user("appsec.lead", Role.APPSEC)
        resp = client.get("/api/v1/findings", headers=auth_headers("appsec.lead"))
        row = resp.json()["items"][0]
        assert row["application_name"] == "Customer Web Portal"
        assert row["version_label"] == "2026.9.1"
        assert row["component_name"] == "org.apache.logging.log4j:log4j-core"
        assert row["component_version"] == "2.14.1"
        assert row["owner_team"] == "Team Alpha"

    def test_pentest_finding_without_component_appears_in_backlog(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        """FR-6.5.6: Pentest findings share the SBOM backlog rather than living apart."""
        application = make_application()
        version = make_version(application)
        make_finding(
            version,
            component=None,
            source=FindingSource.PENTEST,
            cve_id=None,
            title="Missing account lockout on login endpoint",
            severity_tier=SeverityTier.HIGH,
            cvss=None,
            epss=None,
            kev_flag=False,
            due_date=NEXT_WEEK,
        )

        make_user("appsec.lead", Role.APPSEC)
        resp = client.get("/api/v1/findings", headers=auth_headers("appsec.lead"))
        row = resp.json()["items"][0]
        assert row["source"] == "pentest"
        assert row["cve_id"] is None
        assert row["title"] == "Missing account lockout on login endpoint"
        assert row["component_name"] is None


class TestBacklogFilters:
    def test_filter_by_severity(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        make_finding(version, severity_tier=SeverityTier.CRITICAL, cve_id="CVE-1")
        make_finding(version, severity_tier=SeverityTier.LOW, cve_id="CVE-2")

        make_user("appsec.lead", Role.APPSEC)
        resp = client.get(
            "/api/v1/findings", headers=auth_headers("appsec.lead"), params={"severity": "critical"}
        )
        assert resp.json()["total"] == 1
        assert resp.json()["items"][0]["cve_id"] == "CVE-1"

    def test_filter_overdue_only(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        """FR-5.4: Overdue = open and past its due date."""
        version = make_version(make_application())
        make_finding(version, cve_id="CVE-OVERDUE", due_date=YESTERDAY)
        make_finding(version, cve_id="CVE-OK", due_date=NEXT_WEEK)
        make_finding(version, cve_id="CVE-NO-SLA", due_date=None)

        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")
        overdue = client.get(
            "/api/v1/findings", headers=headers, params={"sla_status": "overdue"}
        ).json()
        assert [item["cve_id"] for item in overdue["items"]] == ["CVE-OVERDUE"]
        assert overdue["items"][0]["is_overdue"] is True

        within = client.get(
            "/api/v1/findings", headers=headers, params={"sla_status": "within_sla"}
        ).json()
        assert sorted(item["cve_id"] for item in within["items"]) == ["CVE-NO-SLA", "CVE-OK"]

    def test_closed_finding_past_due_date_is_not_overdue(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        make_finding(version, cve_id="CVE-FIXED", due_date=YESTERDAY, status=FindingStatus.FIXED)
        make_user("appsec.lead", Role.APPSEC)
        resp = client.get(
            "/api/v1/findings",
            headers=auth_headers("appsec.lead"),
            params={"sla_status": "overdue"},
        )
        assert resp.json()["total"] == 0

    def test_search_matches_cve_and_application_name(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        alpha = make_version(make_application(app_name="Customer Web Portal"))
        beta = make_version(make_application(app_name="Payment Gateway API"))
        make_finding(alpha, cve_id="CVE-2021-44228")
        make_finding(beta, cve_id="CVE-2020-36518")

        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")
        by_cve = client.get("/api/v1/findings", headers=headers, params={"search": "44228"})
        assert by_cve.json()["total"] == 1
        by_app = client.get("/api/v1/findings", headers=headers, params={"search": "Payment"})
        assert by_app.json()["items"][0]["cve_id"] == "CVE-2020-36518"

    def test_filter_by_application(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        alpha_app = make_application(app_name="Alpha App")
        make_finding(make_version(alpha_app), cve_id="CVE-1")
        make_finding(make_version(make_application(app_name="Beta App")), cve_id="CVE-2")

        make_user("appsec.lead", Role.APPSEC)
        resp = client.get(
            "/api/v1/findings",
            headers=auth_headers("appsec.lead"),
            params={"application_id": str(alpha_app.id)},
        )
        assert resp.json()["total"] == 1
        assert resp.json()["items"][0]["cve_id"] == "CVE-1"


class TestDataScoping:
    """Section 4: Dev Team / Tech Lead sees only Applications their team owns."""

    def test_dev_team_sees_only_own_team_findings(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        make_finding(make_version(make_application(owner_team="Team Alpha")), cve_id="CVE-ALPHA")
        make_finding(make_version(make_application(owner_team="Team Beta")), cve_id="CVE-BETA")

        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.get("/api/v1/findings", headers=auth_headers("dev.alpha"))
        assert resp.json()["total"] == 1
        assert resp.json()["items"][0]["cve_id"] == "CVE-ALPHA"

    def test_dev_team_cannot_read_another_teams_finding_by_id(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        other = make_finding(make_version(make_application(owner_team="Team Beta")))
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.get(f"/api/v1/findings/{other.id}", headers=auth_headers("dev.alpha"))
        assert resp.status_code == 404

    def test_dev_team_without_owner_team_sees_nothing(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        """Unassigned Dev Team users fail closed rather than seeing the whole estate."""
        make_finding(make_version(make_application(owner_team="Team Alpha")))
        make_user("dev.orphan", Role.DEV_TEAM, owner_team=None)
        resp = client.get("/api/v1/findings", headers=auth_headers("dev.orphan"))
        assert resp.json()["total"] == 0

    def test_audit_role_sees_all_findings_read_only(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        make_finding(make_version(make_application(owner_team="Team Alpha")), cve_id="CVE-A")
        make_finding(make_version(make_application(owner_team="Team Beta")), cve_id="CVE-B")

        make_user("audit.viewer", Role.AUDIT)
        headers = auth_headers("audit.viewer")
        assert client.get("/api/v1/findings", headers=headers).json()["total"] == 2
        # FR-10.4: Compliance/Audit is read-only across the whole system.
        finding_id = client.get("/api/v1/findings", headers=headers).json()["items"][0]["id"]
        patch = client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=headers,
            json={"remediation_plan": "should not be allowed"},
        )
        assert patch.status_code == 403


class TestBacklogSummary:
    def test_summary_splits_severity_by_sla_state(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        make_finding(version, severity_tier=SeverityTier.CRITICAL, cve_id="C1", due_date=YESTERDAY)
        make_finding(version, severity_tier=SeverityTier.CRITICAL, cve_id="C2", due_date=NEXT_WEEK)
        make_finding(version, severity_tier=SeverityTier.HIGH, cve_id="H1", due_date=NEXT_WEEK)
        make_finding(
            version,
            severity_tier=SeverityTier.LOW,
            cve_id="L1",
            due_date=YESTERDAY,
            status=FindingStatus.FIXED,
        )

        make_user("appsec.lead", Role.APPSEC)
        body = client.get("/api/v1/findings/summary", headers=auth_headers("appsec.lead")).json()

        assert body["total_open"] == 3
        assert body["total_overdue"] == 1
        by_tier = {row["severity_tier"]: row for row in body["by_severity"]}
        assert by_tier["critical"] == {
            "severity_tier": "critical",
            "total": 2,
            "overdue": 1,
            "within_sla": 1,
        }
        assert by_tier["high"]["total"] == 1
        # Fixed findings leave the backlog entirely.
        assert by_tier["low"]["total"] == 0

    def test_summary_reports_sla_compliance_percentage(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        """FR-10.3 KPI: share of open Findings still inside their SLA."""
        version = make_version(make_application())
        for index in range(3):
            make_finding(version, cve_id=f"CVE-OK-{index}", due_date=NEXT_WEEK)
        make_finding(version, cve_id="CVE-LATE", due_date=YESTERDAY)

        make_user("appsec.lead", Role.APPSEC)
        body = client.get("/api/v1/findings/summary", headers=auth_headers("appsec.lead")).json()
        assert body["sla_compliance_percent"] == 75.0

    def test_summary_breaks_down_per_application(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        """FR-5.4: backlog per Application, so the worst offender is visible first."""
        quiet = make_version(make_application(app_name="Quiet App"))
        noisy = make_version(make_application(app_name="Noisy App"))
        make_finding(quiet, severity_tier=SeverityTier.MEDIUM, cve_id="M1")
        make_finding(noisy, severity_tier=SeverityTier.CRITICAL, cve_id="C1")
        make_finding(noisy, severity_tier=SeverityTier.HIGH, cve_id="H1", due_date=YESTERDAY)

        make_user("appsec.lead", Role.APPSEC)
        body = client.get("/api/v1/findings/summary", headers=auth_headers("appsec.lead")).json()

        rows = body["by_application"]
        assert [row["application_name"] for row in rows] == ["Noisy App", "Quiet App"]
        assert rows[0]["critical"] == 1
        assert rows[0]["high"] == 1
        assert rows[0]["overdue"] == 1
        assert rows[0]["total"] == 2
        assert rows[1]["medium"] == 1

    def test_summary_is_scoped_for_dev_team(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        make_finding(make_version(make_application(owner_team="Team Alpha")))
        make_finding(make_version(make_application(owner_team="Team Beta")))

        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        body = client.get("/api/v1/findings/summary", headers=auth_headers("dev.alpha")).json()
        assert body["total_open"] == 1
        assert len(body["by_application"]) == 1


class TestManualFindingIntake:
    def test_appsec_creates_pentest_finding_with_explicit_severity(
        self, client, make_user, auth_headers, make_application, make_version, make_pentest_project
    ):
        """FR-6.5.5: the tester assigns Pentest severity; the SLA still comes from policy.
        FR-6.5.6: only allowed once the Pentest Project has reached Report Final."""
        version = make_version(make_application())
        project = make_pentest_project(version)
        make_user("appsec.lead", Role.APPSEC)
        resp = client.post(
            "/api/v1/findings",
            headers=auth_headers("appsec.lead"),
            json={
                "app_version_id": str(version.id),
                "source": "pentest",
                "pentest_project_id": str(project.id),
                "title": "Reflected XSS in statement search",
                "severity_tier": "high",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["severity_tier"] == "high"
        assert body["status"] == "open"
        assert body["policy_version"] == 1
        # High = 30 days under the Section 12 default policy.
        assert body["due_date"] == (datetime.now(UTC).date() + timedelta(days=30)).isoformat()

    def test_severity_is_derived_from_policy_when_not_supplied(
        self, client, make_user, auth_headers, make_application, make_version
    ):
        version = make_version(make_application())
        make_user("appsec.lead", Role.APPSEC)
        resp = client.post(
            "/api/v1/findings",
            headers=auth_headers("appsec.lead"),
            json={
                "app_version_id": str(version.id),
                "source": "sast",
                "title": "SQL injection in report builder",
                "cvss": 9.4,
                "epss": 0.4,
            },
        )
        assert resp.status_code == 201
        # CVSS >= 9.0 with EPSS >= 0.3 → Critical, 7-day SLA (FR-4.1, Section 12).
        assert resp.json()["severity_tier"] == "critical"
        assert resp.json()["due_date"] == (datetime.now(UTC).date() + timedelta(days=7)).isoformat()

    def test_dev_scope_component_downgrades_derived_severity(
        self, client, make_user, auth_headers, make_application, make_version, make_component
    ):
        """FR-4.2: a development-only dependency is de-prioritised on intake."""
        version = make_version(make_application())
        component = make_component(version, component_name="eslint-utils", scope="development")
        make_user("appsec.lead", Role.APPSEC)
        resp = client.post(
            "/api/v1/findings",
            headers=auth_headers("appsec.lead"),
            json={
                "app_version_id": str(version.id),
                "component_id": str(component.id),
                "source": "sbom",
                "cve_id": "CVE-2020-7598",
                "cvss": 7.5,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["severity_tier"] == "medium"

    def test_finding_requires_cve_or_title(
        self, client, make_user, auth_headers, make_application, make_version
    ):
        version = make_version(make_application())
        make_user("appsec.lead", Role.APPSEC)
        resp = client.post(
            "/api/v1/findings",
            headers=auth_headers("appsec.lead"),
            json={"app_version_id": str(version.id), "source": "pentest"},
        )
        assert resp.status_code == 422

    def test_unknown_app_version_returns_404(self, client, make_user, auth_headers):
        make_user("appsec.lead", Role.APPSEC)
        resp = client.post(
            "/api/v1/findings",
            headers=auth_headers("appsec.lead"),
            json={
                "app_version_id": "00000000-0000-0000-0000-000000000000",
                "source": "pentest",
                "title": "orphan",
            },
        )
        assert resp.status_code == 404

    def test_dev_team_cannot_create_findings(
        self, client, make_user, auth_headers, make_application, make_version
    ):
        version = make_version(make_application())
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.post(
            "/api/v1/findings",
            headers=auth_headers("dev.alpha"),
            json={
                "app_version_id": str(version.id),
                "source": "pentest",
                "title": "self-reported",
            },
        )
        assert resp.status_code == 403


class TestRemediationPlan:
    def test_owning_dev_team_updates_plan(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        """FR-10.2: the Dev Team maintains the remediation plan on their own Findings."""
        finding = make_finding(make_version(make_application(owner_team="Team Alpha")))
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.patch(
            f"/api/v1/findings/{finding.id}",
            headers=auth_headers("dev.alpha"),
            json={"remediation_plan": "Upgrade log4j-core to 2.17.1 in sprint 2026.10"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["remediation_plan"] == "Upgrade log4j-core to 2.17.1 in sprint 2026.10"
        assert body["remediation_plan_updated_by"] == "dev.alpha"
        assert body["remediation_plan_updated_at"] is not None

    def test_other_dev_team_cannot_update_plan(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        finding = make_finding(make_version(make_application(owner_team="Team Beta")))
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.patch(
            f"/api/v1/findings/{finding.id}",
            headers=auth_headers("dev.alpha"),
            json={"remediation_plan": "not my application"},
        )
        assert resp.status_code == 404

    def test_plan_update_is_audited_with_before_and_after(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        """FR-11.1: before/after values are recorded for every significant change."""
        finding = make_finding(make_version(make_application(owner_team="Team Alpha")))
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        make_user("audit.viewer", Role.AUDIT)
        dev_headers = auth_headers("dev.alpha")

        client.patch(
            f"/api/v1/findings/{finding.id}", headers=dev_headers, json={"remediation_plan": "v1"}
        )
        client.patch(
            f"/api/v1/findings/{finding.id}", headers=dev_headers, json={"remediation_plan": "v2"}
        )

        logs = client.get(
            "/api/v1/audit-logs",
            headers=auth_headers("audit.viewer"),
            params={"entity_type": "finding", "entity_id": str(finding.id)},
        ).json()
        assert logs["total"] == 2
        latest = logs["items"][0]
        assert latest["actor"] == "dev.alpha"
        assert latest["before_value"] == {"remediation_plan": "v1"}
        assert latest["after_value"] == {"remediation_plan": "v2"}

    def test_empty_plan_is_rejected(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        finding = make_finding(make_version(make_application()))
        make_user("appsec.lead", Role.APPSEC)
        resp = client.patch(
            f"/api/v1/findings/{finding.id}",
            headers=auth_headers("appsec.lead"),
            json={"remediation_plan": ""},
        )
        assert resp.status_code == 422


def test_findings_require_authentication(client):
    assert client.get("/api/v1/findings").status_code == 401
    assert client.get("/api/v1/findings/summary").status_code == 401
