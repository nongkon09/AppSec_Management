"""VEX status + Global Suppression tests (Requirement.md FR-8.1-8.3)."""

from app.models.finding import FindingStatus
from app.models.user import Role


class TestVexUpdate:
    def test_appsec_marks_not_affected_suppresses_finding(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        finding = make_finding(version, status=FindingStatus.OPEN)
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")

        resp = client.patch(
            f"/api/v1/findings/{finding.id}/vex",
            headers=headers,
            json={"vex_status": "not_affected", "vex_justification": "component_not_present"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["vex_status"] == "not_affected"
        assert resp.json()["status"] == "suppressed"

    def test_reverting_to_affected_reopens_a_suppressed_finding(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        finding = make_finding(version, status=FindingStatus.OPEN)
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")

        client.patch(
            f"/api/v1/findings/{finding.id}/vex",
            headers=headers,
            json={"vex_status": "not_affected", "vex_justification": "component_not_present"},
        )
        resp = client.patch(
            f"/api/v1/findings/{finding.id}/vex",
            headers=headers,
            json={"vex_status": "affected"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "open"

    def test_dev_team_cannot_update_vex(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application(owner_team="Team Alpha"))
        finding = make_finding(version)
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")

        resp = client.patch(
            f"/api/v1/findings/{finding.id}/vex",
            headers=auth_headers("dev.alpha"),
            json={"vex_status": "not_affected"},
        )
        assert resp.status_code == 403


class TestGlobalVexSuppression:
    def test_suppresses_every_open_finding_sharing_the_cve_across_applications(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        v1 = make_version(make_application(app_name="App One"))
        v2 = make_version(make_application(app_name="App Two"))
        f1 = make_finding(v1, cve_id="CVE-2024-9999", status=FindingStatus.OPEN)
        f2 = make_finding(v2, cve_id="CVE-2024-9999", status=FindingStatus.OPEN)
        # A different CVE must be left untouched.
        f3 = make_finding(v2, cve_id="CVE-2024-0000", status=FindingStatus.OPEN)

        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")
        resp = client.post(
            "/api/v1/findings/vex/global-suppress",
            headers=headers,
            json={
                "cve_id": "CVE-2024-9999",
                "vex_status": "not_affected",
                "vex_justification": "vulnerable_code_not_in_execute_path",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["affected_finding_count"] == 2

        assert client.get(f"/api/v1/findings/{f1.id}", headers=headers).json()["status"] == (
            "suppressed"
        )
        assert client.get(f"/api/v1/findings/{f2.id}", headers=headers).json()["status"] == (
            "suppressed"
        )
        assert client.get(f"/api/v1/findings/{f3.id}", headers=headers).json()["status"] == "open"

    def test_dev_team_cannot_global_suppress(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application(owner_team="Team Alpha"))
        make_finding(version, cve_id="CVE-2024-1111")
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")

        resp = client.post(
            "/api/v1/findings/vex/global-suppress",
            headers=auth_headers("dev.alpha"),
            json={"cve_id": "CVE-2024-1111", "vex_status": "not_affected"},
        )
        assert resp.status_code == 403
