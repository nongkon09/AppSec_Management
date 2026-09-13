"""Go-Live Security Gate tests (Requirement.md FR-6.1, FR-6.3, FR-6.4)."""

from app.models.finding import FindingSource, FindingStatus, SeverityTier
from app.models.inventory import Criticality
from app.models.pentest import PentestStatus
from app.models.user import Role


class TestChecklist:
    def test_ready_when_no_blocking_findings_and_pentest_not_required(
        self, client, make_user, auth_headers, make_application, make_version
    ):
        application = make_application(criticality=Criticality.LOW)
        version = make_version(application)
        make_user("appsec.lead", Role.APPSEC)

        resp = client.get(
            f"/api/v1/app-versions/{version.id}/go-live-checklist",
            headers=auth_headers("appsec.lead"),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["sbom_pass"] is True
        assert body["sast_pass"] is True
        assert body["pentest_required"] is False
        assert body["pentest_pass"] is True
        assert body["ready"] is True

    def test_blocked_by_open_critical_sbom_finding(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        application = make_application(criticality=Criticality.LOW)
        version = make_version(application)
        make_finding(
            version,
            source=FindingSource.SBOM,
            severity_tier=SeverityTier.CRITICAL,
            status=FindingStatus.OPEN,
        )
        make_user("appsec.lead", Role.APPSEC)

        resp = client.get(
            f"/api/v1/app-versions/{version.id}/go-live-checklist",
            headers=auth_headers("appsec.lead"),
        )
        body = resp.json()
        assert body["sbom_pass"] is False
        assert body["sbom_blocking_count"] == 1
        assert body["ready"] is False

    def test_medium_severity_finding_never_blocks(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        application = make_application(criticality=Criticality.LOW)
        version = make_version(application)
        make_finding(
            version,
            source=FindingSource.SBOM,
            severity_tier=SeverityTier.MEDIUM,
            status=FindingStatus.OPEN,
        )
        make_user("appsec.lead", Role.APPSEC)

        resp = client.get(
            f"/api/v1/app-versions/{version.id}/go-live-checklist",
            headers=auth_headers("appsec.lead"),
        )
        assert resp.json()["ready"] is True

    def test_internet_facing_application_requires_pentest(
        self, client, db_session, make_user, auth_headers, make_application, make_version
    ):
        application = make_application(criticality=Criticality.LOW)
        application.internet_facing = True
        db_session.commit()
        version = make_version(application)
        make_user("appsec.lead", Role.APPSEC)

        resp = client.get(
            f"/api/v1/app-versions/{version.id}/go-live-checklist",
            headers=auth_headers("appsec.lead"),
        )
        body = resp.json()
        assert body["pentest_required"] is True
        assert body["pentest_pass"] is False
        assert body["ready"] is False

    def test_pentest_passes_once_project_closed_with_no_blocking_findings(
        self,
        client,
        make_user,
        auth_headers,
        make_application,
        make_version,
        make_pentest_project,
    ):
        application = make_application(criticality=Criticality.CRITICAL)
        version = make_version(application)
        make_pentest_project(version, status=PentestStatus.CLOSED)
        make_user("appsec.lead", Role.APPSEC)

        resp = client.get(
            f"/api/v1/app-versions/{version.id}/go-live-checklist",
            headers=auth_headers("appsec.lead"),
        )
        body = resp.json()
        assert body["pentest_required"] is True
        assert body["pentest_pass"] is True
        assert body["ready"] is True

    def test_dev_team_cannot_see_another_teams_checklist(
        self, client, make_user, auth_headers, make_application, make_version
    ):
        version = make_version(make_application(owner_team="Team Beta"))
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")

        resp = client.get(
            f"/api/v1/app-versions/{version.id}/go-live-checklist",
            headers=auth_headers("dev.alpha"),
        )
        assert resp.status_code == 404


class TestApproval:
    def test_approval_blocked_when_checklist_not_ready(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        application = make_application(criticality=Criticality.LOW)
        version = make_version(application)
        make_finding(
            version,
            source=FindingSource.SAST,
            severity_tier=SeverityTier.HIGH,
            status=FindingStatus.OPEN,
        )
        make_user("appsec.lead", Role.APPSEC)

        resp = client.post(
            f"/api/v1/app-versions/{version.id}/go-live-approve",
            headers=auth_headers("appsec.lead"),
        )
        assert resp.status_code == 422

    def test_approval_succeeds_and_is_recorded_when_ready(
        self, client, make_user, auth_headers, make_application, make_version
    ):
        application = make_application(criticality=Criticality.LOW)
        version = make_version(application)
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")

        resp = client.post(f"/api/v1/app-versions/{version.id}/go-live-approve", headers=headers)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["sbom_pass"] is True
        assert body["approver"] == "appsec.lead"
        assert body["is_break_glass"] is False

        history = client.get(
            f"/api/v1/app-versions/{version.id}/go-live-history", headers=headers
        ).json()
        assert len(history) == 1

    def test_dev_team_cannot_approve(
        self, client, make_user, auth_headers, make_application, make_version
    ):
        version = make_version(make_application(owner_team="Team Alpha"))
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")

        resp = client.post(
            f"/api/v1/app-versions/{version.id}/go-live-approve",
            headers=auth_headers("dev.alpha"),
        )
        assert resp.status_code == 403
