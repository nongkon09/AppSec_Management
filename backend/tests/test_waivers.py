"""Exception/Waiver workflow tests (Requirement.md FR-6.2)."""

from datetime import UTC, datetime, timedelta

from app.models.finding import FindingStatus
from app.models.user import Role
from app.modules.waivers import service


def _create_waiver(client, headers, finding_id, expiry_date=None):
    expiry = expiry_date or (datetime.now(UTC).date() + timedelta(days=30))
    return client.post(
        f"/api/v1/findings/{finding_id}/waivers",
        headers=headers,
        json={"reason": "Compensating WAF control in place", "expiry_date": expiry.isoformat()},
    )


class TestWaiverRequest:
    def test_dev_team_requests_waiver(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application(owner_team="Team Alpha"))
        finding = make_finding(version)
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")

        resp = _create_waiver(client, auth_headers("dev.alpha"), finding.id)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "pending"
        assert body["requested_by"] == "dev.alpha"

    def test_dev_team_cannot_request_waiver_for_another_teams_finding(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application(owner_team="Team Beta"))
        finding = make_finding(version)
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")

        resp = _create_waiver(client, auth_headers("dev.alpha"), finding.id)
        assert resp.status_code == 404

    def test_management_cannot_request_waiver(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        finding = make_finding(version)
        make_user("mgmt.exec", Role.MANAGEMENT)

        resp = _create_waiver(client, auth_headers("mgmt.exec"), finding.id)
        assert resp.status_code == 403

    def test_cannot_request_a_second_waiver_while_one_is_pending(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        finding = make_finding(version)
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")

        assert _create_waiver(client, headers, finding.id).status_code == 201
        resp = _create_waiver(client, headers, finding.id)
        assert resp.status_code == 409


class TestWaiverDecision:
    def test_appsec_approves_waiver_sets_finding_risk_accepted(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        finding = make_finding(version, status=FindingStatus.OPEN)
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")

        waiver_id = _create_waiver(client, headers, finding.id).json()["id"]
        resp = client.post(f"/api/v1/waivers/{waiver_id}/approve", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"
        assert resp.json()["approved_by"] == "appsec.lead"

        finding_resp = client.get(f"/api/v1/findings/{finding.id}", headers=headers)
        assert finding_resp.json()["status"] == "risk_accepted"

    def test_appsec_rejects_waiver_leaves_finding_open(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        finding = make_finding(version, status=FindingStatus.OPEN)
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")

        waiver_id = _create_waiver(client, headers, finding.id).json()["id"]
        resp = client.post(f"/api/v1/waivers/{waiver_id}/reject", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "rejected"

        finding_resp = client.get(f"/api/v1/findings/{finding.id}", headers=headers)
        assert finding_resp.json()["status"] == "open"

    def test_dev_team_cannot_approve_waiver(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application(owner_team="Team Alpha"))
        finding = make_finding(version)
        make_user("appsec.lead", Role.APPSEC)
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")

        waiver_id = _create_waiver(client, auth_headers("appsec.lead"), finding.id).json()["id"]
        resp = client.post(
            f"/api/v1/waivers/{waiver_id}/approve", headers=auth_headers("dev.alpha")
        )
        assert resp.status_code == 403

    def test_revoking_active_waiver_reopens_finding(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        finding = make_finding(version, status=FindingStatus.OPEN)
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")

        waiver_id = _create_waiver(client, headers, finding.id).json()["id"]
        client.post(f"/api/v1/waivers/{waiver_id}/approve", headers=headers)

        resp = client.post(f"/api/v1/waivers/{waiver_id}/revoke", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

        finding_resp = client.get(f"/api/v1/findings/{finding.id}", headers=headers)
        assert finding_resp.json()["status"] == "open"


class TestWaiverExpiry:
    def test_expiry_sweep_reopens_finding_when_waiver_lapses(
        self, db_session, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        finding = make_finding(version, status=FindingStatus.OPEN)

        from app.schemas.waiver import WaiverCreate

        waiver = service.request_waiver(
            db_session,
            finding,
            WaiverCreate(reason="temp", expiry_date=datetime.now(UTC).date() - timedelta(days=1)),
            actor="dev.alpha",
        )
        service.approve_waiver(db_session, waiver, finding, actor="appsec.lead")
        assert finding.status == FindingStatus.RISK_ACCEPTED

        result = service.check_expired_waivers(db_session)
        assert result.expired_count == 1
        assert result.reopened_finding_count == 1

        db_session.refresh(finding)
        db_session.refresh(waiver)
        assert waiver.status.value == "expired"
        assert finding.status == FindingStatus.OPEN

    def test_expiry_sweep_ignores_waivers_not_yet_due(
        self, db_session, make_application, make_version, make_finding
    ):
        version = make_version(make_application())
        finding = make_finding(version, status=FindingStatus.OPEN)

        from app.schemas.waiver import WaiverCreate

        waiver = service.request_waiver(
            db_session,
            finding,
            WaiverCreate(reason="temp", expiry_date=datetime.now(UTC).date() + timedelta(days=30)),
            actor="dev.alpha",
        )
        service.approve_waiver(db_session, waiver, finding, actor="appsec.lead")

        result = service.check_expired_waivers(db_session)
        assert result.expired_count == 0
        assert result.reopened_finding_count == 0
