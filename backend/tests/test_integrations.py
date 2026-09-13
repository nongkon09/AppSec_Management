"""ITSM Connector configuration + ticket lifecycle tests (Requirement.md FR-7).

Ticket creation/routing/auto-close never call a real Jira — `app.modules.integrations
.service.build_connector` is monkeypatched to a `FakeTicketConnector`, exactly the same
technique the SBOM sync tests use for `SCAConnector`: the reconciliation logic is
independent of which ITSM platform the connector talks to.
"""

from datetime import date

import pytest

from app.models.finding import FindingStatus
from app.models.ticket import Ticket
from app.models.user import Role
from app.modules.integrations import service


class FakeTicketConnector:
    """A minimal `TicketConnector` double."""

    def __init__(self, should_fail: bool = False):
        self.should_fail = should_fail
        self.created: list = []
        self.closed: list = []

    def create_ticket(self, draft) -> str:
        if self.should_fail:
            raise RuntimeError("simulated ITSM outage")
        external_id = f"FAKE-{len(self.created) + 1}"
        self.created.append((external_id, draft))
        return external_id

    def attach_comment(self, external_id: str, comment: str) -> None:
        pass

    def update_ticket(self, external_id: str, *, comment: str | None = None) -> None:
        pass

    def close_ticket(self, external_id: str, *, resolution: str, comment: str) -> None:
        if self.should_fail:
            raise RuntimeError("simulated ITSM outage")
        self.closed.append((external_id, resolution, comment))

    def get_ticket_status(self, external_id: str) -> str:
        return "open"


@pytest.fixture
def fake_connector_impl(monkeypatch):
    """Patches the factory so `create_ticket`/routing/auto-close never call a real
    connector; returns the fake so a test can assert on what it recorded."""
    fake = FakeTicketConnector()
    monkeypatch.setattr(service, "build_connector", lambda _connector: fake)
    return fake


def _connector_payload(**overrides):
    payload = {
        "name": "Jira - Security",
        "connector_type": "jira",
        "base_url": "https://example.atlassian.net",
        "auth_token": "user@example.com:secret-token",
        "config": {"project_key": "SEC"},
        "routing_severities": ["critical", "high"],
        "is_enabled": True,
    }
    payload.update(overrides)
    return payload


class TestConnectorCrud:
    def test_admin_creates_connector(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        resp = client.post(
            "/api/v1/integrations/connectors",
            headers=auth_headers("sysadmin"),
            json=_connector_payload(),
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["name"] == "Jira - Security"
        assert body["connector_type"] == "jira"
        assert body["routing_severities"] == ["critical", "high"]
        assert "auth_token" not in body
        assert body["auth_token_configured"] is True

    def test_appsec_cannot_create_update_or_delete_connectors(
        self, client, make_user, auth_headers
    ):
        """Section 4: Integration Connector Configuration (create/edit/delete, which
        includes the stored credential) is Admin-only, distinct from AppSec's own
        Policy/Waiver ownership."""
        make_user("sysadmin", Role.ADMIN)
        connector_id = client.post(
            "/api/v1/integrations/connectors",
            headers=auth_headers("sysadmin"),
            json=_connector_payload(),
        ).json()["id"]

        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")
        assert (
            client.post(
                "/api/v1/integrations/connectors", headers=headers, json=_connector_payload()
            ).status_code
            == 403
        )
        assert (
            client.patch(
                f"/api/v1/integrations/connectors/{connector_id}",
                headers=headers,
                json={"is_enabled": False},
            ).status_code
            == 403
        )
        assert (
            client.delete(
                f"/api/v1/integrations/connectors/{connector_id}", headers=headers
            ).status_code
            == 403
        )

    def test_appsec_can_list_connectors_to_pick_one_for_a_manual_ticket(
        self, client, make_user, auth_headers
    ):
        """FR-7.8: AppSec needs to see which connectors exist to create a ticket
        manually from a Finding, even though only Admin can configure one."""
        make_user("sysadmin", Role.ADMIN)
        client.post(
            "/api/v1/integrations/connectors",
            headers=auth_headers("sysadmin"),
            json=_connector_payload(),
        )
        make_user("appsec.lead", Role.APPSEC)
        resp = client.get("/api/v1/integrations/connectors", headers=auth_headers("appsec.lead"))
        assert resp.status_code == 200
        assert len(resp.json()) == 1
        assert "auth_token" not in resp.json()[0]

    def test_dev_team_cannot_list_connectors(self, client, make_user, auth_headers):
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.get("/api/v1/integrations/connectors", headers=auth_headers("dev.alpha"))
        assert resp.status_code == 403

    def test_anonymous_cannot_list_connectors(self, client):
        assert client.get("/api/v1/integrations/connectors").status_code == 401

    def test_admin_updates_and_disables_connector(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        connector_id = client.post(
            "/api/v1/integrations/connectors", headers=headers, json=_connector_payload()
        ).json()["id"]

        resp = client.patch(
            f"/api/v1/integrations/connectors/{connector_id}",
            headers=headers,
            json={"is_enabled": False, "routing_severities": ["critical"]},
        )
        assert resp.status_code == 200
        assert resp.json()["is_enabled"] is False
        assert resp.json()["routing_severities"] == ["critical"]

    def test_admin_deletes_connector(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        connector_id = client.post(
            "/api/v1/integrations/connectors", headers=headers, json=_connector_payload()
        ).json()["id"]

        resp = client.delete(f"/api/v1/integrations/connectors/{connector_id}", headers=headers)
        assert resp.status_code == 204
        assert client.get("/api/v1/integrations/connectors", headers=headers).json() == []

    def test_create_connector_is_audited_without_leaking_token(
        self, client, make_user, auth_headers
    ):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        connector_id = client.post(
            "/api/v1/integrations/connectors", headers=headers, json=_connector_payload()
        ).json()["id"]

        logs = client.get(
            "/api/v1/audit-logs",
            headers=headers,
            params={"entity_type": "integration_connector", "entity_id": connector_id},
        ).json()
        assert logs["total"] == 1
        after = logs["items"][0]["after_value"]
        assert "auth_token" not in after
        assert "secret-token" not in str(logs["items"][0])


class TestManualTicketCreation:
    def test_appsec_creates_ticket_manually(
        self,
        client,
        make_user,
        auth_headers,
        make_application,
        make_version,
        make_finding,
        fake_connector_impl,
        db_session,
    ):
        """FR-7.8: manual ticket creation from a Finding."""
        finding = make_finding(make_version(make_application()))
        make_user("sysadmin", Role.ADMIN)
        connector_id = client.post(
            "/api/v1/integrations/connectors",
            headers=auth_headers("sysadmin"),
            json=_connector_payload(routing_severities=[]),  # manual-only
        ).json()["id"]

        make_user("appsec.lead", Role.APPSEC)
        resp = client.post(
            f"/api/v1/findings/{finding.id}/tickets",
            headers=auth_headers("appsec.lead"),
            json={"connector_id": connector_id},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "open"
        assert body["external_id"] == "FAKE-1"
        assert len(fake_connector_impl.created) == 1

    def test_ticket_content_includes_fr73_fields(
        self,
        client,
        make_user,
        auth_headers,
        make_application,
        make_version,
        make_component,
        make_finding,
        fake_connector_impl,
        db_session,
    ):
        """FR-7.3: library/version, fixed version, CVE, due date, affected app/version."""
        application = make_application(app_name="Customer Web Portal")
        version = make_version(application, version_label="2026.9.1")
        component = make_component(version, component_name="log4j-core", component_version="2.14.1")
        finding = make_finding(
            version, component=component, cve_id="CVE-2021-44228", due_date=date(2026, 9, 20)
        )
        # The HTTP client below runs its request in its own DB session (a separate
        # connection to the same test database) — this must be committed, not just set
        # on the in-memory object, or the request will not see it.
        finding.fixed_version = "2.17.1"
        db_session.commit()

        make_user("sysadmin", Role.ADMIN)
        connector_id = client.post(
            "/api/v1/integrations/connectors",
            headers=auth_headers("sysadmin"),
            json=_connector_payload(routing_severities=[]),
        ).json()["id"]
        make_user("appsec.lead", Role.APPSEC)
        client.post(
            f"/api/v1/findings/{finding.id}/tickets",
            headers=auth_headers("appsec.lead"),
            json={"connector_id": connector_id},
        )

        _, draft = fake_connector_impl.created[0]
        assert "CVE-2021-44228" in draft.summary
        assert "Customer Web Portal" in draft.description
        assert "2026.9.1" in draft.description
        assert "log4j-core 2.14.1" in draft.description
        assert "2.17.1" in draft.description
        assert draft.due_date == "2026-09-20"

    def test_dev_team_cannot_create_ticket(
        self, client, make_user, auth_headers, make_application, make_version, make_finding
    ):
        finding = make_finding(make_version(make_application(owner_team="Team Alpha")))
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.post(
            f"/api/v1/findings/{finding.id}/tickets",
            headers=auth_headers("dev.alpha"),
            json={"connector_id": "00000000-0000-0000-0000-000000000000"},
        )
        assert resp.status_code == 403

    def test_manual_creation_failure_is_recorded_not_raised(
        self,
        client,
        make_user,
        auth_headers,
        make_application,
        make_version,
        make_finding,
        monkeypatch,
    ):
        """FR-7.7: a failed push is recorded on the Ticket (status=error, last_error
        set) rather than surfacing as a 500 or silently vanishing."""
        failing = FakeTicketConnector(should_fail=True)
        monkeypatch.setattr(service, "build_connector", lambda _connector: failing)

        finding = make_finding(make_version(make_application()))
        make_user("sysadmin", Role.ADMIN)
        connector_id = client.post(
            "/api/v1/integrations/connectors",
            headers=auth_headers("sysadmin"),
            json=_connector_payload(routing_severities=[]),
        ).json()["id"]
        make_user("appsec.lead", Role.APPSEC)
        resp = client.post(
            f"/api/v1/findings/{finding.id}/tickets",
            headers=auth_headers("appsec.lead"),
            json={"connector_id": connector_id},
        )
        assert resp.status_code == 201  # the API call itself succeeds...
        body = resp.json()
        assert body["status"] == "error"  # ...but the failure is visible on the ticket
        assert "simulated ITSM outage" in body["last_error"]

    def test_finding_tickets_are_listed(
        self,
        client,
        make_user,
        auth_headers,
        make_application,
        make_version,
        make_finding,
        fake_connector_impl,
    ):
        """FR-7.4: cross-reference view of every ticket raised for a Finding."""
        finding = make_finding(make_version(make_application()))
        make_user("sysadmin", Role.ADMIN)
        connector_id = client.post(
            "/api/v1/integrations/connectors",
            headers=auth_headers("sysadmin"),
            json=_connector_payload(routing_severities=[]),
        ).json()["id"]
        make_user("appsec.lead", Role.APPSEC)
        headers = auth_headers("appsec.lead")
        client.post(
            f"/api/v1/findings/{finding.id}/tickets",
            headers=headers,
            json={"connector_id": connector_id},
        )
        resp = client.get(f"/api/v1/findings/{finding.id}/tickets", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()) == 1
        assert resp.json()[0]["external_id"] == "FAKE-1"


class TestAutomaticRouting:
    def test_new_finding_routes_to_matching_connector(
        self, db_session, make_application, make_version, fake_connector_impl
    ):
        """FR-7.2: a Finding at a routed Severity Tier automatically raises a ticket."""
        from app.modules.findings import service as findings_service
        from app.schemas.finding import FindingCreate

        connector_payload = _connector_payload(routing_severities=["high"])
        from app.schemas.integration import ConnectorCreate

        connector = service.create_connector(
            db_session, ConnectorCreate(**connector_payload), actor="sysadmin"
        )

        version = make_version(make_application())
        finding = findings_service.create_finding(
            db_session,
            FindingCreate(
                app_version_id=version.id,
                source="sast",
                title="Reflected XSS",
                severity_tier="high",
            ),
            actor="appsec.lead",
        )

        tickets = db_session.query(Ticket).filter_by(finding_id=finding.id).all()
        assert len(tickets) == 1
        assert tickets[0].connector_id == connector.id
        assert len(fake_connector_impl.created) == 1

    def test_finding_below_routed_severity_creates_no_ticket(
        self, db_session, make_application, make_version, fake_connector_impl
    ):
        from app.modules.findings import service as findings_service
        from app.schemas.finding import FindingCreate
        from app.schemas.integration import ConnectorCreate

        service.create_connector(
            db_session,
            ConnectorCreate(**_connector_payload(routing_severities=["critical"])),
            actor="sysadmin",
        )

        version = make_version(make_application())
        finding = findings_service.create_finding(
            db_session,
            FindingCreate(
                app_version_id=version.id,
                source="sast",
                title="Low-severity info leak",
                severity_tier="low",
            ),
            actor="appsec.lead",
        )

        assert db_session.query(Ticket).filter_by(finding_id=finding.id).count() == 0
        assert len(fake_connector_impl.created) == 0

    def test_disabled_connector_is_not_routed_to(
        self, db_session, make_application, make_version, fake_connector_impl
    ):
        from app.modules.findings import service as findings_service
        from app.schemas.finding import FindingCreate
        from app.schemas.integration import ConnectorCreate

        service.create_connector(
            db_session,
            ConnectorCreate(
                **_connector_payload(routing_severities=["critical"], is_enabled=False)
            ),
            actor="sysadmin",
        )

        version = make_version(make_application())
        finding = findings_service.create_finding(
            db_session,
            FindingCreate(
                app_version_id=version.id, source="sast", title="X", severity_tier="critical"
            ),
            actor="appsec.lead",
        )
        assert db_session.query(Ticket).filter_by(finding_id=finding.id).count() == 0

    def test_routing_is_idempotent_per_connector(
        self, db_session, make_application, make_version, make_finding, fake_connector_impl
    ):
        from app.schemas.integration import ConnectorCreate

        connector = service.create_connector(
            db_session,
            ConnectorCreate(**_connector_payload(routing_severities=["critical"])),
            actor="sysadmin",
        )
        finding = make_finding(make_version(make_application()), severity_tier="critical")

        service.route_finding_to_connectors(db_session, finding)
        service.route_finding_to_connectors(db_session, finding)  # called again

        tickets = (
            db_session.query(Ticket)
            .filter_by(finding_id=finding.id, connector_id=connector.id)
            .all()
        )
        assert len(tickets) == 1


class TestAutoClose:
    def test_fixed_finding_closes_its_open_ticket(
        self, db_session, make_application, make_version, make_finding, fake_connector_impl
    ):
        """FR-7.5: auto-verified fix closes the linked ticket."""
        from app.schemas.integration import ConnectorCreate

        connector = service.create_connector(
            db_session, ConnectorCreate(**_connector_payload()), actor="sysadmin"
        )
        finding = make_finding(make_version(make_application()), severity_tier="critical")
        ticket = Ticket(
            finding_id=finding.id,
            connector_id=connector.id,
            external_system="jira",
            external_id="FAKE-1",
            status="open",
        )
        db_session.add(ticket)
        db_session.commit()

        finding.status = FindingStatus.FIXED
        db_session.commit()

        closed = service.on_finding_fixed(db_session, finding)
        assert len(closed) == 1
        db_session.refresh(ticket)
        assert ticket.status == "done"
        assert ("FAKE-1", "done", "Auto-verified by SBOM re-scan") in fake_connector_impl.closed

    def test_close_failure_is_recorded_not_raised(
        self, db_session, make_application, make_version, make_finding, monkeypatch
    ):
        failing = FakeTicketConnector(should_fail=True)
        monkeypatch.setattr(service, "build_connector", lambda _connector: failing)
        from app.schemas.integration import ConnectorCreate

        connector = service.create_connector(
            db_session, ConnectorCreate(**_connector_payload()), actor="sysadmin"
        )
        finding = make_finding(make_version(make_application()))
        ticket = Ticket(
            finding_id=finding.id,
            connector_id=connector.id,
            external_system="jira",
            external_id="FAKE-1",
            status="open",
        )
        db_session.add(ticket)
        db_session.commit()
        finding.status = FindingStatus.FIXED
        db_session.commit()

        service.on_finding_fixed(db_session, finding)
        db_session.refresh(ticket)
        assert ticket.status == "error"
        assert "simulated ITSM outage" in ticket.last_error

    def test_open_finding_is_not_closed(
        self, db_session, make_application, make_version, make_finding, fake_connector_impl
    ):
        """on_finding_fixed is a no-op unless the Finding's status is actually FIXED."""
        finding = make_finding(make_version(make_application()))
        closed = service.on_finding_fixed(db_session, finding)
        assert closed == []
