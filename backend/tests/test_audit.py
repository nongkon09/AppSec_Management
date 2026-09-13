"""Audit Trail API tests (Requirement.md FR-11, FR-10.4)."""

import csv
import io
from datetime import UTC, datetime, timedelta

import pytest

from app.core.audit import record_audit
from app.models.user import Role


@pytest.fixture
def seeded_audit_log(db_session):
    """Three entries spread over three days, for range-filter and ordering assertions."""
    now = datetime.now(UTC)
    entries = [
        ("policy.publish_version", "appsec.lead", "policy_set", "p-1", now - timedelta(days=2)),
        ("finding.update_remediation_plan", "dev.alpha", "finding", "f-1", now - timedelta(days=1)),
        ("finding.create_manual", "appsec.lead", "finding", "f-2", now),
    ]
    for action, actor, entity_type, entity_id, timestamp in entries:
        entry = record_audit(
            db_session,
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            before={"value": "old"},
            after={"value": "new"},
        )
        entry.timestamp = timestamp
    db_session.commit()
    return entries


class TestAuditAccess:
    @pytest.mark.parametrize("role", [Role.AUDIT, Role.APPSEC, Role.ADMIN])
    def test_permitted_roles_can_read(self, client, make_user, auth_headers, role):
        make_user(f"user.{role.value}", role)
        resp = client.get("/api/v1/audit-logs", headers=auth_headers(f"user.{role.value}"))
        assert resp.status_code == 200

    @pytest.mark.parametrize("role", [Role.DEV_TEAM, Role.LEGAL, Role.MANAGEMENT])
    def test_other_roles_are_rejected(self, client, make_user, auth_headers, role):
        """Section 4: the audit trail is for Compliance/Audit, AppSec and System Admin."""
        make_user(f"user.{role.value}", role, owner_team="Team Alpha")
        resp = client.get("/api/v1/audit-logs", headers=auth_headers(f"user.{role.value}"))
        assert resp.status_code == 403

    def test_anonymous_is_rejected(self, client):
        assert client.get("/api/v1/audit-logs").status_code == 401

    def test_no_write_endpoints_are_exposed(self, client, make_user, auth_headers):
        """FR-11.1 immutability: the API offers no way to alter or delete an entry."""
        make_user("audit.viewer", Role.AUDIT)
        headers = auth_headers("audit.viewer")
        assert client.post("/api/v1/audit-logs", headers=headers, json={}).status_code == 405
        assert client.delete("/api/v1/audit-logs", headers=headers).status_code == 405


class TestAuditFilters:
    def test_newest_entry_comes_first(self, client, make_user, auth_headers, seeded_audit_log):
        make_user("audit.viewer", Role.AUDIT)
        body = client.get("/api/v1/audit-logs", headers=auth_headers("audit.viewer")).json()
        assert body["total"] == 3
        assert [item["action"] for item in body["items"]] == [
            "finding.create_manual",
            "finding.update_remediation_plan",
            "policy.publish_version",
        ]

    def test_filter_by_entity(self, client, make_user, auth_headers, seeded_audit_log):
        make_user("audit.viewer", Role.AUDIT)
        headers = auth_headers("audit.viewer")
        by_type = client.get(
            "/api/v1/audit-logs", headers=headers, params={"entity_type": "finding"}
        ).json()
        assert by_type["total"] == 2
        by_id = client.get(
            "/api/v1/audit-logs", headers=headers, params={"entity_id": "f-2"}
        ).json()
        assert by_id["total"] == 1

    def test_filter_by_actor_and_action(self, client, make_user, auth_headers, seeded_audit_log):
        make_user("audit.viewer", Role.AUDIT)
        headers = auth_headers("audit.viewer")
        by_actor = client.get(
            "/api/v1/audit-logs", headers=headers, params={"actor": "dev.alpha"}
        ).json()
        assert by_actor["total"] == 1
        by_action = client.get(
            "/api/v1/audit-logs", headers=headers, params={"action": "policy."}
        ).json()
        assert by_action["total"] == 1

    def test_date_range_is_inclusive_of_both_ends(
        self, client, make_user, auth_headers, seeded_audit_log
    ):
        """FR-11.2: "export ตามช่วงเวลา" must include entries on the boundary days."""
        make_user("audit.viewer", Role.AUDIT)
        headers = auth_headers("audit.viewer")
        today = datetime.now(UTC).date()

        only_today = client.get(
            "/api/v1/audit-logs",
            headers=headers,
            params={"date_from": today.isoformat(), "date_to": today.isoformat()},
        ).json()
        assert only_today["total"] == 1

        whole_window = client.get(
            "/api/v1/audit-logs",
            headers=headers,
            params={
                "date_from": (today - timedelta(days=2)).isoformat(),
                "date_to": today.isoformat(),
            },
        ).json()
        assert whole_window["total"] == 3


class TestAuditExport:
    def test_export_returns_csv_with_all_columns(
        self, client, make_user, auth_headers, seeded_audit_log
    ):
        make_user("audit.viewer", Role.AUDIT)
        resp = client.get("/api/v1/audit-logs/export", headers=auth_headers("audit.viewer"))
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert "attachment; filename=" in resp.headers["content-disposition"]

        rows = list(csv.reader(io.StringIO(resp.text)))
        assert rows[0] == [
            "timestamp",
            "actor",
            "action",
            "entity_type",
            "entity_id",
            "before_value",
            "after_value",
        ]
        # Oldest first, so the export reads as a chronological history.
        assert [row[2] for row in rows[1:]] == [
            "policy.publish_version",
            "finding.update_remediation_plan",
            "finding.create_manual",
        ]
        assert rows[1][5] == '{"value": "old"}'

    def test_export_honours_filters(self, client, make_user, auth_headers, seeded_audit_log):
        make_user("audit.viewer", Role.AUDIT)
        resp = client.get(
            "/api/v1/audit-logs/export",
            headers=auth_headers("audit.viewer"),
            params={"entity_type": "policy_set"},
        )
        rows = list(csv.reader(io.StringIO(resp.text)))
        assert len(rows) == 2  # header + one entry

    def test_export_is_denied_to_dev_team(self, client, make_user, auth_headers):
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.get("/api/v1/audit-logs/export", headers=auth_headers("dev.alpha"))
        assert resp.status_code == 403
