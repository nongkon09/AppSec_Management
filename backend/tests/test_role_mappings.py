"""System Admin: role mappings, and what can still be edited on an Entra account."""

import pytest

from app.models.audit import AuditLog
from app.models.directory import DirectoryGroup, DirectoryGroupMember
from app.models.user import AuthSource, Role, User

GROUP = "5b0f1c2e-0000-4000-8000-00000000beef"


@pytest.fixture
def admin(make_user, auth_headers):
    make_user("sysadmin", Role.ADMIN)
    return auth_headers("sysadmin")


@pytest.fixture
def entra_member(db_session):
    user = User(
        username="somchai@corp.example",
        email="somchai@corp.example",
        full_name="Somchai",
        auth_source=AuthSource.ENTRA,
        directory_roles=[],
        hashed_password=None,
        role=None,
    )
    group = DirectoryGroup(external_id=GROUP, display_name="AppSec-Dev-Alpha")
    db_session.add_all([user, group])
    db_session.flush()
    db_session.add(DirectoryGroupMember(group_id=group.id, user_id=user.id))
    db_session.commit()
    return user


def _mapping(**extra):
    return {
        "kind": "group",
        "value": GROUP,
        "role": "dev_team",
        "owner_team": "Team Alpha",
        **extra,
    }


def test_only_admin_manages_mappings(client, make_user, auth_headers):
    make_user("appsec.lead", Role.APPSEC)
    resp = client.get("/api/v1/directory/mappings", headers=auth_headers("appsec.lead"))
    assert resp.status_code == 403


def test_creating_a_mapping_updates_members_at_once(client, admin, db_session, entra_member):
    resp = client.post("/api/v1/directory/mappings", json=_mapping(), headers=admin)
    assert resp.status_code == 201, resp.text
    assert resp.json()["users_changed"] == 1
    assert resp.json()["mapping"]["group_name"] == "AppSec-Dev-Alpha"
    db_session.expire_all()
    user = db_session.get(User, entra_member.id)
    assert user.role == Role.DEV_TEAM and user.owner_team == "Team Alpha"
    actions = {a.action for a in db_session.query(AuditLog).all()}
    assert {"role_mapping.create", "user.directory_access"} <= actions

    mapping_id = resp.json()["mapping"]["id"]
    edited = client.put(
        f"/api/v1/directory/mappings/{mapping_id}",
        json=_mapping(owner_team="Team Beta"),
        headers=admin,
    )
    assert edited.json()["users_changed"] == 1
    removed = client.delete(f"/api/v1/directory/mappings/{mapping_id}", headers=admin)
    assert removed.json()["users_changed"] == 1
    db_session.expire_all()
    assert db_session.get(User, entra_member.id).role is None


def test_mapping_rules_are_enforced(client, admin):
    no_team = client.post(
        "/api/v1/directory/mappings", json=_mapping(owner_team=None), headers=admin
    )
    assert no_team.status_code == 422
    level = client.post(
        "/api/v1/directory/mappings",
        json={"kind": "app_role", "value": "Audit", "role": "audit", "approval_level": "l2"},
        headers=admin,
    )
    assert level.status_code == 422
    client.post("/api/v1/directory/mappings", json=_mapping(), headers=admin)
    dup = client.post("/api/v1/directory/mappings", json=_mapping(), headers=admin)
    assert dup.status_code == 409


def test_status_shows_urls_without_secrets(client, admin):
    body = client.get("/api/v1/directory/status", headers=admin).json()
    assert body["redirect_uri"].endswith("/api/v1/auth/sso/callback")
    assert body["scim_url"].endswith("/api/v1/scim/v2")
    assert "secret" not in str(body).lower()


def test_groups_list_counts_members(client, admin, entra_member):
    groups = client.get("/api/v1/directory/groups", headers=admin).json()
    assert groups[0]["display_name"] == "AppSec-Dev-Alpha" and groups[0]["member_count"] == 1


def test_entra_account_role_cannot_be_edited_locally(client, admin, entra_member):
    url = f"/api/v1/users/{entra_member.id}"
    assert client.patch(url, json={"role": "admin"}, headers=admin).status_code == 422
    assert client.patch(url, json={"is_active": False}, headers=admin).status_code == 200
    reset = client.post(f"{url}/reset-password", json={"new_password": "x" * 12}, headers=admin)
    assert reset.status_code == 422


def test_user_list_shows_source_and_missing_role(client, admin, entra_member):
    items = client.get("/api/v1/users", headers=admin).json()["items"]
    entra = next(u for u in items if u["username"] == "somchai@corp.example")
    assert entra["auth_source"] == "entra" and entra["role"] is None


def test_account_view_explains_the_role(client, admin, entra_member):
    client.post("/api/v1/directory/mappings", json=_mapping(), headers=admin)
    body = client.get(f"/api/v1/directory/users/{entra_member.id}", headers=admin).json()
    assert body["groups"][0]["display_name"] == "AppSec-Dev-Alpha"
    assert body["matched"] == [f"group:{GROUP}"]
