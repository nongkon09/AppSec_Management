"""SCIM 2.0 provisioning as the Entra ID provisioning service drives it."""

import pytest

from app.core.config import get_settings
from app.models.directory import MappingKind, RoleMapping
from app.models.user import ApprovalLevel, AuthSource, Role, User

TOKEN = "scim-test-token"
BASE = "/api/v1/scim/v2"
GROUP_ID = "5b0f1c2e-0000-4000-8000-00000000beef"


@pytest.fixture(autouse=True)
def scim_enabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "scim_bearer_token", TOKEN)


@pytest.fixture
def scim(client):
    headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/scim+json"}

    class Scim:
        def get(self, path, **kw):
            return client.get(BASE + path, headers=headers, **kw)

        def post(self, path, body):
            return client.post(BASE + path, json=body, headers=headers)

        def patch(self, path, *operations):
            body = {
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": list(operations),
            }
            return client.patch(BASE + path, json=body, headers=headers)

        def put(self, path, body):
            return client.put(BASE + path, json=body, headers=headers)

        def delete(self, path):
            return client.delete(BASE + path, headers=headers)

    return Scim()


@pytest.fixture
def dev_mapping(db_session):
    db_session.add(
        RoleMapping(
            kind=MappingKind.GROUP,
            value=GROUP_ID,
            role=Role.DEV_TEAM,
            approval_level=ApprovalLevel.NONE,
            owner_team="Team Alpha",
        )
    )
    db_session.add(
        RoleMapping(
            kind=MappingKind.APP_ROLE,
            value="AppSec.Lead",
            role=Role.APPSEC,
            approval_level=ApprovalLevel.L2,
        )
    )
    db_session.commit()


def _entra_user(username="somchai@corp.example", external_id="somchai"):
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "externalId": external_id,
        "userName": username,
        "active": True,
        "displayName": "Somchai J.",
        "emails": [{"primary": True, "type": "work", "value": username}],
        "name": {"formatted": "Somchai J.", "familyName": "J.", "givenName": "Somchai"},
    }


def _user(db_session, username):
    db_session.expire_all()
    return db_session.query(User).filter(User.username == username).one()


def test_requires_the_bearer_token(client):
    assert client.get(f"{BASE}/Users").status_code == 401
    bad = client.get(f"{BASE}/Users", headers={"Authorization": "Bearer nope"})
    assert bad.status_code == 401


def test_disabled_without_a_token(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "scim_bearer_token", "")
    assert client.get(f"{BASE}/Users", headers={"Authorization": "Bearer "}).status_code == 404


def test_entra_connection_test_filter_on_unknown_user(scim):
    resp = scim.get("/Users", params={"filter": 'userName eq "e2a3b4c5-random"'})
    assert resp.status_code == 200
    assert resp.json()["totalResults"] == 0 and resp.json()["Resources"] == []
    assert resp.headers["content-type"].startswith("application/scim+json")


def test_create_then_find_user(scim, db_session):
    created = scim.post("/Users", _entra_user())
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["userName"] == "somchai@corp.example" and body["active"] is True

    found = scim.get("/Users", params={"filter": 'userName eq "SOMCHAI@corp.example"'})
    assert found.json()["totalResults"] == 1
    assert scim.get(f"/Users/{body['id']}").json()["externalId"] == "somchai"

    user = _user(db_session, "somchai@corp.example")
    assert user.auth_source == AuthSource.ENTRA and user.hashed_password is None
    assert user.role is None  # no mapping matches yet


def test_duplicate_user_conflicts(scim):
    scim.post("/Users", _entra_user())
    again = scim.post("/Users", _entra_user())
    assert again.status_code == 409 and again.json()["scimType"] == "uniqueness"


def test_local_accounts_are_invisible_and_protected(scim, make_user):
    make_user("admin", Role.ADMIN)
    assert scim.get("/Users", params={"filter": 'userName eq "admin"'}).json()["totalResults"] == 0
    clash = scim.post("/Users", {**_entra_user("admin"), "emails": []})
    assert clash.status_code == 409


def test_group_membership_grants_the_mapped_role(scim, db_session, dev_mapping):
    user_id = scim.post("/Users", _entra_user()).json()["id"]
    group = scim.post(
        "/Groups",
        {"displayName": "AppSec-Dev-Alpha", "externalId": GROUP_ID, "members": []},
    )
    assert group.status_code == 201
    group_id = group.json()["id"]

    added = scim.patch(
        f"/Groups/{group_id}", {"op": "Add", "path": "members", "value": [{"value": user_id}]}
    )
    assert added.status_code == 204
    user = _user(db_session, "somchai@corp.example")
    assert user.role == Role.DEV_TEAM and user.owner_team == "Team Alpha"

    removed = scim.patch(
        f"/Groups/{group_id}", {"op": "Remove", "path": f'members[value eq "{user_id}"]'}
    )
    assert removed.status_code == 204
    assert _user(db_session, "somchai@corp.example").role is None


def test_app_role_assignment_via_roles_attribute(scim, db_session, dev_mapping):
    user_id = scim.post("/Users", _entra_user()).json()["id"]
    resp = scim.patch(
        f"/Users/{user_id}",
        {"op": "Add", "path": 'roles[primary eq "True"].value', "value": "AppSec.Lead"},
    )
    assert resp.status_code == 200
    user = _user(db_session, "somchai@corp.example")
    assert user.role == Role.APPSEC and user.approval_level == ApprovalLevel.L2


def test_complex_roles_on_create(scim, db_session, dev_mapping):
    body = {
        **_entra_user(),
        "roles": [
            {"primary": False, "type": "WindowsAzureActiveDirectoryRole", "value": "AppSec.Lead"}
        ],
    }
    scim.post("/Users", body)
    assert _user(db_session, "somchai@corp.example").role == Role.APPSEC


def test_disable_with_string_boolean_and_delete(scim, db_session, dev_mapping):
    user_id = scim.post("/Users", _entra_user()).json()["id"]
    resp = scim.patch(f"/Users/{user_id}", {"op": "Replace", "path": "active", "value": "False"})
    assert resp.status_code == 200 and resp.json()["active"] is False

    scim.patch(f"/Users/{user_id}", {"op": "Replace", "value": {"active": True}})
    assert _user(db_session, "somchai@corp.example").is_active is True

    assert scim.delete(f"/Users/{user_id}").status_code == 204
    assert _user(db_session, "somchai@corp.example").is_active is False
    assert scim.get(f"/Users/{user_id}").json()["active"] is False


def test_patch_profile_fields(scim, db_session):
    user_id = scim.post("/Users", _entra_user()).json()["id"]
    scim.patch(
        f"/Users/{user_id}",
        {"op": "Replace", "path": "displayName", "value": "Somchai Jaidee"},
        {"op": "Replace", "path": 'emails[type eq "work"].value', "value": "sj@corp.example"},
    )
    user = _user(db_session, "somchai@corp.example")
    assert user.full_name == "Somchai Jaidee" and user.email == "sj@corp.example"


def test_group_filter_and_excluded_members(scim):
    scim.post("/Groups", {"displayName": "AppSec-Dev-Alpha", "externalId": GROUP_ID})
    resp = scim.get(
        "/Groups",
        params={"filter": 'displayName eq "AppSec-Dev-Alpha"', "excludedAttributes": "members"},
    )
    assert resp.json()["totalResults"] == 1 and "members" not in resp.json()["Resources"][0]


def test_deleting_a_group_revokes_its_role(scim, db_session, dev_mapping):
    user_id = scim.post("/Users", _entra_user()).json()["id"]
    group_id = scim.post(
        "/Groups",
        {
            "displayName": "AppSec-Dev-Alpha",
            "externalId": GROUP_ID,
            "members": [{"value": user_id}],
        },
    ).json()["id"]
    assert _user(db_session, "somchai@corp.example").role == Role.DEV_TEAM
    assert scim.delete(f"/Groups/{group_id}").status_code == 204
    assert _user(db_session, "somchai@corp.example").role is None


def test_unknown_resource_is_404(scim):
    assert scim.get("/Users/not-a-uuid").status_code == 404
    assert scim.get("/Groups/00000000-0000-0000-0000-000000000000").status_code == 404


def test_unsupported_filter_is_400(scim):
    resp = scim.get("/Users", params={"filter": 'userName co "x"'})
    assert resp.status_code == 400 and resp.json()["scimType"] == "invalidFilter"


def test_service_provider_config(scim):
    assert scim.get("/ServiceProviderConfig").json()["patch"]["supported"] is True
