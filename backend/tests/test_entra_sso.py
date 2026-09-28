"""Sign-in with Entra ID (OIDC code flow) with the Microsoft endpoints replaced by a
locally generated signing key."""

import time
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import get_settings
from app.models.audit import AuditLog
from app.models.directory import MappingKind, RoleMapping
from app.models.user import ApprovalLevel, AuthSource, Role, User
from app.modules.directory import entra

TENANT = "0b1c2d3e-0000-4000-8000-000000000001"
CLIENT = "a1b2c3d4-0000-4000-8000-000000000002"
DEV_GROUP = "5b0f1c2e-0000-4000-8000-00000000beef"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def entra_enabled(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "entra_tenant_id", TENANT)
    monkeypatch.setattr(settings, "entra_client_id", CLIENT)
    monkeypatch.setattr(settings, "entra_client_secret", "secret")
    monkeypatch.setattr(settings, "app_public_url", "http://app.test")
    monkeypatch.setattr(settings, "api_public_url", "http://testserver")
    monkeypatch.setattr(settings, "entra_jit_provisioning", True)
    monkeypatch.setattr(settings, "local_login_enabled", True)
    monkeypatch.setattr(entra, "signing_key", lambda token: KEY.public_key())


@pytest.fixture
def mappings(db_session):
    db_session.add_all(
        [
            RoleMapping(
                kind=MappingKind.GROUP,
                value=DEV_GROUP,
                role=Role.DEV_TEAM,
                approval_level=ApprovalLevel.NONE,
                owner_team="Team Alpha",
            ),
            RoleMapping(
                kind=MappingKind.APP_ROLE,
                value="Mgmt.RiskExec",
                role=Role.MANAGEMENT,
                approval_level=ApprovalLevel.L3,
            ),
        ]
    )
    db_session.commit()


def _id_token(nonce, **claims):
    now = int(time.time())
    body = {
        "iss": f"https://login.microsoftonline.com/{TENANT}/v2.0",
        "aud": CLIENT,
        "sub": "pairwise-sub",
        "tid": TENANT,
        "oid": "11111111-2222-3333-4444-555555555555",
        "preferred_username": "Somchai@corp.example",
        "name": "Somchai J.",
        "nonce": nonce,
        "iat": now,
        "exp": now + 600,
        **claims,
    }
    return jwt.encode(body, KEY, algorithm="RS256")


def _sign_in(client, monkeypatch, *, token_claims=None, tamper_state=False, nonce=None):
    start = client.get("/api/v1/auth/sso/login", follow_redirects=False)
    assert start.status_code == 302
    query = parse_qs(urlparse(start.headers["location"]).query)
    assert query["code_challenge_method"] == ["S256"]
    assert query["redirect_uri"] == ["http://testserver/api/v1/auth/sso/callback"]
    token = _id_token(nonce or query["nonce"][0], **(token_claims or {}))
    monkeypatch.setattr(entra, "exchange_code", lambda code, verifier: {"id_token": token})
    state = "forged" if tamper_state else query["state"][0]
    back = client.get(
        "/api/v1/auth/sso/callback", params={"code": "c", "state": state}, follow_redirects=False
    )
    assert back.status_code == 302
    location = back.headers["location"]
    assert location.startswith("http://app.test/login/sso#")
    return dict(part.split("=", 1) for part in location.split("#", 1)[1].split("&"))


def test_config_is_public(client):
    assert client.get("/api/v1/auth/sso/config").json() == {
        "enabled": True,
        "local_login_enabled": True,
    }


def test_group_member_signs_in_and_gets_the_mapped_role(client, db_session, monkeypatch, mappings):
    result = _sign_in(client, monkeypatch, token_claims={"groups": [DEV_GROUP]})
    assert "token" in result
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {result['token']}"})
    assert me.json()["role"] == "dev_team" and me.json()["owner_team"] == "Team Alpha"
    assert me.json()["auth_source"] == "entra"
    user = db_session.query(User).filter(User.username == "somchai@corp.example").one()
    assert user.entra_object_id and user.hashed_password is None and user.last_login_at
    assert db_session.query(AuditLog).filter(AuditLog.action == "user.create").count() == 1


def test_app_role_claim_gives_checker_level(client, db_session, monkeypatch, mappings):
    result = _sign_in(client, monkeypatch, token_claims={"roles": ["Mgmt.RiskExec"]})
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {result['token']}"})
    assert me.json()["role"] == "management" and me.json()["approval_level"] == "l3"


def test_no_mapping_is_refused_and_no_account_is_kept(client, db_session, monkeypatch, mappings):
    assert _sign_in(client, monkeypatch, token_claims={"groups": ["other"]}) == {
        "error": "not_assigned"
    }
    assert db_session.query(User).count() == 0


def test_removed_from_group_loses_access_at_next_request(client, db_session, monkeypatch, mappings):
    token = _sign_in(client, monkeypatch, token_claims={"groups": [DEV_GROUP]})["token"]
    _sign_in(client, monkeypatch, token_claims={"groups": []})  # signs in again, no groups
    resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401


def test_forged_state_is_rejected(client, monkeypatch, mappings):
    assert _sign_in(client, monkeypatch, tamper_state=True) == {"error": "sso_failed"}


def test_wrong_nonce_is_rejected(client, monkeypatch, mappings):
    result = _sign_in(client, monkeypatch, nonce="replayed", token_claims={"groups": [DEV_GROUP]})
    assert result == {"error": "sso_failed"}


def test_token_from_another_tenant_is_rejected(client, monkeypatch, mappings):
    result = _sign_in(client, monkeypatch, token_claims={"tid": "evil", "groups": [DEV_GROUP]})
    assert result == {"error": "sso_failed"}


def test_never_takes_over_a_local_account(client, monkeypatch, make_user, mappings):
    make_user("somchai@corp.example", Role.ADMIN)
    result = _sign_in(client, monkeypatch, token_claims={"groups": [DEV_GROUP]})
    assert result == {"error": "local_conflict"}


def test_without_jit_only_provisioned_accounts_get_in(client, monkeypatch, mappings):
    monkeypatch.setattr(get_settings(), "entra_jit_provisioning", False)
    result = _sign_in(client, monkeypatch, token_claims={"groups": [DEV_GROUP]})
    assert result == {"error": "not_provisioned"}


def test_scim_provisioned_account_is_linked_on_first_sign_in(
    client, db_session, monkeypatch, mappings
):
    db_session.add(
        User(
            username="somchai@corp.example",
            email="somchai@corp.example",
            full_name="S",
            auth_source=AuthSource.ENTRA,
            directory_roles=[],
            hashed_password=None,
            role=None,
        )
    )
    db_session.commit()
    result = _sign_in(client, monkeypatch, token_claims={"groups": [DEV_GROUP]})
    assert "token" in result
    assert db_session.query(User).count() == 1


def test_disabled_account_is_refused(client, db_session, monkeypatch, mappings):
    _sign_in(client, monkeypatch, token_claims={"groups": [DEV_GROUP]})
    db_session.query(User).update({User.is_active: False})
    db_session.commit()
    assert _sign_in(client, monkeypatch, token_claims={"groups": [DEV_GROUP]}) == {
        "error": "inactive"
    }


def test_entra_account_cannot_use_password_login(client, db_session, monkeypatch, mappings):
    _sign_in(client, monkeypatch, token_claims={"groups": [DEV_GROUP]})
    resp = client.post(
        "/api/v1/auth/login", data={"username": "somchai@corp.example", "password": "x" * 10}
    )
    assert resp.status_code == 401


def test_local_login_off_keeps_break_glass_admin(client, monkeypatch, make_user):
    monkeypatch.setattr(get_settings(), "local_login_enabled", False)
    make_user("admin", Role.ADMIN)
    make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
    login = "/api/v1/auth/login"
    allowed = client.post(login, data={"username": "admin", "password": "Passw0rd!"})
    assert allowed.status_code == 200
    blocked = client.post(login, data={"username": "dev.alpha", "password": "Passw0rd!"})
    assert blocked.status_code == 403


def test_sso_endpoints_hidden_when_not_configured(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "entra_client_secret", "")
    assert client.get("/api/v1/auth/sso/login", follow_redirects=False).status_code == 404
    assert client.get("/api/v1/auth/sso/config").json()["enabled"] is False
