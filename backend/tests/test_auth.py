from app.models.user import ApprovalLevel, Role


def test_login_success(client, make_user):
    make_user("appsec.lead", Role.APPSEC, password="Passw0rd!")
    resp = client.post(
        "/api/v1/auth/login", data={"username": "appsec.lead", "password": "Passw0rd!"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_login_wrong_password(client, make_user):
    make_user("appsec.lead", Role.APPSEC, password="Passw0rd!")
    resp = client.post("/api/v1/auth/login", data={"username": "appsec.lead", "password": "wrong"})
    assert resp.status_code == 401


def test_me_requires_token(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401


def test_me_returns_current_user(client, make_user, auth_headers):
    make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha", password="Passw0rd!")
    headers = auth_headers("dev.alpha")
    resp = client.get("/api/v1/auth/me", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "dev.alpha"
    assert body["role"] == "dev_team"
    assert body["owner_team"] == "Team Alpha"
    assert body["approval_level"] == "none"


def test_me_includes_approval_level(client, make_user, auth_headers):
    # The UI decides whether to offer Checker actions from this field.
    make_user("appsec.lead", Role.APPSEC, approval_level=ApprovalLevel.L2)
    body = client.get("/api/v1/auth/me", headers=auth_headers("appsec.lead")).json()
    assert body["approval_level"] == "l2"
