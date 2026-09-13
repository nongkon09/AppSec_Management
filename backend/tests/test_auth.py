from app.models.user import Role


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
