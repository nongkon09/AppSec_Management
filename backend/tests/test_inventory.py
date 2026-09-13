from app.models.user import Role


def _create_app(client, headers, app_name="Payment Gateway", owner_team="Team Alpha"):
    return client.post(
        "/api/v1/applications",
        headers=headers,
        json={
            "app_name": app_name,
            "app_type": "in_house",
            "owner_team": owner_team,
            "criticality": "critical",
            "internet_facing": True,
        },
    )


def test_create_application_requires_appsec_role(client, make_user, auth_headers):
    make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha", password="Passw0rd!")
    headers = auth_headers("dev.alpha")
    resp = _create_app(client, headers)
    assert resp.status_code == 403


def test_appsec_can_create_and_list_application(client, make_user, auth_headers):
    make_user("appsec.lead", Role.APPSEC, password="Passw0rd!")
    headers = auth_headers("appsec.lead")

    create_resp = _create_app(client, headers)
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]

    list_resp = client.get("/api/v1/applications", headers=headers)
    assert list_resp.status_code == 200
    body = list_resp.json()
    assert body["total"] == 1
    assert body["items"][0]["id"] == app_id


def test_dev_team_only_sees_own_owner_team_applications(client, make_user, auth_headers):
    make_user("appsec.lead", Role.APPSEC, password="Passw0rd!")
    appsec_headers = auth_headers("appsec.lead")
    _create_app(client, appsec_headers, app_name="Alpha App", owner_team="Team Alpha")
    _create_app(client, appsec_headers, app_name="Beta App", owner_team="Team Beta")

    make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha", password="Passw0rd!")
    dev_headers = auth_headers("dev.alpha")

    list_resp = client.get("/api/v1/applications", headers=dev_headers)
    assert list_resp.status_code == 200
    body = list_resp.json()
    assert body["total"] == 1
    assert body["items"][0]["app_name"] == "Alpha App"


def test_create_and_list_app_versions(client, make_user, auth_headers):
    make_user("appsec.lead", Role.APPSEC, password="Passw0rd!")
    headers = auth_headers("appsec.lead")
    app_id = _create_app(client, headers).json()["id"]

    version_resp = client.post(
        f"/api/v1/applications/{app_id}/versions",
        headers=headers,
        json={"version_label": "1.2.3", "commit_sha": "abc123", "is_current_production": True},
    )
    assert version_resp.status_code == 201

    list_resp = client.get(f"/api/v1/applications/{app_id}/versions", headers=headers)
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1
    assert list_resp.json()[0]["version_label"] == "1.2.3"
