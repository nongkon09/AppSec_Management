"""User/Role management tests (Requirement.md Section 4: System Admin responsibility)."""

from app.models.user import Role


def _create_payload(**overrides):
    payload = {
        "username": "dev.new",
        "email": "dev.new@example.local",
        "full_name": "New Dev",
        "role": "dev_team",
        "owner_team": "Team Alpha",
        "password": "Passw0rd!123",
    }
    payload.update(overrides)
    return payload


class TestListUsers:
    def test_admin_can_list_users(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        make_user("appsec.lead", Role.APPSEC)
        resp = client.get("/api/v1/users", headers=auth_headers("sysadmin"))
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_appsec_cannot_list_users(self, client, make_user, auth_headers):
        """Section 4: User/Role administration is Admin-only, distinct from AppSec's
        Policy/Waiver ownership."""
        make_user("appsec.lead", Role.APPSEC)
        resp = client.get("/api/v1/users", headers=auth_headers("appsec.lead"))
        assert resp.status_code == 403

    def test_dev_team_cannot_list_users(self, client, make_user, auth_headers):
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        resp = client.get("/api/v1/users", headers=auth_headers("dev.alpha"))
        assert resp.status_code == 403

    def test_anonymous_cannot_list_users(self, client):
        assert client.get("/api/v1/users").status_code == 401


class TestCreateUser:
    def test_admin_creates_user(self, client, make_user, auth_headers, db_session):
        make_user("sysadmin", Role.ADMIN)
        resp = client.post(
            "/api/v1/users", headers=auth_headers("sysadmin"), json=_create_payload()
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["username"] == "dev.new"
        assert body["role"] == "dev_team"
        assert body["is_active"] is True
        assert "password" not in body
        assert "hashed_password" not in body

    def test_new_user_can_log_in(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        client.post("/api/v1/users", headers=auth_headers("sysadmin"), json=_create_payload())
        login = client.post(
            "/api/v1/auth/login", data={"username": "dev.new", "password": "Passw0rd!123"}
        )
        assert login.status_code == 200

    def test_duplicate_username_rejected(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        client.post("/api/v1/users", headers=headers, json=_create_payload())
        resp = client.post(
            "/api/v1/users",
            headers=headers,
            json=_create_payload(email="different@example.local"),
        )
        assert resp.status_code == 409

    def test_duplicate_email_rejected(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        client.post("/api/v1/users", headers=headers, json=_create_payload())
        resp = client.post(
            "/api/v1/users", headers=headers, json=_create_payload(username="dev.other")
        )
        assert resp.status_code == 409

    def test_dev_team_without_owner_team_rejected(self, client, make_user, auth_headers):
        """Fail-closed rule (Section 4 Data Scoping): a Dev Team account with no team
        would see nothing, which is never the intent of creating one."""
        make_user("sysadmin", Role.ADMIN)
        resp = client.post(
            "/api/v1/users",
            headers=auth_headers("sysadmin"),
            json=_create_payload(owner_team=None),
        )
        assert resp.status_code == 422

    def test_short_password_rejected(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        resp = client.post(
            "/api/v1/users",
            headers=auth_headers("sysadmin"),
            json=_create_payload(password="short"),
        )
        assert resp.status_code == 422

    def test_appsec_cannot_create_user(self, client, make_user, auth_headers):
        make_user("appsec.lead", Role.APPSEC)
        resp = client.post(
            "/api/v1/users", headers=auth_headers("appsec.lead"), json=_create_payload()
        )
        assert resp.status_code == 403

    def test_create_is_audited(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        create_resp = client.post("/api/v1/users", headers=headers, json=_create_payload())
        user_id = create_resp.json()["id"]

        logs = client.get(
            "/api/v1/audit-logs",
            headers=headers,
            params={"entity_type": "user", "entity_id": user_id},
        ).json()
        assert logs["total"] == 1
        assert logs["items"][0]["action"] == "user.create"
        assert logs["items"][0]["actor"] == "sysadmin"


class TestUpdateUser:
    def test_admin_updates_role_and_team(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        user_id = client.post("/api/v1/users", headers=headers, json=_create_payload()).json()["id"]

        resp = client.patch(
            f"/api/v1/users/{user_id}",
            headers=headers,
            json={"owner_team": "Team Beta"},
        )
        assert resp.status_code == 200
        assert resp.json()["owner_team"] == "Team Beta"

    def test_deactivate_blocks_login(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        user_id = client.post("/api/v1/users", headers=headers, json=_create_payload()).json()["id"]

        client.patch(f"/api/v1/users/{user_id}", headers=headers, json={"is_active": False})
        login = client.post(
            "/api/v1/auth/login", data={"username": "dev.new", "password": "Passw0rd!123"}
        )
        assert login.status_code == 401

    def test_deactivate_invalidates_existing_token_immediately(
        self, client, make_user, auth_headers
    ):
        """get_current_user re-checks is_active on every request, so an existing token
        must stop working the moment an admin deactivates the account — not just block
        future logins."""
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        dev_headers = auth_headers("dev.alpha")
        make_user("sysadmin", Role.ADMIN)
        admin_headers = auth_headers("sysadmin")

        assert client.get("/api/v1/auth/me", headers=dev_headers).status_code == 200

        users = client.get("/api/v1/users", headers=admin_headers).json()["items"]
        dev_id = next(u["id"] for u in users if u["username"] == "dev.alpha")
        client.patch(f"/api/v1/users/{dev_id}", headers=admin_headers, json={"is_active": False})

        assert client.get("/api/v1/auth/me", headers=dev_headers).status_code == 401

    def test_removing_owner_team_from_dev_team_role_rejected(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        user_id = client.post("/api/v1/users", headers=headers, json=_create_payload()).json()["id"]

        resp = client.patch(f"/api/v1/users/{user_id}", headers=headers, json={"owner_team": None})
        assert resp.status_code == 422

    def test_email_conflict_on_update_rejected(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        client.post("/api/v1/users", headers=headers, json=_create_payload())
        other_id = client.post(
            "/api/v1/users",
            headers=headers,
            json=_create_payload(username="dev.other", email="other@example.local"),
        ).json()["id"]

        resp = client.patch(
            f"/api/v1/users/{other_id}",
            headers=headers,
            json={"email": "dev.new@example.local"},
        )
        assert resp.status_code == 409

    def test_update_unknown_user_returns_404(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        resp = client.patch(
            "/api/v1/users/00000000-0000-0000-0000-000000000000",
            headers=auth_headers("sysadmin"),
            json={"full_name": "x"},
        )
        assert resp.status_code == 404

    def test_update_is_audited_with_before_after(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        user_id = client.post("/api/v1/users", headers=headers, json=_create_payload()).json()["id"]

        client.patch(f"/api/v1/users/{user_id}", headers=headers, json={"owner_team": "Team Beta"})

        logs = client.get(
            "/api/v1/audit-logs",
            headers=headers,
            params={"entity_type": "user", "entity_id": user_id, "action": "update"},
        ).json()
        assert logs["items"][0]["before_value"]["owner_team"] == "Team Alpha"
        assert logs["items"][0]["after_value"]["owner_team"] == "Team Beta"


class TestResetPassword:
    def test_admin_resets_password(self, client, make_user, auth_headers):
        make_user("sysadmin", Role.ADMIN)
        headers = auth_headers("sysadmin")
        user_id = client.post("/api/v1/users", headers=headers, json=_create_payload()).json()["id"]

        resp = client.post(
            f"/api/v1/users/{user_id}/reset-password",
            headers=headers,
            json={"new_password": "NewPassw0rd!"},
        )
        assert resp.status_code == 200

        old_login = client.post(
            "/api/v1/auth/login", data={"username": "dev.new", "password": "Passw0rd!123"}
        )
        assert old_login.status_code == 401
        new_login = client.post(
            "/api/v1/auth/login", data={"username": "dev.new", "password": "NewPassw0rd!"}
        )
        assert new_login.status_code == 200

    def test_appsec_cannot_reset_password(self, client, make_user, auth_headers):
        make_user("appsec.lead", Role.APPSEC)
        make_user("dev.alpha", Role.DEV_TEAM, owner_team="Team Alpha")
        headers = auth_headers("appsec.lead")
        users = client.get("/api/v1/users", headers=auth_headers("appsec.lead"))
        # appsec cannot even list users to find the id; confirm the endpoint itself
        # is gated regardless.
        assert users.status_code == 403
        resp = client.post(
            "/api/v1/users/00000000-0000-0000-0000-000000000000/reset-password",
            headers=headers,
            json={"new_password": "Whatever123!"},
        )
        assert resp.status_code == 403
