#!/usr/bin/env python3
"""One-time setup of a fresh Dependency-Track for the AppSec Platform.

Production (from deploy/production/):
    python3 scripts/dtrack-bootstrap.py --url http://localhost:8081 --env-file .env
Local development (from the repository root):
    python3 deploy/production/scripts/dtrack-bootstrap.py --url http://localhost:8081 --env-file .env

Safe to re-run: every step checks what already exists. It waits for the API server to
finish its first start (several minutes on a new database). What it does:
1. Replaces DT's default admin/admin password with a generated one.
2. Creates two teams, each with one API key (Requirement.md FR-2.7.4):
   - "AppSec Platform - Sync (read-only)": VIEW_PORTFOLIO, VIEW_VULNERABILITY -> pull-sync.
   - "AppSec Platform - SBOM Upload": BOM_UPLOAD, PROJECT_CREATION_UPLOAD -> CI/CD uploads
     and manual/COTS SBOM forwarding (FR-2.6.1).
3. Enables the Google OSV mirror with CVE alias sync, so purl-only SBOMs are matched
   without waiting hours for the full NVD mirror.

Secrets go only into the env file (mode 600) and are never printed. Afterwards restart
the backend and worker so they read the keys, and restart dtrack-apiserver once so OSV
mirroring starts.

Standard library only, so it runs on the host without the backend's virtualenv.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DT_URL = "http://localhost:8081"
ENV_FILE = Path(".env")
DEFAULT_OSV_ECOSYSTEMS = "Maven;npm;PyPI;Go;NuGet;crates.io;RubyGems;Packagist"

TEAMS = {
    "DEPENDENCY_TRACK_API_KEY": (
        "AppSec Platform - Sync (read-only)",
        ["VIEW_PORTFOLIO", "VIEW_VULNERABILITY"],
    ),
    "DEPENDENCY_TRACK_UPLOAD_API_KEY": (
        "AppSec Platform - SBOM Upload",
        ["BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO"],
    ),
}


def read_env() -> dict[str, str]:
    if not ENV_FILE.exists():
        return {}
    values: dict[str, str] = {}
    for line in ENV_FILE.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def save_env_value(key: str, value: str) -> None:
    """Sets one key in the env file, keeping every other line (and comment) as it was."""
    lines = ENV_FILE.read_text().splitlines() if ENV_FILE.exists() else []
    for index, line in enumerate(lines):
        stripped = line.lstrip("# ").split("=", 1)[0].strip()
        if stripped == key and "=" in line:
            lines[index] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    ENV_FILE.write_text("\n".join(lines) + "\n")
    ENV_FILE.chmod(0o600)


def wait_until_ready(timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            with urllib.request.urlopen(DT_URL + "/api/version", timeout=10) as response:
                version = json.loads(response.read().decode()).get("version")
                print(f"Dependency-Track {version} is up")
                return
        except (urllib.error.URLError, OSError, ValueError):
            if time.monotonic() > deadline:
                sys.exit(f"Dependency-Track did not answer on {DT_URL} within {timeout_seconds}s.")
            print("Waiting for Dependency-Track to finish starting...")
            time.sleep(15)


def form_post(path: str, data: dict[str, str]) -> tuple[int, str]:
    request = urllib.request.Request(
        DT_URL + path,
        data=urllib.parse.urlencode(data).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def api(token: str, method: str, path: str, body: object | None = None) -> object:
    request = urllib.request.Request(
        DT_URL + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request) as response:
        text = response.read().decode()
        return json.loads(text) if text else None


def login(values: dict[str, str]) -> str:
    password = values.get("DTRACK_ADMIN_PASSWORD")
    if not password:
        password = "Dt-" + secrets.token_urlsafe(18)
        status, _ = form_post(
            "/api/v1/user/forceChangePassword",
            {"username": "admin", "password": "admin", "newPassword": password, "confirmPassword": password},
        )
        if status != 200:
            sys.exit(f"Could not change the default admin password (HTTP {status}).")
        values["DTRACK_ADMIN_PASSWORD"] = password
        save_env_value("DTRACK_ADMIN_PASSWORD", password)
        print(f"Admin password changed and saved to {ENV_FILE} (DTRACK_ADMIN_PASSWORD)")
    status, token = form_post("/api/v1/user/login", {"username": "admin", "password": password})
    if status != 200:
        sys.exit(f"Admin login failed (HTTP {status}); check DTRACK_ADMIN_PASSWORD in {ENV_FILE}.")
    return token


def main() -> None:
    global DT_URL, ENV_FILE
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--url", default=DT_URL, help="Dependency-Track API server URL")
    parser.add_argument("--env-file", default=str(ENV_FILE), help="env file to read and update")
    parser.add_argument("--osv-ecosystems", default=DEFAULT_OSV_ECOSYSTEMS)
    parser.add_argument("--wait", type=int, default=900, help="seconds to wait for startup")
    args = parser.parse_args()
    DT_URL = args.url.rstrip("/")
    ENV_FILE = Path(args.env_file)

    wait_until_ready(args.wait)
    values = read_env()
    token = login(values)

    teams = {team["name"]: team for team in api(token, "GET", "/api/v1/team")}  # type: ignore[union-attr]
    for env_key, (name, permissions) in TEAMS.items():
        team = teams.get(name) or api(token, "PUT", "/api/v1/team", {"name": name})
        assert isinstance(team, dict)
        granted = {permission["name"] for permission in team.get("permissions") or []}
        for permission in permissions:
            if permission not in granted:
                api(token, "POST", f"/api/v1/permission/{permission}/team/{team['uuid']}")
        if env_key not in values:
            key = api(token, "PUT", f"/api/v1/team/{team['uuid']}/key")
            assert isinstance(key, dict)
            values[env_key] = key["key"]
            save_env_value(env_key, key["key"])
            print(f"Created API key for '{name}' -> {env_key} in {ENV_FILE}")
        else:
            print(f"'{name}' already has a key in {ENV_FILE}")

    config = [
        ("vuln-source", "google.osv.enabled", args.osv_ecosystems),
        ("vuln-source", "google.osv.alias.sync.enabled", "true"),
    ]
    for group, name, value in config:
        api(token, "POST", "/api/v1/configProperty", {"groupName": group, "propertyName": name, "propertyValue": value})
    print(f"OSV mirror ({args.osv_ecosystems.replace(';', ', ')}) and alias sync enabled")


if __name__ == "__main__":
    main()
