#!/usr/bin/env bash
# Clean installation of the AppSec Platform + Dependency-Track (docs/deployment-guide.md).
#
#   scripts/install.sh --host appsec.example.org          # build from source and start
#   scripts/install.sh --host appsec.example.org --offline # load images from an offline bundle
#
# Re-running is safe: an existing .env is kept, secrets are never regenerated, and
# Dependency-Track setup skips whatever already exists.
set -euo pipefail

cd "$(dirname "$0")/.."
HOST=""
SCHEME="http"
OFFLINE=false

usage() {
    sed -n '2,8p' "$0"
    exit 1
}

while [ $# -gt 0 ]; do
    case "$1" in
        --host) HOST="${2:-}"; shift 2 ;;
        --https) SCHEME="https"; shift ;;
        --offline) OFFLINE=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

step "Checking prerequisites"
command -v docker >/dev/null || fail "docker is not installed"
docker compose version >/dev/null 2>&1 || fail "the Docker Compose v2 plugin is not installed"
command -v python3 >/dev/null || fail "python3 is required (standard library only)"
command -v openssl >/dev/null || fail "openssl is required to generate secrets"

memory_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
if [ "$memory_kb" -gt 0 ] && [ "$memory_kb" -lt 7500000 ]; then
    echo "WARNING: less than 8 GB RAM. Dependency-Track alone needs about 4.5 GB."
fi

if [ ! -f .env ]; then
    [ -n "$HOST" ] || fail "first install: pass --host <the server's DNS name or IP>"
    step "Creating .env with generated secrets"
    umask 077
    python3 - "$HOST" "$SCHEME" <<'PY'
import secrets
import sys
from pathlib import Path

host, scheme = sys.argv[1], sys.argv[2]
text = Path(".env.example").read_text()
text = text.replace("http://appsec.example.org:8082", f"{scheme}://{host}:8082")
text = text.replace("http://appsec.example.org:8081", f"{scheme}://{host}:8081")
text = text.replace("http://appsec.example.org", f"{scheme}://{host}")
lines = []
for line in text.splitlines():
    if line.endswith("=<generate>"):
        key = line.split("=", 1)[0]
        # URL-safe characters only: these end up inside a database URL.
        line = f"{key}={secrets.token_urlsafe(48 if key == 'SECRET_KEY' else 24)}"
    lines.append(line)
Path(".env").write_text("\n".join(lines) + "\n")
PY
    chmod 600 .env
    echo "Created .env (mode 600). Review it before going live."
else
    echo "Keeping the existing .env"
fi

set -a
# shellcheck disable=SC1091
. ./.env
set +a

if $OFFLINE; then
    step "Loading container images from images.tar.gz"
    [ -f images.tar.gz ] || fail "images.tar.gz not found next to docker-compose.yml"
    gunzip -c images.tar.gz | docker load
    UP_FLAGS=(--no-build)
else
    step "Building application images (a few minutes the first time)"
    docker compose build
    UP_FLAGS=()
fi

step "Starting the database and the application"
docker compose up -d ${UP_FLAGS[@]+"${UP_FLAGS[@]}"} postgres backend frontend worker

step "Waiting for the backend to migrate the database and become healthy"
for _ in $(seq 1 60); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$(docker compose ps -q backend)" 2>/dev/null || true)
    [ "$status" = "healthy" ] && break
    sleep 5
done
[ "$status" = "healthy" ] || { docker compose logs --tail 50 backend; fail "backend did not become healthy"; }

step "Starting Dependency-Track (first start takes several minutes)"
docker compose up -d ${UP_FLAGS[@]+"${UP_FLAGS[@]}"} dtrack-apiserver dtrack-frontend

step "Configuring Dependency-Track (admin password, API keys, OSV mirror)"
python3 scripts/dtrack-bootstrap.py --url "http://127.0.0.1:${DTRACK_API_PORT:-8081}" --env-file .env

step "Restarting services so they pick up the Dependency-Track keys"
docker compose up -d ${UP_FLAGS[@]+"${UP_FLAGS[@]}"} backend worker
docker compose restart dtrack-apiserver

cat <<EOF

Installation complete.

  AppSec Platform      ${APP_PUBLIC_URL}
  Dependency-Track UI  ${DTRACK_UI_PUBLIC_URL}   (user: admin)
  Dependency-Track API ${DTRACK_API_PUBLIC_URL}  (CI/CD uploads SBOMs here)

  Platform admin user: ${INITIAL_ADMIN_USERNAME:-admin}
  Its password and the Dependency-Track admin password are in .env
  (INITIAL_ADMIN_PASSWORD, DTRACK_ADMIN_PASSWORD).

Next: follow "หลังติดตั้ง" in docs/deployment-guide.md — change the admin password,
create the real users and approval levels, the pipeline account, and the control library.
EOF
