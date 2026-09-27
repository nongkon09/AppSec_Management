#!/usr/bin/env bash
# Backs up everything needed to rebuild this installation (docs/deployment-guide.md):
#   appsec.dump      platform database (findings, exceptions, approvals, audit trail)
#   dtrack.dump      Dependency-Track database (projects, SBOMs, analysis)
#   uploads.tar.gz   pentest reports and SBOM scan evidence
#   dtrack-keys.tar.gz  Dependency-Track's encryption keys (without them its stored
#                       secrets cannot be decrypted after a restore)
#   env              the .env file (secrets — store the backup encrypted)
#
#   scripts/backup.sh [target directory]   default: ./backups/<timestamp>
set -euo pipefail

cd "$(dirname "$0")/.."
target="${1:-backups/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$target"
chmod 700 "$target"

echo "Backing up to $target"
docker compose exec -T postgres pg_dump -U appsec -Fc appsec > "$target/appsec.dump"
docker compose exec -T postgres pg_dump -U appsec -Fc dtrack > "$target/dtrack.dump"
docker compose exec -T backend tar czf - -C /app uploads > "$target/uploads.tar.gz"
docker compose exec -T dtrack-apiserver tar czf - -C /data .dependency-track/keys > "$target/dtrack-keys.tar.gz"
cp .env "$target/env"
chmod 600 "$target"/*

( cd "$target" && sha256sum ./* > SHA256SUMS 2>/dev/null || shasum -a 256 ./* > SHA256SUMS )
echo "Done:"
ls -lh "$target"
