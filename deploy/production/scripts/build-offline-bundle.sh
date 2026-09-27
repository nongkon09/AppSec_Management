#!/usr/bin/env bash
# Builds a self-contained bundle for servers without internet or registry access:
#   dist/appsec-platform-<APP_VERSION>.tar.gz
#     appsec-platform/            this directory (compose file, scripts, postgres-init)
#     appsec-platform/images.tar.gz   every container image the stack needs
#     appsec-platform/docs/       deployment guide and workflows
# On the server: tar xzf ...; cd appsec-platform; scripts/install.sh --host <name> --offline
#
# Images are built for the server's CPU, not this machine's: PLATFORM defaults to
# linux/amd64 (x86 servers). Use PLATFORM=linux/arm64 for ARM servers. Building for a
# different CPU than this machine runs under emulation and takes longer.
set -euo pipefail

cd "$(dirname "$0")/.."
docker save --help 2>/dev/null | grep -q -- "--platform" \
    || { echo "ERROR: needs Docker 28 or newer (docker save --platform)" >&2; exit 1; }
version="${APP_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' ../../backend/pyproject.toml)}"
dtrack="${DTRACK_VERSION:-4.14.4}"
prefix="${IMAGE_PREFIX:-appsec-platform}"
platform="${PLATFORM:-linux/amd64}"
export DOCKER_DEFAULT_PLATFORM="$platform"
export APP_VERSION="$version" DTRACK_VERSION="$dtrack" IMAGE_PREFIX="$prefix"

# Compose needs these to parse the file; the values are irrelevant for building.
export SECRET_KEY=x POSTGRES_PASSWORD=x DTRACK_DB_PASSWORD=x APP_PUBLIC_URL=x \
    DTRACK_UI_PUBLIC_URL=x DTRACK_API_PUBLIC_URL=x

echo "Building application images $prefix/*:$version for $platform"
docker compose --env-file /dev/null build
for image in postgres:16-alpine "dependencytrack/apiserver:$dtrack" "dependencytrack/frontend:$dtrack"; do
    docker pull --platform "$platform" "$image"
done

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
bundle="$stage/appsec-platform"
mkdir -p "$bundle/docs"
cp -R docker-compose.yml .env.example postgres-init scripts "$bundle/"
cp ../../docs/deployment-guide.md ../../docs/workflows.md "$bundle/docs/"
# The bundle ships images, not source: point version pins at what was built.
sed -i.bak "s/^APP_VERSION=.*/APP_VERSION=$version/; s/^DTRACK_VERSION=.*/DTRACK_VERSION=$dtrack/" \
    "$bundle/.env.example" && rm "$bundle/.env.example.bak"

echo "Saving images (this takes a while)"
# --platform matters: with the containerd image store a tag can hold several
# platforms, and without it docker save picks this machine's, not the server's.
docker save --platform "$platform" "$prefix/backend:$version" "$prefix/frontend:$version" postgres:16-alpine \
    "dependencytrack/apiserver:$dtrack" "dependencytrack/frontend:$dtrack" | gzip > "$bundle/images.tar.gz"

mkdir -p ../../dist
out="../../dist/appsec-platform-$version-${platform//\//-}.tar.gz"
tar czf "$out" -C "$stage" appsec-platform
echo "Bundle: $(cd ../../dist && pwd)/$(basename "$out") ($(du -h "$out" | cut -f1))"
