#!/bin/sh
# API container start-up: apply pending migrations, run the idempotent first-run
# bootstrap (initial admin + default policy, a no-op once users exist), then serve.
# The background worker reuses this image with RUN_MIGRATIONS=false so only one
# container ever migrates.
set -e

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
    echo "Running database migrations..."
    alembic upgrade head
    echo "Running first-run bootstrap..."
    python -m app.bootstrap
fi

echo "Starting: $@"
exec "$@"
