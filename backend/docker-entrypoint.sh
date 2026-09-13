#!/bin/sh
# Applies pending Alembic migrations before the API starts serving traffic, so a
# fresh container always comes up against an up-to-date schema without a manual
# step. Safe to run on every start: a no-op when already at head.
set -e

echo "Running database migrations..."
alembic upgrade head

echo "Starting: $@"
exec "$@"
