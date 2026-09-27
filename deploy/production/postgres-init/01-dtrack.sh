#!/bin/sh
# Runs once, when the postgres volume is first initialised: gives Dependency-Track its
# own database and login, so a compromise of one application's credentials does not
# expose the other's data.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v dtrack_password="$DTRACK_DB_PASSWORD" <<'SQL'
CREATE ROLE dtrack LOGIN PASSWORD :'dtrack_password';
CREATE DATABASE dtrack OWNER dtrack;
REVOKE ALL ON DATABASE dtrack FROM PUBLIC;
REVOKE ALL ON DATABASE appsec FROM PUBLIC;
SQL
