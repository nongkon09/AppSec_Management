-- Creates the separate database used by the Dependency-Track container.
-- The "appsec" application database itself is created automatically by the
-- official postgres image via the POSTGRES_DB environment variable.
CREATE DATABASE dtrack OWNER appsec;
