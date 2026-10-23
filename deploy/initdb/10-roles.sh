#!/bin/sh
# Runs once, when the Postgres volume is first initialised.
# tabbysync_owner owns the schema and runs migrations;
# tabbysync_app (the server) can only read and write rows.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
	-v owner_pw="$(cat /run/secrets/db_owner_password)" \
	-v app_pw="$(cat /run/secrets/db_app_password)" <<'SQL'
CREATE ROLE tabbysync_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE tabbysync_app LOGIN PASSWORD :'app_pw';

REVOKE ALL ON DATABASE tabbysync FROM PUBLIC;
GRANT CONNECT ON DATABASE tabbysync TO tabbysync_owner, tabbysync_app;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA tabbysync AUTHORIZATION tabbysync_owner;
GRANT USAGE ON SCHEMA tabbysync TO tabbysync_app;
ALTER ROLE tabbysync_owner SET search_path = tabbysync;
ALTER ROLE tabbysync_app SET search_path = tabbysync;

ALTER DEFAULT PRIVILEGES FOR ROLE tabbysync_owner IN SCHEMA tabbysync
	GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tabbysync_app;
ALTER DEFAULT PRIVILEGES FOR ROLE tabbysync_owner IN SCHEMA tabbysync
	GRANT USAGE, SELECT ON SEQUENCES TO tabbysync_app;
SQL
