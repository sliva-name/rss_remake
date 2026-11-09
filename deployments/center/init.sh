#!/usr/bin/env bash
# Runs once, on the first start of the center's PostgreSQL.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v password="$(cat "$CENTER_PG_APP_PASSWORD_FILE")" <<'SQL'
CREATE ROLE dg_runtime LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD :'password';
SQL

# Keycloak of an installation without its own identity provider keeps its data
# here, in a database and role of its own (deployments/production, profile
# keycloak). The stand's Keycloak keeps it in memory.
if [ -n "${KEYCLOAK_DB_PASSWORD_FILE:-}" ]; then
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    -v password="$(cat "$KEYCLOAK_DB_PASSWORD_FILE")" <<'SQL'
CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'password';
CREATE DATABASE keycloak OWNER keycloak;
SQL
fi
