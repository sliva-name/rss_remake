#!/usr/bin/env bash
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v scanner_password="$SOURCE_SCANNER_PASSWORD" \
  -v app_password="$SOURCE_APP_PASSWORD" <<'SQL'
CREATE EXTENSION pgaudit;
CREATE ROLE dg_scanner LOGIN PASSWORD :'scanner_password';
CREATE ROLE dg_app LOGIN PASSWORD :'app_password';
GRANT pg_read_all_data TO dg_scanner;
GRANT pg_read_all_settings TO dg_scanner;
GRANT ALL ON SCHEMA public TO dg_app;
ALTER DEFAULT PRIVILEGES FOR ROLE dg_app IN SCHEMA public GRANT SELECT ON TABLES TO dg_scanner;
SQL
