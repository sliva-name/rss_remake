#!/usr/bin/env bash
# Generates random passwords for the local stand. Existing values are kept so
# that restarting the stand does not invalidate already initialized volumes.
set -euo pipefail

dev_dir="$(dirname "$0")/../deployments/dev"
env_file="$dev_dir/.env"

# Containers write as their own users, and the tests read as the host user.
install -d -m 0777 "$dev_dir/.state/audit/postgres" "$dev_dir/.state/audit/mysql" "$dev_dir/.state/audit/mariadb"

[ -f "$env_file" ] && exit 0

secret() { openssl rand -hex 16; }

umask 077
{
  echo "SOURCE_ADMIN_PASSWORD=$(secret)"
  echo "SOURCE_SCANNER_PASSWORD=$(secret)"
  echo "SOURCE_APP_PASSWORD=$(secret)"
  # SQL Server rejects passwords without mixed character classes.
  echo "SOURCE_MSSQL_SA_PASSWORD=Dg1!$(secret)"
  echo "SOURCE_MSSQL_SCANNER_PASSWORD=Dg2!$(secret)"
  echo "SOURCE_MSSQL_APP_PASSWORD=Dg3!$(secret)"
  echo "CENTER_PG_ADMIN_PASSWORD=$(secret)"
  echo "CENTER_PG_APP_PASSWORD=$(secret)"
  echo "CENTER_CH_ADMIN_PASSWORD=$(secret)"
  echo "CENTER_CH_APP_PASSWORD=$(secret)"
  echo "KEYCLOAK_ADMIN_PASSWORD=$(secret)"
} > "$env_file"
