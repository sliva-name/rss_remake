#!/bin/bash
# Starts SQL Server and applies init.sql once it accepts logins. The marker file
# lets the healthcheck report ready only after the logins and the audit exist.
set -euo pipefail

rm -f /tmp/dg-initialized
mkdir -p -m 0750 /var/opt/mssql/dg-audit

/opt/mssql/bin/launch_sqlservr.sh /opt/mssql/bin/sqlservr &
server=$!
trap 'kill -TERM "$server"' TERM INT

sqlcmd=(/opt/mssql-tools18/bin/sqlcmd -C -S localhost -U sa -b)
export SQLCMDPASSWORD="$MSSQL_SA_PASSWORD"
until "${sqlcmd[@]}" -Q 'SELECT 1' -o /dev/null 2>/dev/null; do
  kill -0 "$server" 2>/dev/null || exit 1
  sleep 2
done
# Logins open before system databases finish upgrading after an image update,
# and init.sql fails until they do. It is idempotent, so it is simply repeated.
attempts=0
until "${sqlcmd[@]}" -i /dg/init.sql; do
  kill -0 "$server" 2>/dev/null || exit 1
  attempts=$((attempts + 1))
  [ "$attempts" -lt 60 ] || exit 1
  sleep 5
done
unset SQLCMDPASSWORD SCANNER_PASSWORD APP_PASSWORD
touch /tmp/dg-initialized

wait "$server"
