#!/usr/bin/env bash
# Generates random passwords for the local stand. Existing values are kept so
# that restarting the stand does not invalidate already initialized volumes.
set -euo pipefail

dev_dir="$(dirname "$0")/../deployments/dev"
env_file="$dev_dir/.env"

# Containers write as their own users, and the tests read as the host user.
# A database may already own its directory, so existing ones are left as they are.
for directory in audit/postgres audit/mysql audit/mariadb browser; do
  [ -d "$dev_dir/.state/$directory" ] || install -d -m 0777 "$dev_dir/.state/$directory"
done

# Signing key of the demo application "crm", whose user context the agent verifies.
# Both halves are raw base64: the seed for the tests, the public key for the agent.
apps="$dev_dir/.state/apps"
if [ ! -f "$apps/crm.pub" ]; then
  install -d -m 0755 "$apps"
  key="$(openssl genpkey -algorithm ed25519 -outform DER | base64 -w0)"
  (umask 077; echo "$key" | base64 -d | tail -c 32 | base64 -w0 > "$apps/crm.seed")
  echo "$key" | base64 -d | openssl pkey -inform DER -pubout -outform DER | tail -c 32 | base64 -w0 > "$apps/crm.pub"
  chmod 0644 "$apps/crm.pub"
fi

secret() { openssl rand -hex 16; }

# A stand created before a component existed gets only the passwords it lacks.
add_missing() {
  grep -q "^$1=" "$env_file" || echo "$1=$(secret)" >> "$env_file"
}

if [ -f "$env_file" ]; then
  add_missing CENTER_BROKER_ADMIN_PASSWORD
  add_missing CENTER_BROKER_APP_PASSWORD
else
  (
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
      echo "CENTER_BROKER_ADMIN_PASSWORD=$(secret)"
      echo "CENTER_BROKER_APP_PASSWORD=$(secret)"
    } > "$env_file"
  )
fi

# The center reads its passwords from secret files, as an installation does: a
# file mounted into a container is not shown by the Docker API,
# a variable is. The tests keep reading .env, so the files repeat its values.
# Container users differ from the host user, so the files are readable inside
# the containers and the directory keeps them from other users of the host.
secrets="$dev_dir/.state/secrets"
install -d -m 0700 "$secrets"
for name in CENTER_PG_ADMIN_PASSWORD CENTER_PG_APP_PASSWORD CENTER_CH_ADMIN_PASSWORD CENTER_CH_APP_PASSWORD \
  CENTER_BROKER_ADMIN_PASSWORD CENTER_BROKER_APP_PASSWORD KEYCLOAK_ADMIN_PASSWORD; do
  file="$secrets/$(echo "$name" | tr '[:upper:]' '[:lower:]')"
  grep "^$name=" "$env_file" | cut -d= -f2- | tr -d '\n' > "$file"
  chmod 0644 "$file"
done
