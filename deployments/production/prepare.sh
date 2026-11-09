#!/usr/bin/env bash
# Prepares a center installation next to this file (INSTALL.md): generates the
# passwords once and checks the dashboard certificate. Running it again keeps
# existing passwords, so it never breaks initialized databases.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
# The settings file may live elsewhere, as for docker compose --env-file.
env_file="${DG_ENV_FILE:-.env}"
if [ ! -f "$env_file" ]; then
  echo "Copy example.env to .env and fill it in first." >&2
  exit 1
fi
# The two directories may be set in the settings or overridden in the environment.
env_value() { grep -E "^$1=" "$env_file" | tail -n1 | cut -d= -f2-; }
secrets="${DG_SECRETS_DIR:-$(env_value DG_SECRETS_DIR)}"
tls="${DG_TLS_DIR:-$(env_value DG_TLS_DIR)}"
secrets="${secrets:-./secrets}"
tls="${tls:-./tls}"

# Containers run as their own users, so the files are readable inside them; the
# directory keeps them from other users of the host.
install -d -m 0700 "$secrets"
for name in center_pg_admin_password center_pg_app_password center_ch_admin_password center_ch_app_password \
  center_broker_admin_password center_broker_app_password keycloak_admin_password keycloak_db_password; do
  if [ ! -s "$secrets/$name" ]; then
    openssl rand -hex 24 | tr -d '\n' > "$secrets/$name"
  fi
  chmod 0644 "$secrets/$name"
done

if [ ! -s "$tls/dashboard.crt" ] || [ ! -s "$tls/dashboard.key" ]; then
  echo "Put the dashboard certificate with its chain into $tls/dashboard.crt and its key into $tls/dashboard.key." >&2
  exit 1
fi
# Without a CA of your own for the identity provider the file stays empty.
[ -f "$tls/oidc-ca.crt" ] || : > "$tls/oidc-ca.crt"
chmod 0700 "$tls"
chmod 0644 "$tls"/*
if ! openssl x509 -noout -in "$tls/dashboard.crt" 2>/dev/null; then
  echo "$tls/dashboard.crt is not a PEM certificate." >&2
  exit 1
fi
echo "Ready: passwords in $secrets, certificate in $tls."
