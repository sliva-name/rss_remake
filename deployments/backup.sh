#!/usr/bin/env bash
# Backs up and restores what the center cannot rebuild: its PostgreSQL database
# (organizations, agents, sources with sealed passwords, catalog, policies,
# journal) and the PKI volume (CA, server certificate, policy keys). Events in
# ClickHouse are not included: see INSTALL.md.
#
# Runs in the backup service of the compose file, on the PostgreSQL image:
#   backup.sh backup   writes /backup/postgres.dump and /backup/pki.tar
#   backup.sh restore  replaces the database and the PKI volume with them
# Restore expects the server to be stopped; make restore and INSTALL.md do that.
set -euo pipefail
umask 077

PGPASSWORD="$(cat /run/secrets/center_pg_admin_password)"
export PGPASSWORD PGHOST="${PGHOST:-center-postgres}" PGUSER="${PGUSER:-dg_owner}"
database="${PGDATABASE:-dataguard}"

case "${1:-}" in
backup)
  # The owner is a superuser: the dump is not filtered by row-level security.
  pg_dump --format=custom --dbname="$database" --file=/backup/postgres.dump.tmp
  tar --create --numeric-owner --file=/backup/pki.tar.tmp --directory=/pki .
  mv /backup/postgres.dump.tmp /backup/postgres.dump
  mv /backup/pki.tar.tmp /backup/pki.tar
  date --utc +%Y-%m-%dT%H:%M:%SZ > /backup/created_at
  echo "backup written: postgres.dump, pki.tar"
  ;;
restore)
  for file in postgres.dump pki.tar; do
    [ -s "/backup/$file" ] || { echo "/backup/$file is missing" >&2; exit 1; }
  done
  # Checked before anything is dropped: a broken archive must not cost the
  # current database.
  pg_restore --list /backup/postgres.dump > /dev/null
  tar --list --file=/backup/pki.tar > /dev/null
  dropdb --if-exists --force --maintenance-db=postgres "$database"
  createdb --maintenance-db=postgres "$database"
  pg_restore --dbname="$database" --exit-on-error /backup/postgres.dump
  find /pki -mindepth 1 -delete
  tar --extract --numeric-owner --same-permissions --file=/backup/pki.tar --directory=/pki
  echo "restored from the backup of $(cat /backup/created_at 2>/dev/null || echo 'unknown date')"
  ;;
*)
  echo "usage: backup.sh backup|restore" >&2
  exit 2
  ;;
esac
