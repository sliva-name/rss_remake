#!/usr/bin/env bash
set -euo pipefail

# The application password goes in as a query parameter, so no quoting can break it.
clickhouse-client --user "$CLICKHOUSE_USER" --password "$(cat "$CLICKHOUSE_PASSWORD_FILE")" \
  --param_password="$(cat "$CENTER_CH_APP_PASSWORD_FILE")" \
  --query "CREATE USER IF NOT EXISTS dg_ch_app IDENTIFIED WITH sha256_password BY {password:String}"
