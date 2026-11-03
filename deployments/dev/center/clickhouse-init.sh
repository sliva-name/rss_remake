#!/usr/bin/env bash
set -euo pipefail

clickhouse-client --user "$CLICKHOUSE_USER" --password "$CLICKHOUSE_PASSWORD" --multiquery <<SQL
CREATE USER IF NOT EXISTS dg_ch_app IDENTIFIED WITH sha256_password BY '$CENTER_CH_APP_PASSWORD';
SQL
