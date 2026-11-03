#!/usr/bin/env bash
set -euo pipefail

sed -e "s/\${SOURCE_SCANNER_PASSWORD}/$SOURCE_SCANNER_PASSWORD/" \
    -e "s/\${SOURCE_APP_PASSWORD}/$SOURCE_APP_PASSWORD/" \
    /dg/init.sql.tmpl | "${DG_CLIENT}" --user=root --password="$MYSQL_ROOT_PASSWORD"
