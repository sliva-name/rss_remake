# DataGuard

Платформа обнаружения, классификации и мониторинга доступа к чувствительным данным в СУБД. Исходные значения не покидают контур заказчика.

Устройство описано в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), текущее состояние — в разделе «Состояние» того же файла.

## Разработка

Нужны Go 1.26, Docker с Compose и `openssl`. Инструменты (buf, golangci-lint, govulncheck) зафиксированы в `tools/go.mod`, ставить их отдельно не надо.

```bash
make check
```

Локальный стенд поднимается отдельным проектом `dataguard-dev`. Порты из диапазона `25xxx` слушают только loopback, пароли генерируются в `deployments/dev/.env`.

```bash
make dev-up
```

```bash
make test-integration
```

После изменения контрактов в `api/proto`:

```bash
make proto
```

## Запуск

Сервер настраивается переменными окружения: `DG_PG_DSN` (роль без `BYPASSRLS`), `DG_PG_MIGRATION_DSN` (владелец схемы), `DG_PKI_DIR`, `DG_API_ADDR`, `DG_AGENT_ADDR`, `DG_OIDC_ISSUER`, `DG_OIDC_CLIENT_ID`.

```bash
bin/server pki-init --dir ./pki --hosts center.example.com
```

```bash
bin/server migrate
```

```bash
bin/server serve
```

Агент читает YAML-файл. Только в нём указаны адреса и учётные данные СУБД: центр их не знает.

```yaml
center:
  url: https://center.example.com:8443
  ca_file: /etc/dataguard/ca.crt
state_dir: /var/lib/dataguard
sources:
  - key: crm
    engine: postgresql   # postgresql, mysql, mariadb, mssql
    host: db.internal
    port: 5432
    database: crm
    username: dg_scanner
    password_file: /etc/dataguard/crm.password
    tls: verify-full     # verify-full, require, disable
    max_connections: 2
```

```bash
bin/agent enroll --config agent.yaml --token-file token.txt
```

```bash
bin/agent run --config agent.yaml
```
