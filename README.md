# DataGuard

Платформа обнаружения, классификации и мониторинга доступа к чувствительным данным в СУБД. Исходные значения не покидают контур заказчика.

Устройство описано в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), текущее состояние — в разделе «Состояние» того же файла.

## Разработка

Нужны Docker с Compose и `openssl`, для тестов и генерации кода — Go 1.27 и Node 24. Инструменты (buf, golangci-lint, govulncheck) зафиксированы в `tools/go.mod`, ставить их отдельно не надо.

```bash
make check
```

Каждая часть платформы работает в контейнере: сервер вместе с Dashboard, агент, миграции и выпуск PKI (ADR-0005). Стенд — отдельный compose-проект `dataguard-dev`: исходные СУБД, центральные PostgreSQL и ClickHouse, Keycloak и сама платформа. Порты из диапазона `25xxx` слушают только loopback, пароли генерируются в `deployments/dev/.env`.

```bash
make dev-up
```

Dashboard откроется на http://127.0.0.1:25800, Keycloak — на http://127.0.0.1:25080. Пользователи заводятся в Keycloak: администратор `dg_admin`, пароль `KEYCLOAK_ADMIN_PASSWORD` из `.env`. Пользователю нужна роль, а сотруднику организации — ещё атрибут `tenant_id`. Агент стартует после регистрации. Токен выпускается в разделе «Инфраструктура» и передаётся агенту через стандартный ввод:

```bash
make agent-enroll TOKEN_FILE=token.txt
```

```bash
make agent-up
```

Интеграционные тесты поднимают сервер внутри процесса теста, на базах стенда:

```bash
make test-integration
```

Сквозной тест пересобирает образы и управляет контейнерами. Он регистрирует агента, убивает агента и сервер через `kill -9`, ищет исходные значения во всех хранилищах и проходит Dashboard в браузере из контейнера Playwright. Скриншоты сохраняются в `deployments/dev/.state/browser`.

```bash
make test-e2e
```

После изменения контрактов в `api/proto`:

```bash
make proto
```

## Запуск

Образы собираются из `Dockerfile` в корне репозитория: цель `server` — сервер с Dashboard, цель `agent` — агент.

```bash
docker build --target server -t dataguard/server .
```

```bash
docker build --target agent -t dataguard/agent .
```

Готовая связка сервисов — `deployments/dev/compose.yml`. Сервер настраивается переменными окружения:

- `DG_PG_DSN` — роль без `BYPASSRLS`;
- `DG_PG_MIGRATION_DSN` — владелец схемы;
- `DG_PKI_DIR`, `DG_API_ADDR`, `DG_AGENT_ADDR`;
- `DG_OIDC_ISSUER` и `DG_OIDC_CLIENT_ID`;
- `DG_OIDC_DISCOVERY_URL` — необязательно: адрес провайдера, если сервер видит его не так, как браузер;
- `DG_CH_ADDR`, `DG_CH_DATABASE`, `DG_CH_USER`, `DG_CH_PASSWORD`;
- `DG_CH_MIGRATION_USER` и `DG_CH_MIGRATION_PASSWORD`.

Подкоманды образа сервера:

- `pki-init --dir DIR --hosts HOSTS [--keep-existing] [--public-dir DIR]`;
- `migrate`;
- `serve` — запускается по умолчанию;
- `ready` — проверка для healthcheck.

Агент читает YAML-файл, смонтированный в `/etc/dataguard/agent.yaml`. Только в нём указаны адреса и учётные данные СУБД, центр их не знает. Агенту нужны:

- сертификат CA центра;
- каталоги журналов аудита, только для чтения;
- том для состояния в `/var/lib/dataguard`.

Пример для стенда — `deployments/dev/agent/agent.yaml`.

```yaml
center:
  url: https://center.example.com:8443
  ca_file: /etc/dataguard/ca/ca.crt
state_dir: /var/lib/dataguard
sources:
  - key: crm
    engine: postgresql   # postgresql, mysql, mariadb, mssql
    host: db.internal
    port: 5432
    database: crm
    username: dg_scanner
    password_file: /run/secrets/crm-password
    tls: verify-full     # verify-full, require, disable
    max_connections: 2
    audit:
      directory: /var/log/postgresql   # каталог журналов; для SQL Server — путь на сервере
applications:                          # необязательно: приложения, подписывающие контекст
  - id: crm
    public_key_file: /etc/dataguard/apps/crm.pub
```

Регистрация и запуск:

```bash
docker run --rm -i -v agent-state:/var/lib/dataguard -v ./agent.yaml:/etc/dataguard/agent.yaml:ro -v ./ca:/etc/dataguard/ca:ro dataguard/agent enroll --config /etc/dataguard/agent.yaml --token-file /dev/stdin < token.txt
```

```bash
docker run -d -v agent-state:/var/lib/dataguard -v ./agent.yaml:/etc/dataguard/agent.yaml:ro -v ./ca:/etc/dataguard/ca:ro -v /var/log/postgresql:/var/log/postgresql:ro dataguard/agent
```
