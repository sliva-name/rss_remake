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

Dashboard откроется на http://127.0.0.1:25800. Учётные записи для входа создаёт отдельная команда. Она заводит администратора платформы, организацию «Демо» с её администратором и аналитиком и печатает их пароли. При каждом запуске пароли выдаются заново.

```bash
make dev-users
```

`dg_admin` из `.env` — администратор самого Keycloak (http://127.0.0.1:25080/admin). В Dashboard с ним не войти.

Агент стартует после регистрации. Под `demo-admin` в разделе «Инфраструктура» создайте среду и выпустите токен, сохраните его в файл и передайте агенту через стандартный ввод. Затем там же добавьте источники. Агенту стенда разрешены хосты `source-postgres`, `source-mysql`, `source-mariadb` и `source-mssql` и каталог `/var/log/dg-audit` (у SQL Server журнал на его сервере: `/var/opt/mssql/dg-audit`), пользователь сканера — `dg_scanner`, пароли лежат в `.env`.

```bash
make agent-enroll TOKEN_FILE=token.txt
```

```bash
make agent-up
```

Повторно агент регистрируется только с пустым состоянием. Иначе события из старой очереди ушли бы под новой регистрацией. Состояние стирается так:

```bash
make agent-reset
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

Источники создаются в Dashboard, в разделе «Инфраструктура». Браузер шифрует пароль ключом выбранного агента, центр хранит только шифротекст (ADR-0006).

Агент читает YAML-файл, смонтированный в `/etc/dataguard/agent.yaml`. В нём указаны адрес центра и обязательный список разрешённых целей. Источник вне этого списка агент не откроет, даже если его потребует центр. Агенту нужны:

- сертификат CA центра;
- каталоги журналов аудита, только для чтения;
- том для состояния в `/var/lib/dataguard`.

Пример для стенда — `deployments/dev/agent/agent.yaml`.

```yaml
center:
  url: https://center.example.com:8443
  ca_file: /etc/dataguard/ca/ca.crt
state_dir: /var/lib/dataguard
allowed:
  hosts: ["10.20.0.0/16", "db.internal", "*.db.corp"]   # сети, адреса, имена, домены
  audit_directories: [/var/log/postgresql]             # откуда можно читать журналы
applications:                                          # необязательно: приложения, подписывающие контекст
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
