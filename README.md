# DataGuard

Платформа обнаружения, классификации и мониторинга доступа к чувствительным данным в СУБД. Исходные значения не покидают контур заказчика.

Устройство описано в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), текущее состояние — в разделе «Состояние» того же файла.

## Быстрый старт

Нужны Docker с Compose, `openssl` и Go 1.27. Одна команда поднимает стенд и доводит его до заполненного Dashboard. Она заводит учётные записи и организацию «Демо», регистрирует агента и добавляет четыре базы стенда как источники. Затем засевает синтетические данные, делает обращения к ним и сканирует. Первый запуск занимает несколько минут, в основном на сборку образов, повторный — секунды.

```bash
make demo
```

В конце команда печатает адрес Dashboard (http://127.0.0.1:25800) и пароли `platform`, `demo-admin` и `demo-analyst`. Пароли хранятся только в Keycloak и при каждом запуске выдаются заново. `dg_admin` из `.env` — администратор самого Keycloak (http://127.0.0.1:25080/admin), в Dashboard с ним не войти.

## Разработка

Для тестов и генерации кода нужен ещё Node 24. Инструменты (buf, golangci-lint, govulncheck) зафиксированы в `tools/go.mod`, ставить их отдельно не надо.

```bash
make check
```

Каждая часть платформы работает в контейнере: сервер вместе с Dashboard, агент, миграции и выпуск PKI (ADR-0005). Стенд — отдельный compose-проект `dataguard-dev`: исходные СУБД, центральные PostgreSQL, ClickHouse и Redpanda, Keycloak и сама платформа. Порты из диапазона `25xxx` слушают только loopback, пароли генерируются в `deployments/dev/.env`. Метрики сервера — http://127.0.0.1:25910/metrics, агента — http://127.0.0.1:25964/metrics. Без демонстрационных данных стенд поднимается так:

```bash
make dev-up
```

Агента можно подключить и вручную, как у заказчика. В разделе «Инфраструктура» выпустите токен и скопируйте его. Команда регистрации спросит токен и прочитает его без вывода на экран, поэтому он не попадёт в историю команд.

```bash
make agent-enroll
```

```bash
make agent-up
```

Источники добавляются там же, в разделе «Источники». Агенту стенда разрешены хосты `source-postgres`, `source-mysql`, `source-mariadb` и `source-mssql` и каталог `/var/log/dg-audit`. Журнал SQL Server лежит на его сервере: `/var/opt/mssql/dg-audit`. Пользователь сканера — `dg_scanner`, пароли лежат в `.env`.

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

Нагрузочные тесты засевают эталонный объём, 100 млн синтетических событий, и проверяют отчёты, поиск и запись по целям из `docs/ROADMAP.md`. Прогон занимает около 4 минут. Для быстрой проверки объём можно уменьшить: `DG_PERF_EVENTS=10000000`.

```bash
make test-performance
```

## CI

GitHub Actions запускает те же команды, что и локально (`.github/workflows/ci.yml`):

- на каждый push и PR — `make check`, проверку, что сгенерированный код совпадает с контрактами, сборку и тесты Dashboard;
- для PR и `main` — поднятие стенда (`make dev-up`), затем `make test-integration` и `make test-e2e`. При падении сохраняются журналы контейнеров платформы и скриншоты браузера. Журналы СУБД и Keycloak не сохраняются: в них могут быть пароли стенда.

Нагрузочные тесты (`.github/workflows/performance.yml`) запускаются раз в неделю и вручную. На диск runner GitHub эталонные 100 млн событий не помещаются, поэтому там засевается 20 млн. Эталонный прогон делается на машине стенда.

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
- `DG_CH_MIGRATION_USER` и `DG_CH_MIGRATION_PASSWORD`;
- `DG_BROKERS`, `DG_BROKER_USER`, `DG_BROKER_PASSWORD` — брокер Redpanda и учётная запись сервера в нём. Необязательно: `DG_BROKER_TOPIC`, `DG_BROKER_GROUP`, `DG_BROKER_CA_FILE` для TLS;
- для `migrate` ещё `DG_BROKER_ADMIN_USER`, `DG_BROKER_ADMIN_PASSWORD` и `DG_BROKER_REPLICATION`: 1 только для стенда, при установке 3 узла и 3. Необязательно: `DG_BROKER_PARTITIONS` (12) и `DG_BROKER_RETENTION` (`168h`);
- `DG_METRICS_ADDR` — необязательно: адрес порта метрик Prometheus, например `:9100`. Порт без аутентификации, открывайте его только во внутренней сети.

Страницы входа рисует провайдер OIDC, а не Dashboard. Для Keycloak есть тема в стиле Dashboard: `deployments/keycloak/themes/dataguard`. Каталог копируется в `/opt/keycloak/themes/dataguard`, в realm выставляется тема входа `dataguard` и русский язык, как в `deployments/dev/keycloak/dataguard-realm.json`. Цвета темы — копия цветов Dashboard, тест Dashboard следит, чтобы они не разошлись. Другой провайдер OIDC показывает свои страницы.

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

Без центра агент копит события в очереди. Событие занимает в ней около 400 байт, поэтому очередь по умолчанию вмещает примерно 650 тыс. событий: 4,5 часа при 40 событиях в секунду, 27 минут при 400. Когда очередь заполнится, агент перестаёт читать журнал, и записи ждут в журнале СУБД. Они теряются, только если СУБД ротирует журнал раньше, и тогда агент сообщает о потере. Срок хранения журнала аудита выбирайте с этим запасом.

```yaml
center:
  url: https://center.example.com:8443
  ca_file: /etc/dataguard/ca/ca.crt
state_dir: /var/lib/dataguard
queue_capacity_bytes: 268435456                        # необязательно: очередь на время недоступности центра, по умолчанию 256 МиБ
allowed:
  hosts: ["10.20.0.0/16", "db.internal", "*.db.corp"]   # сети, адреса, имена, домены
  audit_directories: [/var/log/postgresql]             # откуда можно читать журналы
metrics:                                               # необязательно: порт метрик Prometheus, по умолчанию закрыт
  address: 127.0.0.1:9464
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
