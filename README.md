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
