GO_TOOL := go tool -modfile=tools/go.mod
COMPOSE := docker compose --project-name dataguard-dev --env-file deployments/dev/.env -f deployments/dev/compose.yml

.PHONY: check fmt fmt-check lint test test-integration vuln proto proto-lint api dev-env dev-up dev-down build images demo agent-enroll agent-up agent-reset

check: fmt-check proto-lint lint test vuln

build:
	go build -o bin/ ./cmd/...

fmt:
	gofmt -w cmd internal sdk tests

fmt-check:
	@unformatted="$$(gofmt -l cmd internal sdk tests 2>/dev/null)"; \
	if [ -n "$$unformatted" ]; then echo "not formatted:"; echo "$$unformatted"; exit 1; fi

lint:
	$(GO_TOOL) golangci-lint run ./...

test:
	go test -race ./...

test-integration:
	go test -race -tags=integration -count=1 ./tests/... ./internal/...

vuln:
	$(GO_TOOL) govulncheck ./...

proto:
	$(GO_TOOL) buf generate

api:
	$(GO_TOOL) oapi-codegen -config api/openapi/oapi-codegen.yaml api/openapi/dataguard.yaml

proto-lint:
	$(GO_TOOL) buf lint

dev-env:
	./scripts/dev-env.sh

# The whole stand: source databases, the center and its dependencies. The agent
# starts separately, after enrollment.
dev-up: dev-env
	$(COMPOSE) up --detach --build --wait --remove-orphans

images:
	$(COMPOSE) --profile agent --profile check build

# The whole stand with a filled dashboard: accounts, organization, agent,
# sources, data, traffic and scans. Each run starts from an empty stand, so the
# dashboard shows what a new installation does and nothing left from earlier
# runs. Every run prints new passwords. Two calls of make keep the teardown
# before the start even under -j.
demo: dev-env
	$(MAKE) --no-print-directory dev-down
	$(MAKE) --no-print-directory dev-up
	$(COMPOSE) --profile agent build agent
	go run ./scripts/demo

# The token goes to the agent through stdin, so it never appears in the command
# line, the shell history or the image. Without TOKEN_FILE it is asked for.
agent-enroll:
	@if [ -n "$(TOKEN_FILE)" ]; then cat "$(TOKEN_FILE)"; \
	else printf 'Токен регистрации: ' >&2; stty -echo 2>/dev/null; read -r token; stty echo 2>/dev/null; echo >&2; echo "$$token"; fi \
	| $(COMPOSE) run --rm --no-deps -T agent enroll --config /etc/dataguard/agent.yaml --token-file /dev/stdin

agent-up:
	$(COMPOSE) up --detach --no-deps agent

# Removes the agent with its identity and queue, so it can be enrolled again.
agent-reset:
	$(COMPOSE) --profile agent rm --stop --force agent
	docker volume rm --force dataguard-dev_agent-state

# Removes the stand with its data: the volumes and the audit logs that the
# source databases write to the host. A log left behind would be read again
# from its start by the next agent and show old sessions as new events.
dev-down:
	$(COMPOSE) --profile agent --profile check down --volumes
	rm -f deployments/dev/.state/audit/*/*

.PHONY: web web-test

web:
	cd web/dashboard && npm ci --no-audit --no-fund && npm run api && npm run build

web-test:
	cd web/dashboard && npm test

.PHONY: test-e2e test-performance

# Drives the containers of dev-up; the test rebuilds the images it needs.
test-e2e:
	go test -tags=e2e -count=1 -timeout 15m ./tests/e2e/

test-performance:
	go test -tags=performance -count=1 -v ./tests/performance/
