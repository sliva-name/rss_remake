GO_TOOL := go tool -modfile=tools/go.mod
COMPOSE := docker compose --project-name dataguard-dev --env-file deployments/dev/.env -f deployments/dev/compose.yml

.PHONY: check fmt fmt-check lint test test-integration vuln proto proto-lint api dev-env dev-up dev-down build

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

dev-up: dev-env
	$(COMPOSE) up --detach --build --wait

dev-down:
	$(COMPOSE) down --volumes
