.PHONY: all build test test-race test-db lint ai-test run up down

all: lint test

build:
	go build -o bin/admintwin-core ./cmd/admintwin-core

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

# Тесты на реальном PostgreSQL (каждый пересоздаёт схему в своей БД):
#   ADMINTWIN_TEST_DATABASE_URL=postgres://.../admintwin_test ADMINTWIN_TEST_STORE_URL=postgres://.../admintwin_store make test-db
test-db:
	go test -count=1 -v ./tests/security/
	go test -count=1 -v -run TestPostgresStore ./tests/e2e/
	go test -count=1 -v -run PG ./services/incidents/   # ADMINTWIN_TEST_INCIDENTS_DB_URL
	go test -count=1 -v -run TestIntegrationPostgres ./connectors/db/   # ADMINTWIN_TEST_PG_CONNECTOR_URL (read-only роль с паролем)

lint:
	@test -z "$$(gofmt -l cmd internal pkg services tests)" || (gofmt -l cmd internal pkg services tests; exit 1)
	go vet ./...

ai-test:
	cd ai && python3 -m venv .venv && .venv/bin/pip install -q -e '.[dev]' && .venv/bin/ruff check . && .venv/bin/mypy && .venv/bin/pytest -q && bash scripts/ci_eval_gate.sh

run:
	ADMINTWIN_DEV_AUTH=true ADMINTWIN_SIMULATOR=true ADMINTWIN_FIXTURES=infra/dev/fixtures.yaml go run ./cmd/admintwin-core

up:
	docker compose -f infra/docker/docker-compose.yml up --build -d

down:
	docker compose -f infra/docker/docker-compose.yml down
