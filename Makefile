.PHONY: all build test test-race test-db lint ai-test run up down

all: lint test

build:
	go build -o bin/admintwin-core ./cmd/admintwin-core

test:
	go test ./...

test-race:
	go test -race -count=1 ./...

# Тест RLS на реальном PostgreSQL: ADMINTWIN_TEST_DATABASE_URL=postgres://... make test-db
test-db:
	go test -count=1 -v ./tests/security/

lint:
	@test -z "$$(gofmt -l cmd internal pkg services tests)" || (gofmt -l cmd internal pkg services tests; exit 1)
	go vet ./...

ai-test:
	cd ai && python3 -m venv .venv && .venv/bin/pip install -q -e '.[dev]' && .venv/bin/ruff check . && .venv/bin/pytest -q

run:
	ADMINTWIN_DEV_AUTH=true ADMINTWIN_SIMULATOR=true ADMINTWIN_FIXTURES=infra/dev/fixtures.yaml go run ./cmd/admintwin-core

up:
	docker compose -f infra/docker/docker-compose.yml up --build -d

down:
	docker compose -f infra/docker/docker-compose.yml down
