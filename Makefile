PYTHON := .venv/bin/python
RUFF := .venv/bin/ruff
MYPY := .venv/bin/mypy
PYTEST := .venv/bin/pytest
ALEMBIC := .venv/bin/alembic
COMPOSE := docker compose -f infra/compose.yaml

.PHONY: bootstrap services-up services-down lint format format-check typecheck db-migrate db-migrate-check test-unit test-contract test-security phase run

bootstrap:
	@test -d .venv || python3 -m venv .venv
	@$(PYTHON) -m pip install --disable-pip-version-check -e '.[dev]'

services-up:
	@$(COMPOSE) up -d --wait postgres redis

services-down:
	@$(COMPOSE) down

lint:
	@$(RUFF) check .

format:
	@$(RUFF) format .

format-check:
	@$(RUFF) format --check .

typecheck:
	@$(MYPY)

db-migrate: services-up
	@$(ALEMBIC) -c backend/alembic.ini upgrade head

db-migrate-check: services-up
	@NEXORA_ENVIRONMENT=test NEXORA_ALLOW_DESTRUCTIVE_MIGRATION_CHECK=true $(PYTHON) scripts/codex/migration_check.py

test-unit:
	@$(PYTEST) -q -m unit

test-contract:
	@$(PYTEST) -q -m contract

test-security: db-migrate
	@$(PYTEST) -q -m security

phase:
	@test "$(PHASE)" = "01" || (echo "PHASE must be exactly 01" >&2; exit 2)
	@$(MAKE) db-migrate
	@$(PYTEST) -q

run:
	@$(PYTHON) -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8091
