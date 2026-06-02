# Argus - common developer tasks.
#
# Usage:
#   make run     # run the exporter locally against config.yaml
#   make test    # run the unit tests
#   make up      # bring up the full docker-compose stack
#   make down    # tear the stack down
#
# On Windows, run these from Git Bash / WSL, or just run the underlying
# commands shown below directly in PowerShell.

PYTHON ?= python
COMPOSE ?= docker compose
COMPOSE_FILE ?= deploy/docker-compose.yml
CONFIG ?= config.yaml

.PHONY: help run test up down logs build clean config

help:
	@echo "Argus targets:"
	@echo "  make run     - run the exporter locally (serves /metrics on :9882)"
	@echo "  make test    - run unit tests with pytest"
	@echo "  make up      - docker compose up (argus + prometheus + grafana + alertmanager)"
	@echo "  make down    - docker compose down (and remove volumes)"
	@echo "  make logs    - tail the stack logs"
	@echo "  make build   - build the argus docker image"
	@echo "  make config  - create config.yaml from the example if missing"
	@echo "  make clean   - remove caches and local report output"

# Ensure a config.yaml exists (copy from the example on first run).
config:
	@test -f $(CONFIG) || (cp config.example.yaml $(CONFIG) && echo "Created $(CONFIG) from example")

run: config
	$(PYTHON) -m argus.exporter --config $(CONFIG)

test:
	$(PYTHON) -m pytest tests/ -v

up: config
	$(COMPOSE) -f $(COMPOSE_FILE) up --build

down:
	$(COMPOSE) -f $(COMPOSE_FILE) down -v

logs:
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f

build:
	$(COMPOSE) -f $(COMPOSE_FILE) build

clean:
	rm -rf .pytest_cache __pycache__ argus/__pycache__ argus/collectors/__pycache__ \
	       tests/__pycache__ reports out *.sarif
