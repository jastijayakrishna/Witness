SHELL := bash
.SHELLFLAGS := -euo pipefail -c

COMPOSE ?= docker compose -f deploy/docker-compose.yml
HUBBLEOPS ?= go run ./cmd/hubbleops
BASE_URL ?= http://localhost:8080

.PHONY: check-prereqs up quickstart doctor test

check-prereqs:
	bash scripts/check-prereqs.sh

up:
	$(COMPOSE) up --build -d

doctor:
	$(HUBBLEOPS) doctor -base-url $(BASE_URL)

quickstart: check-prereqs up
	@echo "Waiting for HubbleOps to become ready..."
	@tmp="$${TMPDIR:-/tmp}/hubbleops-doctor.log"; \
	for i in $$(seq 1 60); do \
		if $(HUBBLEOPS) doctor -base-url $(BASE_URL) > "$$tmp" 2>&1; then \
			cat "$$tmp"; \
			break; \
		fi; \
		if [ "$$i" -eq 60 ]; then \
			cat "$$tmp"; \
			echo "HubbleOps did not become ready. Run: docker compose -f deploy/docker-compose.yml logs proxy" >&2; \
			exit 1; \
		fi; \
		sleep 2; \
	done

test:
	go test ./...
