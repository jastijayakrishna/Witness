SHELL := bash
.SHELLFLAGS := -euo pipefail -c

HUBBLEOPS ?= go run ./cmd/hubbleops
GATE ?= go run ./cmd/gate
PLAN ?= internal/preflight/terraform/testdata/datatalks_destroy_plan.json
POLICY ?= configs/policy.yaml.example
WAL_DIR ?= data/wal
ACTION_LEDGER ?= data/action-ledger.json
APPROVAL_STORE ?= data/approvals.json

.PHONY: preflight-terraform preflight-deploy phase4-demo gate verify-receipts evidence-pack test sqlparse-build

# Build the optional SQL parse-validity oracle (separate module; Linux + cgo, Go >= 1.26.4).
# Its heavy parser deps live in internal/sqlparse and never touch the root module graph.
sqlparse-build:
	cd internal/sqlparse && go mod tidy && CGO_ENABLED=1 go build -o hubbleops-sqlparse .
	@echo "built internal/sqlparse/hubbleops-sqlparse; wire it via HUBBLEOPS_SQLPARSE_BIN"

preflight-terraform:
	$(HUBBLEOPS) preflight terraform $(PLAN) \
		-policy $(POLICY) \
		-wal-dir $(WAL_DIR) \
		-project demo \
		-session demo-preflight \
		-actor agent:local-cli \
		-human-delegator local \
		-env production \
		-intent "demo protected destroy"

preflight-deploy:
	$(HUBBLEOPS) preflight deploy \
		-service billing-api \
		-artifact demo-sha \
		-idempotency-key deploy:demo-sha \
		-policy $(POLICY) \
		-wal-dir $(WAL_DIR) \
		-action-ledger $(ACTION_LEDGER) \
		-project demo \
		-session demo-deploy \
		-actor agent:local-cli \
		-human-delegator local \
		-env production

phase4-demo:
	$(HUBBLEOPS) demo phase4 \
		-wal-dir data/phase4-demo/wal \
		-approval-store data/phase4-demo/approvals.json

gate:
	$(GATE) \
		-policy $(POLICY) \
		-wal-dir $(WAL_DIR) \
		-approval-store $(APPROVAL_STORE)

verify-receipts:
	$(HUBBLEOPS) verify-receipts data/wal/*.jsonl

evidence-pack:
	$(HUBBLEOPS) evidence-pack data/wal/*.jsonl

test:
	go test ./...
