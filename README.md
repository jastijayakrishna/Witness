# Witness Action Firewall

Witness stops AI agents from repeating dangerous or useless actions before they execute, and produces a tamper-evident receipt for every decision.

It sits in front of LLM and tool calls. For tools, Witness acts as a pre-execution action firewall: legitimate reads pass through, repeated side-effect attempts are caught with idempotency keys, no-progress loops are detected from results, and every allow/warn/block decision is written to a hash-chained WAL.

## The Problem

Agent loops are expensive, risky, and hard to debug:

- An agent retries the same tool with the same bad args.
- An agent repeats the same customer-visible side effect, such as sending an email, refunding an invoice, opening a ticket, or triggering a deploy.
- A dangerous action is attempted without a stable idempotency key.
- A tool keeps returning `not_found`, `permission_error`, `timeout`, or `rate_limited`.
- The model keeps spending tokens while making no state progress.
- Operators only notice after the bill, duplicate action, or incident.

Witness is built for one job: **send legitimate work through, stop repeated dangerous or useless actions before execution, and prove every decision with an audit trail.**

## Current Status

Production-shaped MVP:

- OpenAI, Anthropic, and Gemini proxy support
- Streaming and non-streaming usage capture
- Pre-execution action firewall for tool calls
- Postgres-backed durable action ledger for duplicate side-effect prevention
- Tool-event fuse for pre-tool and post-tool loop detection
- Redis-backed loop state with detector version `2.2.0`
- Shadow, warn, and block modes
- Decision receipts with `decision_id`, `policy_version`, `action_risk`, effect scope, reason, evidence, and optional HMAC signature
- Fail-open SDK defaults
- Budget seatbelt with atomic Redis reservations
- Tamper-evident JSONL WAL with hash chaining
- Separate WAL drain worker for Postgres reconciliation
- Provider doctor for Gemini key/model/quota/pricing checks
- Shadow report for would-block review and first policy recommendation
- Receipt verifier for hash-chain, decision-field, and signed-receipt integrity
- Real-trace eval harness for recall, precision, missed runaways, false positives, latency, and saved cost

Brutal honest status: the repo is technically strong enough for MVP. The remaining proof gap is real customer shadow traces.

## Fastest Safe Rollout

Use hosted Witness if you have a provisioned endpoint:

```bash
export WITNESS_BASE_URL=https://YOUR_WITNESS_ENDPOINT
export WITNESS_PROJECT_KEY=your_project_key
```

Run the Witness preflight:

```bash
go run ./cmd/witness doctor \
  -base-url "$WITNESS_BASE_URL" \
  -project "$WITNESS_PROJECT_KEY"
```

Expected shape:

```text
Witness doctor
base_url: https://YOUR_WITNESS_ENDPOINT
[ok] base_url: https://YOUR_WITNESS_ENDPOINT
[ok] healthz: {"status":"healthy"}
[ok] tool_check: action=allow
[ok] tool_result: action=allow
```

Then route model calls through Witness:

```bash
export OPENAI_BASE_URL="$WITNESS_BASE_URL/openai/v1"
```

Shadow mode is the default. Witness records what it would warn or block without interrupting the agent.

## Local Demo

```bash
docker compose -f deploy/docker-compose.yml up --build
```

Services:

- Proxy: `http://localhost:8080`
- WAL drain metrics: `http://localhost:9090/metrics`
- Postgres: `localhost:5433`
- Redis: `localhost:6380`

Verify:

```bash
go run ./cmd/witness doctor -base-url http://localhost:8080
curl http://localhost:8080/healthz
curl http://localhost:8080/metrics
```

## Provider Preflight

For Gemini, put a temporary key in `.env`:

```env
GOOGLE_API_KEY=...
```

Then verify key validity, model access, quota, and pricing:

```bash
go run ./cmd/witness provider-doctor \
  -provider gemini \
  -model gemini-2.5-flash-lite
```

Expected shape:

```text
Witness provider doctor
provider: gemini
model: gemini-2.5-flash-lite
base_url: https://generativelanguage.googleapis.com
[ok] api_key: present
[ok] base_url: https://generativelanguage.googleapis.com
[ok] model_status: active_or_not_known_deprecated
[ok] pricing_known: cost can be computed
[ok] models_list: models_visible=...
[ok] model_available: gemini-2.5-flash-lite visible
[ok] quota_generate_content: status=200 model_version=... total_tokens=...
```

## Proxy Examples

OpenAI:

```bash
curl http://localhost:8080/openai/v1/chat/completions \
  -H "Authorization: Bearer YOUR_OPENAI_KEY" \
  -H "X-Project: my-project" \
  -H "X-Session-ID: sess-123" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [{"role": "user", "content": "Hello"}],
    "stream": true
  }'
```

Anthropic:

```bash
curl http://localhost:8080/anthropic/v1/messages \
  -H "x-api-key: YOUR_ANTHROPIC_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "X-Project: my-project" \
  -H "X-Session-ID: sess-123" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-3-5-sonnet-20241022",
    "messages": [{"role": "user", "content": "Hello"}],
    "max_tokens": 100
  }'
```

Gemini:

```bash
curl http://localhost:8080/gemini/v1beta/models/gemini-2.5-flash-lite:generateContent \
  -H "x-goog-api-key: YOUR_GOOGLE_API_KEY" \
  -H "X-Project: my-project" \
  -H "X-Session-ID: sess-123" \
  -H "Content-Type: application/json" \
  -d '{
    "contents": [{
      "parts": [{"text": "Hello"}]
    }]
  }'
```

## Action Firewall

The proxy sees model calls. The action firewall checks consequential actions before execution and records results after execution, which is where agent loops and duplicate side effects become obvious.

Python:

```python
from witness_agent import WitnessClient

witness = WitnessClient(
    base_url="http://localhost:8080",
    project="my-project",
    session_id="sess-123",
)

@witness.action
def search_docs(query: str):
    return retriever.search(query)

def refund_key(call):
    invoice_id = call["kwargs"]["invoice_id"] if "invoice_id" in call["kwargs"] else call["args"][0]
    amount_cents = call["kwargs"]["amount_cents"] if "amount_cents" in call["kwargs"] else call["args"][1]
    return f"refund:{invoice_id}:{amount_cents}"

@witness.action(
    risk="money_movement",
    idempotency_key=refund_key,
    resource_id=lambda call: call["kwargs"].get("invoice_id") or call["args"][0],
    amount_cents=lambda call: call["kwargs"].get("amount_cents") or call["args"][1],
    max_amount_cents=5000,
)
def refund_customer(invoice_id: str, amount_cents: int):
    return payments.refund(invoice_id, amount_cents)
```

JavaScript:

```js
const { WitnessClient } = require("./sdk/javascript/witness-agent");

const witness = new WitnessClient({
  baseUrl: "http://localhost:8080",
  project: "my-project",
  sessionId: "sess-123",
});

const searchDocs = witness.action(async function searchDocs(query) {
  return retriever.search(query);
});

const refundCustomer = witness.action(
  async function refundCustomer(invoiceId, amountCents) {
    return payments.refund(invoiceId, amountCents);
  },
  {
    risk: "money_movement",
    idempotencyKey: ({ args }) => `refund:${args[0]}:${args[1]}`,
    resourceId: ({ args }) => args[0],
    amountCents: ({ args }) => args[1],
    maxAmountCents: 5000,
  }
);
```

For read-only tools, `risk` defaults to `read` and no idempotency key is required. For side-effect tools, set `risk` to `write`, `customer_visible`, `money_movement`, or `dangerous`, and pass a stable `idempotency_key` for the real-world action being attempted.

The `/v1/action/check` endpoint is the pre-execution gate. SDK wrappers call it before the action runs. The `/v1/action/result` endpoint records what happened after the action runs. `/v1/tool/check` and `/v1/tool/result` remain as compatibility aliases.

Direct API:

```bash
curl http://localhost:8080/v1/action/check \
  -H "X-Project: my-project" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "sess-123",
    "action_name": "refund_customer",
    "action_risk": "money_movement",
    "idempotency_key": "refund:invoice_9:5000",
    "resource_id": "invoice_9",
    "amount_cents": 5000,
    "max_amount_cents": 5000,
    "args": {"invoice_id": "invoice_9", "amount_cents": 5000}
  }'
```

Important request fields:

| Field | Purpose |
| --- | --- |
| `action_name` | Name of the real-world action being attempted. |
| `action_risk` | `read`, `write`, `customer_visible`, `money_movement`, or `dangerous`. |
| `idempotency_key` | Stable key for the real-world side effect, such as `refund:invoice_9:5000`. |
| `resource_id` | Optional real-world object being touched, such as an invoice, account, ticket, or deployment. |
| `amount_cents`, `max_amount_cents` | Optional money/action bound. Witness blocks when `amount_cents` exceeds the declared maximum. |
| `backup_id` | Required safety prerequisite for `dangerous` actions unless a valid capability token is supplied. |
| `recipient`, `allowed_domain` | Optional customer-visible guard. Witness blocks when the recipient domain is outside policy. |
| `capability_token` | Optional HMAC-scoped authority for high-risk actions. Verified with `WITNESS_ACTION_CAPABILITY_SECRET`. |
| `duplicate_window_seconds` | Optional duplicate window. Defaults to 24 hours. |
| `agent_id`, `user_id` | Optional attribution fields for receipts and review. |

Duplicate side-effect rule:

- First `write`/`dangerous` action with a new idempotency key is allowed and recorded.
- A repeated action with the same project and idempotency key is a high-confidence `duplicate_side_effect`.
- A `write` action without an idempotency key warns; a `dangerous` action without one is blockable in `block` mode.
- A money-moving action over `max_amount_cents` is blocked before execution.
- A dangerous action with an idempotency key still needs `backup_id` or a valid scoped `capability_token`.
- In `shadow` mode, Witness allows the action but records `would_action=block`.
- In `block` mode, Witness returns `429` before the tool executes.

Every decision response includes a receipt:

```json
{
  "action": "allow",
  "action_name": "refund_customer",
  "would_action": "block",
  "reason": "duplicate side-effect blocked: idempotency key was already seen",
  "receipt": {
    "decision_id": "sha256...",
    "action_name": "refund_customer",
    "policy_version": "action-firewall/2",
    "action_risk": "write",
    "idempotency_key": "refund:invoice_9:5000",
    "resource_id": "invoice_9",
    "amount_cents": 5000,
    "max_amount_cents": 5000,
    "evidence": ["idempotency_key=repeated", "duplicate_window=24h0m0s"],
    "signature": "witreceipt_v1...",
    "key_id": "prod-2026-06"
  }
}
```

SDK defaults are production-safe:

- `WITNESS_FAIL_OPEN=true`: tools continue if Witness is down.
- `WITNESS_CAPTURE_MODE=fingerprint`: args and results are hashed by default.
- `WITNESS_TIMEOUT_SECONDS=1.0` for Python and `WITNESS_TIMEOUT_MS=1000` for JavaScript.
- Raw capture is opt-in with `WITNESS_CAPTURE_MODE=raw`.

## Loop Detection

Witness combines mechanical loop signals with economic signals:

- identical repeated calls
- alternating repeated calls
- no-op repeated results
- cycle repeats
- argument homogeneity
- result homogeneity
- cost velocity
- context growth
- output degradation
- no-progress result classes such as `not_found`, `schema_error`, `permission_error`, `timeout`, and `rate_limited`

Actions:

| Action | Behavior |
| --- | --- |
| `shadow` | Record what Witness would do. Default and recommended first rollout. |
| `warn` | Allow request and emit warning behavior/metrics. |
| `block` | Return 429 when confidence and safety gates pass. |

Blocking is intentionally conservative. High-confidence block decisions require session context and corroborating no-progress evidence.

## Audit Trail

Every proxied request writes a WAL record before the response returns.

The WAL includes:

- project, provider, model, status code
- input/output/total tokens and computed cost
- prompt hash
- session ID and trajectory ID
- tool signature and args fingerprint
- decision ID
- agent ID and user ID
- action risk and idempotency key
- resource ID, amount bounds, backup ID, recipient domain, allowed domain, and capability hash
- policy version, decision reason, and decision evidence
- receipt signature and signing key ID when `WITNESS_RECEIPT_SIGNING_SECRET` is set
- result class and immediate outcome
- loop signals, confidence, action, evidence, detector version
- previous hash and record hash

Hash-chain violations halt the drain worker and increment `llmproxy_wal_chain_violation_total`.

Verify exported receipts:

```bash
go run ./cmd/witness verify-receipts data/wal/*.jsonl
go run ./cmd/witness verify-receipts -json data/wal/*.jsonl
WITNESS_RECEIPT_SIGNING_SECRET=... go run ./cmd/witness verify-receipts -require-signatures data/wal/*.jsonl
```

Expected shape:

```text
Witness receipt verify
records=18421 action_receipts=9120 signed_receipts=9120 unsigned_receipts=0 verified=true
missing_hashes=0 hash_mismatches=0 signature_mismatches=0 chain_broken_at=-1 receipt_field_gaps=0
```

## Shadow Report

Shadow mode is how you prove the product before enforcing it. Run a report over WAL JSONL to see would-blocks, blocked actions, duplicate side effects, no-progress events, estimated wasted cost, and the first policy Witness recommends enabling.

```bash
go run ./cmd/witness shadow-report data/wal/*.jsonl
go run ./cmd/witness shadow-report -json data/wal/*.jsonl
```

Expected shape:

```text
Witness shadow report
records=18421 tool_events=9120 action_receipts=9120
would_block=37 blocked=0 duplicate_side_effects=9 no_progress_events=141
estimated_wasted_cost_usd=18.420000
recommended_first_policy=block duplicate side-effect actions with stable idempotency keys
```

## Proving It On Real Traces

Synthetic tests are useful, but the production proof is shadow data.

Export real shadow traces, anonymize them, then run quality gates:

```bash
go run ./cmd/witness eval raw-shadow.jsonl \
  -anonymize-out testdata/real_shadow/customer-a.jsonl \
  -salt "$WITNESS_ANON_SALT"

go run ./cmd/witness eval -assert testdata/real_shadow/customer-a.jsonl
```

The numbers that matter:

- runaway recall
- block precision
- false-positive block rate
- missed-runaway rate
- replay p95 decision latency
- saved cost

This is the bar for claiming production readiness.

## Configuration

Environment variables:

```bash
WITNESS_SERVER_HOST=0.0.0.0
WITNESS_SERVER_PORT=8080

WITNESS_POSTGRES_HOST=localhost
WITNESS_POSTGRES_PORT=5432
WITNESS_POSTGRES_USER=witness
WITNESS_POSTGRES_PASSWORD=witness
WITNESS_POSTGRES_DBNAME=witness
WITNESS_POSTGRES_SSLMODE=disable

WITNESS_REDIS_HOST=localhost
WITNESS_REDIS_PORT=6379
WITNESS_REDIS_PASSWORD=
WITNESS_REDIS_DB=0

WITNESS_WAL_DIR=data/wal
WITNESS_WAL_SYNC_MODE=batch

WITNESS_LOOP_ENABLED=true
WITNESS_LOOP_ACTION=shadow
WITNESS_LOOP_MAX_REPEATED=3
WITNESS_LOOP_VELOCITY_ACCEL_RATIO=1.5
WITNESS_LOOP_VELOCITY_WINDOW_MS=300000
WITNESS_LOOP_WARN_CONFIDENCE=0.40
WITNESS_LOOP_BLOCK_CONFIDENCE=0.70
WITNESS_LOOP_REQUIRE_SESSION_FOR_BLOCK=true

WITNESS_BUDGET_DAILY_SOFT_USD=0
WITNESS_BUDGET_DAILY_HARD_USD=0
WITNESS_BUDGET_RESERVE_PER_REQUEST_USD=0.50
```

Or edit `configs/proxy.yaml`.

## Development

Build:

```bash
go build ./...
```

Run tests:

```bash
go test ./...
go test ./internal/proxy/... -v
node --check sdk/javascript/witness-agent/index.js
python -m py_compile sdk/python/witness_agent/langchain.py sdk/python/witness_agent/__init__.py
go test ./... -bench=. -benchmem
```

Run gated live Gemini checks:

```bash
WITNESS_LIVE_GEMINI=1 \
WITNESS_LIVE_GEMINI_MODEL=gemini-2.5-flash-lite \
go test ./internal/proxy -run TestLiveGemini -count=1 -v
```

Run the live Gemini agent action-firewall check:

```bash
WITNESS_LIVE_GEMINI=1 \
WITNESS_LIVE_GEMINI_AGENT=1 \
WITNESS_LIVE_GEMINI_MODEL=gemini-2.5-flash \
go test ./internal/proxy -run TestLiveGeminiAgentActionFirewallDuplicateAndDangerous -count=1 -v
```

Run the live Gemini mini-soak:

```bash
WITNESS_LIVE_GEMINI=1 \
WITNESS_LIVE_GEMINI_SOAK=1 \
WITNESS_LIVE_GEMINI_MODEL=gemini-2.5-flash-lite \
go test ./internal/proxy -run TestLiveGeminiProxyMiniSoakConcurrentWAL -count=1 -v
```

## Project Layout

```text
cmd/proxy                 Main proxy binary
cmd/waldrain              Separate WAL drain worker
cmd/witness               Doctor, provider-doctor, trace eval, shadow report, receipt verify CLI
internal/config           YAML config and WITNESS_* env overrides
internal/providers        OpenAI, Anthropic, Gemini, pricing, usage extraction
internal/proxy            HTTP proxy, streaming, action events, attribution
internal/loop             Loop detector, Redis state, budgets, overrides, alerts
internal/wal              JSONL writer, hash chain, crash recovery
internal/storage          Postgres schema and migrations
internal/loopeval         Real shadow trace evaluator
internal/receiptverify    WAL receipt integrity verifier
sdk/python/witness_agent  Python action firewall SDK
sdk/javascript/witness-agent JavaScript action firewall SDK
docs/INSTALL.md           One-page rollout guide
```

## What Not To Add Yet

Do not add a dashboard, new providers, or complex enterprise policy UI before real shadow data.

The next highest-value work is:

1. Run shadow mode on 3 real users or projects.
2. Collect at least 100 real traces.
3. Report false positives, missed runaways, and saved cost.
4. Tighten detector thresholds from real labels.

## License

Apache 2.0
