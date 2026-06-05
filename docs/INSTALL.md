# Witness Install

Witness should be introduced in shadow mode first. The customer should see repeated-action and loop savings before Witness is allowed to interrupt any production agent.

## Hosted shadow mode

```bash
export OPENAI_BASE_URL=https://api.witness.dev/openai/v1
export WITNESS_PROJECT_KEY=your_project_key
```

Run a preflight check:

```bash
go run ./cmd/witness doctor -base-url https://api.witness.dev -project "$WITNESS_PROJECT_KEY"
```

Expected result:

```text
Witness doctor
base_url: https://api.witness.dev
[ok] base_url: https://api.witness.dev
[ok] healthz: {"status":"healthy"}
[ok] tool_check: action=allow
[ok] tool_result: action=allow
```

## Python action firewall

Use the action wrapper when you want Witness to check actions before execution and record results after execution, not just observe model calls.

From this repo:

```bash
pip install ./sdk/python
```

```python
from witness_agent import WitnessClient

witness = WitnessClient()

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

## JavaScript action firewall

From this repo:

```bash
npm install ./sdk/javascript/witness-agent
```

```js
const { WitnessClient } = require("./sdk/javascript/witness-agent");

const witness = new WitnessClient();
const searchDocs = witness.action(async function searchDocs(query) {
  return retriever.search(query);
});

const refundCustomer = witness.action(
  async function refundCustomer(invoiceId, amountCents) {
    return payments.refund(invoiceId, amountCents);
  },
  {
    risk: "write",
    idempotencyKey: ({ args }) => `refund:${args[0]}:${args[1]}`,
    resourceId: ({ args }) => args[0],
    amountCents: ({ args }) => args[1],
    maxAmountCents: 5000,
  }
);
```

For read-only tools, `risk` defaults to `read`. For customer-visible or money-moving tools, set `risk` to `write`, `customer_visible`, `money_movement`, or `dangerous`, and pass a stable `idempotency_key` for the real-world action being attempted.

Witness behavior:

- First side-effect action with a new idempotency key is allowed and recorded.
- A repeated side-effect action with the same project and idempotency key becomes `duplicate_side_effect`.
- A `write` action without an idempotency key warns; a `dangerous` action without one is blockable in `block`.
- A money-moving action over `max_amount_cents` is blocked before execution.
- A `dangerous` action with an idempotency key still needs `backup_id` or a valid scoped `capability_token`.
- In `shadow`, Witness returns `action=allow` and `would_action=block`.
- In `block`, Witness returns `429` before the tool executes.
- Every decision includes a receipt and is written to the tamper-evident WAL.

Defaults are production-safe:

- `WITNESS_FAIL_OPEN=true`: tools continue if Witness is down.
- `WITNESS_TIMEOUT_SECONDS=1.0`: Witness cannot hang the agent.
- `WITNESS_CAPTURE_MODE=fingerprint`: args/results are hashed, not stored raw.
- `WITNESS_LOOP_ACTION=shadow`: detections are recorded, not enforced.
- `WITNESS_RECEIPT_SIGNING_SECRET`: when set on the proxy, action receipts include HMAC signatures.
- `WITNESS_ACTION_CAPABILITY_SECRET`: when set on the proxy, high-risk capability tokens can be verified.

To opt in to raw traces for debugging:

```bash
export WITNESS_CAPTURE_MODE=raw
```

To enable blocking after reviewing shadow data:

```bash
export WITNESS_LOOP_ACTION=block
```

## Self-hosted local demo

Self-hosting is for evaluation and enterprise environments, not the default first customer path.

```bash
docker compose -f deploy/docker-compose.yml up --build
go run ./cmd/witness doctor -base-url http://localhost:8080
```

Use:

```bash
export OPENAI_BASE_URL=http://localhost:8080/openai/v1
```

## Rollout checklist

1. Run hosted shadow mode for at least one real agent path.
2. Verify `witness doctor` is green.
3. Add the tool wrapper to the highest-risk or highest-cost tool path.
4. Add idempotency keys to side-effect tools.
5. Run `witness shadow-report` on WAL traces.
6. Run `witness verify-receipts` on the same WAL export.
7. Review would-block traces and false positives.
8. Enable `warn`, then `block`, only after shadow data is clean.

## Action receipt review

Run the shadow report on WAL JSONL:

```bash
go run ./cmd/witness shadow-report data/wal/*.jsonl
go run ./cmd/witness shadow-report -json data/wal/*.jsonl
```

The report shows would-blocks, duplicate side effects, no-progress events, estimated wasted cost, top tools, and a small review set for false-positive inspection.

Then verify the receipts themselves:

```bash
go run ./cmd/witness verify-receipts data/wal/*.jsonl
go run ./cmd/witness verify-receipts -json data/wal/*.jsonl
```

The verifier checks record hashes, WAL chain continuity, and required action decision fields. A failed verification means the export is not trustworthy enough for enforcement decisions.

## Real shadow proof

Export real shadow traces, anonymize them, and run the quality gates:

```bash
go run ./cmd/witness eval raw-shadow.jsonl \
  -anonymize-out testdata/real_shadow/customer-a.jsonl \
  -salt "$WITNESS_ANON_SALT"

go run ./cmd/witness eval -assert testdata/real_shadow/customer-a.jsonl
```

The number that matters for production is not synthetic pass count. It is real-trace recall, precision, false-positive block rate, missed-runaway rate, decision latency, and saved cost.

## Live Gemini validation

Set a temporary Gemini key in `.env`:

```env
GOOGLE_API_KEY=...
GEMINI_API_KEY=...
```

Run the gated live proxy checks:

```bash
go run ./cmd/witness provider-doctor \
  -provider gemini \
  -model gemini-2.5-flash-lite
```

Expected result:

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

Then run the gated live proxy checks:

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

Run the small concurrency/WAL soak:

```bash
WITNESS_LIVE_GEMINI=1 \
WITNESS_LIVE_GEMINI_SOAK=1 \
WITNESS_LIVE_GEMINI_MODEL=gemini-2.5-flash-lite \
go test ./internal/proxy -run TestLiveGeminiProxyMiniSoakConcurrentWAL -count=1 -v
```

These tests verify real Gemini non-streaming, streaming, function-call extraction, invalid-key WAL behavior, token/cost capture, and WAL hash-chain integrity under concurrent live requests.
