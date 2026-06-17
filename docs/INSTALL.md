# HubbleOps Install

HubbleOps should be introduced in shadow mode first. The customer should see repeated-action and loop savings before HubbleOps is allowed to interrupt any production agent.

## Hosted shadow mode

```bash
export OPENAI_BASE_URL=https://api.hubbleops.dev/openai/v1
export HUBBLEOPS_PROJECT_KEY=your_project_key
```

Run a preflight check:

```bash
go run ./cmd/hubbleops doctor -base-url https://api.hubbleops.dev -project "$HUBBLEOPS_PROJECT_KEY"
```

Expected result:

```text
HubbleOps doctor
base_url: https://api.hubbleops.dev
[ok] base_url: https://api.hubbleops.dev
[ok] healthz: {"status":"healthy"}
[ok] tool_check: action=allow
[ok] tool_result: action=allow
```

Production deployments require `X-HubbleOps-API-Key` on proxy and action/tool
event endpoints. See [AUTH.md](AUTH.md) for key creation and project binding.
HubbleOps also fails open by default rather than enforcing unaudited blocks when
receipt writes fail. See [RECEIPT_INVARIANT.md](RECEIPT_INVARIANT.md).
Startup config validation keeps production from booting with unsafe settings.
See [CONFIG_SAFETY.md](CONFIG_SAFETY.md).

## Python action firewall

Use the action wrapper when you want HubbleOps to check actions before execution and record results after execution, not just observe model calls.

From this repo:

```bash
pip install ./sdk/python
```

```python
from hubbleops_agent import HubbleOpsClient

hubbleops = HubbleOpsClient()

@hubbleops.action
def search_docs(query: str):
    return retriever.search(query)

def refund_key(call):
    invoice_id = call["kwargs"]["invoice_id"] if "invoice_id" in call["kwargs"] else call["args"][0]
    amount_cents = call["kwargs"]["amount_cents"] if "amount_cents" in call["kwargs"] else call["args"][1]
    return f"refund:{invoice_id}:{amount_cents}"

@hubbleops.action(
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
npm install ./sdk/javascript/hubbleops-agent
```

```js
const { HubbleOpsClient } = require("./sdk/javascript/hubbleops-agent");

const hubbleops = new HubbleOpsClient();
const searchDocs = hubbleops.action(async function searchDocs(query) {
  return retriever.search(query);
});

const refundCustomer = hubbleops.action(
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

HubbleOps behavior:

- First side-effect action with a new idempotency key is allowed and recorded.
- A repeated side-effect action with the same project and idempotency key becomes `duplicate_side_effect`.
- A `write` action without an idempotency key warns; a `dangerous` action without one is blockable in `block`.
- The pre-execution check response includes a `claim_nonce`; result events must echo it back as `claim_nonce` (the SDK wrappers do this automatically). A failure result that cannot prove ownership of the pending claim does not release it — the short lease expires on its own instead.
- For `money_movement` / `dangerous` actions, a `duplicate_window_seconds` below the 24h default is ignored: the duplicate window is a server-side guarantee for high-stakes actions, not a client preference.
- A money-moving action over `max_amount_cents` is blocked before execution.
- A `dangerous` action with an idempotency key still needs `backup_id` or a valid scoped `capability_token`.
- In `shadow`, HubbleOps returns `action=allow` and `would_action=block`.
- In `block`, HubbleOps returns `429` before the tool executes.
- Every decision includes a receipt and is written to the tamper-evident WAL.

Defaults are production-safe:

- `HUBBLEOPS_FAIL_OPEN=true`: tools continue if HubbleOps is down.
- `HUBBLEOPS_TIMEOUT_SECONDS=1.0`: HubbleOps cannot hang the agent.
- `HUBBLEOPS_CAPTURE_MODE=fingerprint`: args/results are hashed, not stored raw.
- `HUBBLEOPS_LOOP_ACTION=shadow`: detections are recorded, not enforced.
- `HUBBLEOPS_RECEIPT_SIGNING_SECRET`: when set on the proxy, action receipts are Ed25519-signed. The proxy logs its public key on startup; auditors verify with `hubbleops verify-receipts -receipt-public-key <key>` (or `HUBBLEOPS_RECEIPT_PUBLIC_KEY`) without the secret.
- `HUBBLEOPS_ACTION_CAPABILITY_SECRET`: when set on the proxy, high-risk capability tokens can be verified.

To opt in to raw traces for debugging:

```bash
export HUBBLEOPS_ENV=dev
export HUBBLEOPS_CAPTURE_MODE=raw
```

To enable blocking after reviewing shadow data:

```bash
export HUBBLEOPS_LOOP_ACTION=block
```

## Self-hosted local evaluation

Self-hosting is for evaluation and enterprise environments, not the default first customer path.

```bash
make quickstart
```

The full local path is documented in [QUICKSTART.md](QUICKSTART.md). It does not
require OpenAI, Anthropic, Gemini, or any paid provider key.

Use:

```bash
export OPENAI_BASE_URL=http://localhost:8080/openai/v1
```

## Rollout checklist

1. Run hosted shadow mode for at least one real agent path.
2. Verify `hubbleops doctor` is green.
3. Add the tool wrapper to the highest-risk or highest-cost tool path.
4. Add idempotency keys to side-effect tools.
5. Run `hubbleops shadow-report` on WAL traces.
6. Run `hubbleops verify-receipts` on the same WAL export.
7. Review would-block traces and false positives.
8. Enable `warn`, then `block`, only after shadow data is clean.

## Action receipt review

Run the shadow report on WAL JSONL:

```bash
go run ./cmd/hubbleops shadow-report data/wal/*.jsonl
go run ./cmd/hubbleops shadow-report -json data/wal/*.jsonl
```

The report shows would-blocks, duplicate side effects, no-progress events, estimated wasted cost, top tools, and a small review set for false-positive inspection.

Then verify the receipts themselves:

```bash
go run ./cmd/hubbleops verify-receipts data/wal/*.jsonl
go run ./cmd/hubbleops verify-receipts -json data/wal/*.jsonl
```

The verifier checks record hashes, WAL chain continuity, and required action decision fields. A failed verification means the export is not trustworthy enough for enforcement decisions.

## Real shadow proof

Export real shadow traces, anonymize them, and run the quality gates:

```bash
go run ./cmd/hubbleops eval raw-shadow.jsonl \
  -anonymize-out testdata/real_shadow/customer-a.jsonl \
  -salt "$HUBBLEOPS_ANON_SALT"

go run ./cmd/hubbleops eval -assert testdata/real_shadow/customer-a.jsonl
```

The number that matters for production is not synthetic pass count. It is real-trace recall, precision, false-positive block rate, missed-runaway rate, decision latency, and saved cost.

## Live Gemini validation

Copy `.env.example` to a local `.env` and set temporary Gemini keys there:

```bash
cp .env.example .env
```

Run the gated live proxy checks:

```bash
HUBBLEOPS_LIVE_GEMINI=1 \
HUBBLEOPS_LIVE_GEMINI_MODEL=gemini-2.5-flash-lite \
go test ./internal/proxy -run TestLiveGemini -count=1 -v
```

Run the live Gemini agent action-firewall check:

```bash
HUBBLEOPS_LIVE_GEMINI=1 \
HUBBLEOPS_LIVE_GEMINI_AGENT=1 \
HUBBLEOPS_LIVE_GEMINI_MODEL=gemini-2.5-flash \
go test ./internal/proxy -run TestLiveGeminiAgentActionFirewallDuplicateAndDangerous -count=1 -v
```

Run the small concurrency/WAL soak:

```bash
HUBBLEOPS_LIVE_GEMINI=1 \
HUBBLEOPS_LIVE_GEMINI_SOAK=1 \
HUBBLEOPS_LIVE_GEMINI_MODEL=gemini-2.5-flash-lite \
go test ./internal/proxy -run TestLiveGeminiProxyMiniSoakConcurrentWAL -count=1 -v
```

These tests verify real Gemini non-streaming, streaming, function-call extraction, invalid-key WAL behavior, token/cost capture, and WAL hash-chain integrity under concurrent live requests.
