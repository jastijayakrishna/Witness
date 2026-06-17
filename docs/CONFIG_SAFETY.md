# Configuration Safety

HubbleOps validates startup configuration before it opens storage connections or
serves traffic. Production must be secure by default. Development can stay
convenient, but unsafe settings produce loud startup warnings.

## Environment

Set `HUBBLEOPS_ENV` to one of:

- `dev`: local development and the Docker stack.
- `test`: automated tests and temporary CI environments.
- `prod`: customer, investor, or hosted production deployments.

The default is `prod`, so an unset environment cannot accidentally disable
security controls.

## Production Requirements

In `prod`, HubbleOps refuses to start unless:

- `HUBBLEOPS_AUTH_ENABLED=true`
- `HUBBLEOPS_DEV_AUTH_BYPASS=false`
- `HUBBLEOPS_METRICS_PUBLIC=false`
- `HUBBLEOPS_WAL_DIR` is set
- `HUBBLEOPS_RECEIPT_SIGNING_SECRET` is set
- `HUBBLEOPS_REQUIRE_RECEIPT_FOR_BLOCK=true`
- `HUBBLEOPS_CAPTURE_MODE` is `fingerprint`
- block mode keeps `HUBBLEOPS_LOOP_REQUIRE_SESSION_FOR_BLOCK=true`

The emergency setting `HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT=true` remains available,
but startup logs a critical warning because it can enforce unaudited blocks.

## Development Behavior

In `dev` and `test`, HubbleOps does not fail startup for local conveniences such
as public metrics, disabled auth, dev auth bypass, unsigned receipts, or raw
capture. Each unsafe setting is logged as a warning.

The local Docker stack sets:

```bash
HUBBLEOPS_ENV=dev
HUBBLEOPS_DEV_AUTH_BYPASS=true
HUBBLEOPS_METRICS_PUBLIC=true
```

Do not use those settings for production.

## Capture Mode

Use:

```bash
HUBBLEOPS_CAPTURE_MODE=fingerprint
```

This is the production default. Raw capture is for local debugging only. If raw
capture is explicitly enabled in production with
`HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD=true`, startup logs a critical warning and
operators should include `HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD_NOTE`.

## Receipt Signing

Production receipts must be signed:

```bash
HUBBLEOPS_RECEIPT_SIGNING_SECRET=replace-with-random-secret
HUBBLEOPS_RECEIPT_KEY_ID=prod-2026-06
```

The secret is never printed in the startup config summary.

## Redacted Startup Summary

On startup, the proxy logs a redacted config summary. Secret values are reported
only as `set`, `unset`, or `<redacted>`.

Redacted fields include:

- Postgres password
- Redis password
- alert webhook URL
- receipt signing secret
- action capability secret
- provider target URL credentials or secret query parameters

Provider API keys are request headers and are never included in startup logs.

## Resource Limits (cross-action protections)

The `limits:` section in proxy.yaml declares protections that apply ACROSS
actions, where the action firewall judges each call in isolation:

- **Cumulative caps** — windowed `amount_cents` totals per agent / session /
  resource / recipient. Stops "many small refunds, each under the per-action
  cap" drains.
- **Velocity limits** — windowed counts of side-effecting actions. Stops retry
  storms and sprays even when the agent rotates session ids, because buckets
  are scoped to the authenticated API-key identity, which a client cannot
  rotate away.
- **Circuit breaker** — repeated enforced blocks quarantine an agent's
  fail-closed-risk (money movement / dangerous) actions for a cooldown,
  without affecting other agents.

Safety properties, validated at startup (a half-declared rule fails startup in
every environment):

- All rules are operator-declared. Nothing about a limit is client-tunable.
- Limits run before the idempotency claim, so a rejected action never holds a
  pending lease.
- Counters track ATTEMPTS at decide time and are never refunded on failure —
  conservative in the safe direction. Duplicate replays also count toward
  caps.
- Windows are fixed buckets: a burst straddling a boundary can briefly reach
  ~2x a cap.
- Shadow mode records what limits would do without enforcing, and shadow
  decisions never count as breaker trips.
- If limit state is unreachable, write-tier actions fail open; fail-closed
  risks (money movement / dangerous) fail closed.
