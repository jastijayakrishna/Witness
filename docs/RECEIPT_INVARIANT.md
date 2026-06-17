# Receipt Invariant

HubbleOps must not enforce an action block without first attempting to create a
durable decision receipt. Receipts are written to the hash-chained WAL and can
optionally be signed with Ed25519 so auditors can verify them without holding a
server secret.

## Block Safety

Production defaults require receipt protection for blocks:

```yaml
receipts:
  require_receipt_for_block: true
  enforce_without_receipt: false
```

Equivalent environment variables:

```bash
HUBBLEOPS_REQUIRE_RECEIPT_FOR_BLOCK=true
HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT=false
```

When a block decision cannot be written to the WAL:

- normal block decisions fail open and return `action=allow` with `fail_open=true`
- high-stakes fail-closed actions, such as `money_movement` or `dangerous`, may
  remain blocked
- enforced blocks with a failed WAL write are queued in the durable receipt
  dead-letter directory under the WAL path and replayed when the WAL recovers

`HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT=true` is an emergency override. Production
startup allows it only with a critical warning because it can enforce unaudited
blocks.

## Signing

Production requires a receipt signing secret:

```bash
HUBBLEOPS_RECEIPT_SIGNING_SECRET=replace-with-random-secret
HUBBLEOPS_RECEIPT_KEY_ID=prod-2026-06
```

The proxy derives an Ed25519 signing key from the secret. The public verification
key is intentionally public and is served at:

```text
/v1/receipts/public-key
/.well-known/hubbleops-receipt-key
```

The endpoint returns the key and a verifier command shape.

## Verification

Verify a WAL export with the public key:

```bash
go run ./cmd/hubbleops verify-receipts \
  -receipt-public-key "$HUBBLEOPS_RECEIPT_PUBLIC_KEY" \
  -require-signatures \
  data/wal/*.jsonl
```

Operators can also verify with the signing secret:

```bash
go run ./cmd/hubbleops verify-receipts \
  -receipt-secret "$HUBBLEOPS_RECEIPT_SIGNING_SECRET" \
  -require-signatures \
  data/wal/*.jsonl
```

The verifier checks WAL hash-chain continuity, required action decision fields,
and signed receipt integrity. A non-zero exit means the export is not
trustworthy enough for enforcement review.
