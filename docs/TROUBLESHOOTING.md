# Troubleshooting

## Terraform Plan Does Not Parse

Use Terraform JSON output, not the human plan text:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

## Policy Does Not Match

Run with `-json` and inspect `findings[].action`, `findings[].target`, and
`findings[].change_tags`. Policy rules match those normalized values.
Finding targets and file paths are fingerprinted in JSON output, so use
`findings[].action`, `findings[].kind`, `findings[].change_tags`, and readable
HubbleOps evidence labels to debug matching without exposing raw files or PII.

## Receipt Is Unsigned

For local development, set a dev-only signing secret:

```bash
export HUBBLEOPS_RECEIPT_SIGNING_SECRET=replace-with-random-secret
```

For production gate deployments, configure KMS instead:

```bash
export HUBBLEOPS_RECEIPT_SIGNER=aws-kms
export HUBBLEOPS_RECEIPT_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/...
export HUBBLEOPS_RECEIPT_KMS_REGION=us-east-1
export HUBBLEOPS_RECEIPT_KEY_ID=prod-2026-07
```

Then pass `-require-signatures` when verifying:

```bash
go run ./cmd/hubbleops verify-receipts \
  -receipt-public-keys "$HUBBLEOPS_RECEIPT_PUBLIC_KEYS" \
  -require-signatures \
  data/wal/*.jsonl
```

## WAL Is Not Writable

Pass a writable directory:

```bash
go run ./cmd/hubbleops preflight terraform plan.json -wal-dir ./data/wal
```

## Blocked Command Exits Nonzero

That is intentional. A `block` decision exits `1` after the receipt is written.
A `require_approval` decision exits `3`.

## Approval Was Granted But Preflight Still Requires Review

Rerun the same action request identifiers: `project`, `session_id`, `actor`,
`action`, `target`, environment, idempotency key, and findings must produce the
same decision id. Fetch the latest receipt metadata with:

```bash
curl -s http://localhost:8080/v1/receipts/DECISION_ID
```

## Go Build Prints Stat Cache Access Denied

In a restricted workspace, `go build` may succeed while printing a non-fatal
warning about writing the Go module stat cache. Use the process exit code and the
presence of the requested binary as the build result; the warning does not affect
HubbleOps receipts or WAL verification.
