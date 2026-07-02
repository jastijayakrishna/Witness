# Configuration Safety

The local preflight surface has a small configuration set:

- policy YAML
- WAL directory
- receipt signer configuration
- capture mode
- approval store path
- GitHub webhook secret and App private key, when running `cmd/gate`

## Safe Defaults

The CLI defaults to fingerprint capture and writes receipts to `data/wal`.
Local development can sign receipts with `-receipt-secret` or
`HUBBLEOPS_RECEIPT_SIGNING_SECRET`, which derives a deterministic Ed25519 key
on the host. Production forbids that `LocalSecretSigner`; use an external signer
so the private key cannot be extracted from the gated host.
Deploy idempotency uses the local ActionStore ledger at `data/action-ledger.json`
by default; set `HUBBLEOPS_ACTION_LEDGER` in CI if each workspace needs its own
ledger path.
GitHub webhook verification is enabled whenever `GITHUB_WEBHOOK_SECRET` is set.
Store the GitHub App private key in a secret file and pass
`GITHUB_APP_PRIVATE_KEY_FILE`.
Approval requests are stored in `data/approvals.json` by default. Review records
must include reviewer, time, and source; review comments are stored as hashes.

Production receipt signing uses AWS KMS today:

```bash
export HUBBLEOPS_RECEIPT_SIGNER=aws-kms
export HUBBLEOPS_RECEIPT_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/...
export HUBBLEOPS_RECEIPT_KMS_REGION=us-east-1
export HUBBLEOPS_RECEIPT_KEY_ID=prod-2026-07
```

Publish the matching Ed25519 public key and `key_id` to auditors. Verification
remains public-key-only, including rotated keysets passed to
`verify-receipts -receipt-public-keys`.

The signer role should have only:

- `kms:Sign`
- `kms:GetPublicKey`

It must not have key administration or deletion powers such as
`kms:ScheduleKeyDeletion`, `kms:DisableKey`, or broad `kms:*`. The gate signs
with AWS Signature Version 4 using AWS credentials supplied to the process and
never receives the KMS private key.

Use `configs/policy.yaml.example` as the starting policy. Copy it to
`configs/policy.yaml` for customer-specific protected resources.

## Raw Capture

Do not put raw prompts, raw tool args, raw SQL contents, raw plan contents, raw
emails, raw CRM rows, raw payment data, raw files, or raw PII into preflight
flags. The CLI fingerprints intent, target, evidence, and idempotency values
before writing receipts.

The receipt writer also applies a final privacy guard before WAL persistence:
known safe evidence labels remain readable, while unknown evidence values and
sensitive-looking identifiers are stored as stable fingerprints. Caller-supplied
receipt identifiers such as project, session, actor, human delegator, and target
are fingerprinted by default.

CLI and API JSON responses use the same privacy posture. Finding targets and file
paths are returned as fingerprints, and evidence is readable only for the narrow
allowlist of HubbleOps-generated labels such as `migration_contains`,
`terraform_action`, `public_ingress`, `iam_wildcard_policy`,
`s3_public_access`, `github_linked_ticket`, and `approval_status`.

## Production Checklist

1. Configure an external receipt signer; production refuses `LocalSecretSigner`
   and `HUBBLEOPS_RECEIPT_SIGNING_SECRET`.
2. Use stable `project`, `session`, and `actor` identifiers.
3. Keep the policy file reviewed in source control.
4. Publish receipt public keys by `key_id` and verify receipts with
   `-require-signatures`.
5. Use stable deploy idempotency keys so repeated release attempts replay or block.
6. Export reviewed labels anonymized by default.
7. For GitHub App mode, grant Actions read and upload PR Terraform plan artifacts.
   A Terraform-touched PR without a matching plan artifact is intentionally
   `require_approval` / `action_required`.
8. Require the GitHub check in branch protection only after shadowing real PRs.
9. Back up the approval store with the WAL when using file-backed approvals.
