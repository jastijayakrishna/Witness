# HubbleOps Action Firewall

HubbleOps is a lightweight action firewall for AI agents. The current MVP gates
engineering actions before they execute and writes a tamper-evident receipt for
each decision.

The product surface is deliberately small:

- capture action decisions
- record anonymized action outcomes
- collect customer review labels
- learn policy-template changes from reviewed labels
- export/import reviewed labels with anonymization by default
- aggregate privacy-safe decision intelligence

It is not a dashboard, prompt manager, eval platform, IAM system, DLP product, or
workflow builder.

## Local Preflight

The first working wedge is local preflight:

```bash
go run ./cmd/hubbleops preflight terraform ./plan.json \
  -project acme \
  -session pr-842 \
  -actor agent:claude-code \
  -human-delegator krish \
  -env production \
  -intent "cleanup old audit bucket" \
  -receipt-secret "$HUBBLEOPS_RECEIPT_SIGNING_SECRET"
```

```bash
go run ./cmd/hubbleops preflight migration ./migrations \
  -project acme \
  -session pr-842 \
  -actor agent:claude-code \
  -env production
```

```bash
go run ./cmd/hubbleops preflight deploy \
  -service billing-api \
  -artifact "$GITHUB_SHA" \
  -idempotency-key "deploy:$GITHUB_SHA" \
  -project acme \
  -session pr-842 \
  -actor agent:claude-code \
  -human-delegator krish \
  -env production \
  -receipt-secret "$HUBBLEOPS_RECEIPT_SIGNING_SECRET"
```

Terraform preflight focuses on action-risk changes: protected or stateful
destroys/replaces, deletion-protection removal, storage shrink, force-destroy or
skip-final-snapshot flips, broad public ingress, wildcard IAM policies, public
S3 access, S3 versioning rollback, KMS key deletion, and mass non-harmless
destroys. Migration preflight focuses on destructive, locking, or bulk
schema/data actions, including CTE-driven rewrites and `INSERT ... SELECT`, while
suppressing known-safe local setup work such as indexes on tables created
earlier in the same migration and temporary table cleanup.

Each command prints `allow`, `require_approval`, or `block`, writes a signed WAL
receipt when a receipt signer is configured, and reports the outcome through a
fixed exit-code contract so CI can tell a gate decision from a tool failure:

| Exit code | Meaning |
|-----------|---------|
| 0 | allow |
| 1 | block (also: failed verification for `verify-receipts` / `evidence-pack`, invalid policy for `policy validate`) |
| 2 | usage or flag error; nothing was executed |
| 3 | require_approval |
| 4 | internal error (receipt write failure, ledger unavailable, IO error) — no decision was produced, treat the action as not cleared to run |

Deploy preflight also records the idempotency key in the ActionStore
ledger so the same deploy cannot be gated twice with the same key.

## Gate API And GitHub App

Run the action-gate server:

```bash
go run ./cmd/gate \
  -policy configs/policy.yaml.example \
  -wal-dir data/wal \
  -receipt-signer aws-kms \
  -receipt-kms-key-id "$HUBBLEOPS_RECEIPT_KMS_KEY_ID" \
  -receipt-kms-region "$HUBBLEOPS_RECEIPT_KMS_REGION" \
  -receipt-key-id "$HUBBLEOPS_RECEIPT_KEY_ID"
```

Supported receipt signers are `none`, `local` (dev only), and `aws-kms`;
`gcp-kms` and `vault-transit` are planned but not yet implemented and are
rejected at startup (see docs/ROADMAP-SIGNERS.md).

`POST /v1/preflight` accepts the same action request shape as the CLI and writes
the same signed receipt. `require_approval` decisions create an approval request
in `data/approvals.json` by default. Review it with
`POST /v1/approvals/{approval_id}/review`; the next identical preflight consults
that approval and writes a new signed allow/block receipt with reviewer
fingerprint evidence. `GET /v1/receipts/{decision_id}` returns the latest receipt
metadata for the decision. CLI and API JSON responses sanitize caller-controlled
targets, file paths, evidence, approvers, and reviewer identifiers before echoing
them back.

Decision IDs are derived from a labeled v2 hash payload. Upgrading from the old
v1 derivation intentionally changes IDs, so pre-existing pending approvals keyed
to v1 decision IDs will not match v2 preflight decisions and must be requested
again.

Long-lived gate processes sweep expired ActionStore ledger rows every 10 minutes
so Postgres and file-backed ledgers do not grow forever. Set
`HUBBLEOPS_LEDGER_SWEEP_INTERVAL` to a Go duration such as `5m` to tune it, or
`0` to disable it.

`POST /github/webhook` handles GitHub `pull_request` events, verifies
`X-Hub-Signature-256` when `GITHUB_WEBHOOK_SECRET` is set, loads changed files and
CODEOWNERS through GitHub App installation auth, then creates a check run named
`HubbleOps Action Firewall`.

Required GitHub App settings:

```bash
GITHUB_APP_ID=12345
GITHUB_APP_PRIVATE_KEY_FILE=/run/secrets/github-app.pem
GITHUB_WEBHOOK_SECRET=replace-with-random-secret
```

Give the App read access to contents and pull requests, and write access to
checks. In branch protection, require the `HubbleOps Action Firewall` check.
Set `HUBBLEOPS_SLACK_WEBHOOK_URL` only if you want privacy-safe approval request
notifications.

## Phase 4 Demo

Run the approvals demo:

```bash
go run ./cmd/hubbleops demo phase4 \
  -wal-dir data/phase4-demo/wal \
  -approval-store data/phase4-demo/approvals.json \
  -receipt-secret "local-demo-secret"
```

It processes 20 deterministic PR/plan decisions: 14 allow, 4 require approval,
and 2 block. It then approves one pending item and writes the post-review signed
receipt.

## Policy

Policy is YAML and intentionally deterministic:

- policies are loaded with strict YAML fields; unknown keys fail validation
- rules are evaluated top to bottom, first-match-wins
- every non-default blocking/review rule must have at least one `if` condition
- validate changes before rollout with `hubbleops policy validate <path>`

```yaml
version: engineering-gate/v1
protected_resources:
  - aws_s3_bucket.audit_logs_prod
services:
  billing-api:
    risk: tier_0
    owners:
      - billing-owner
      - sre
rules:
  - id: block-prod-destroy
    if:
      action: terraform.destroy
      env: prod
      touches_any:
        - aws_s3_bucket.audit_logs_prod
    decision: block
    risk_score: 99
    reason: production destroy is blocked

  - id: review-drop-table
    if:
      migration_contains:
        - DROP_TABLE
    decision: require_approval
    required_approvers:
      - db-owner
    risk_score: 85

  - id: review-tier0-prod-deploy
    if:
      action: deploy.release
      env: prod
      service_risk: tier_0
    decision: require_approval
    required_approvers:
      - sre
      - billing-owner
    risk_score: 85

  - id: review-infra-pr
    if:
      action: github.pull_request
      touches_any:
        - infra/
        - terraform/
        - migrations/
    decision: require_approval
    required_approvers:
      - codeowner
    risk_score: 80
```

The default policy path is `configs/policy.yaml` or
`configs/policy.yaml.example` when present. Override with `-policy`.

Because rules are first-match-wins, broad `allow` rules should appear only after
more specific `block` and `require_approval` rules. The validator warns when an
earlier `allow` rule has an exactly identical `if` block to a later `block`
rule, but it does not attempt general overlap analysis.

## Privacy Defaults

Default capture mode is fingerprint. Preflight receipts do not store raw plan
JSON, SQL text, prompts, tool args, CRM rows, payment data, files, or raw PII.
Intent, evidence, project, session, actor, human delegator, target, and
idempotency keys are fingerprinted on the receipt path. Unknown evidence keys are
fingerprinted instead of stored as readable text. The local deploy idempotency
ledger stores hashed idempotency and resource values, not raw service/action
payloads; result payloads are stored as fingerprints plus shape metadata. GitHub
PR titles and bodies are used only as receipt intent input; they are stored as
hashes, not raw text.
Approval comments are stored as hashes, and reviewer identifiers are fingerprinted
when they look sensitive.

## Receipts

Verify WAL receipts:

```bash
go run ./cmd/hubbleops verify-receipts \
  -receipt-public-keys "$HUBBLEOPS_RECEIPT_PUBLIC_KEYS" \
  -require-signatures \
  data/wal/*.jsonl
```

Generate an evidence pack:

```bash
go run ./cmd/hubbleops evidence-pack \
  -receipt-public-key "$HUBBLEOPS_RECEIPT_PUBLIC_KEY" \
  data/wal/*.jsonl
```

## Development

```bash
go test ./...
```

The reusable kernel is the signed receipt code, hash-chained WAL, WAL verifier,
Postgres WAL drain path, privacy helpers, and the idempotency ActionStore.
