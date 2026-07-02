# HubbleOps Install

The local CLI preflight belongs in engineering-action paths that agents can
trigger: Terraform plans, SQL migrations, and production deploys.

The CLI examples below use the dev-only local receipt signer for quick smoke
tests. Production enforcement should run through the gate/GitHub App path with
`HUBBLEOPS_RECEIPT_SIGNER=aws-kms`.

## Terraform

Generate a plan JSON with Terraform:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > plan.json
```

Run HubbleOps:

```bash
go run ./cmd/hubbleops preflight terraform plan.json \
  -policy configs/policy.yaml.example \
  -project acme \
  -session "$GITHUB_RUN_ID" \
  -actor agent:claude-code \
  -human-delegator "$GITHUB_ACTOR" \
  -env production \
  -receipt-secret "$HUBBLEOPS_RECEIPT_SIGNING_SECRET"
```

## Migrations

```bash
go run ./cmd/hubbleops preflight migration ./migrations \
  -policy configs/policy.yaml.example \
  -project acme \
  -session "$GITHUB_RUN_ID" \
  -actor agent:claude-code \
  -human-delegator "$GITHUB_ACTOR" \
  -env production \
  -receipt-secret "$HUBBLEOPS_RECEIPT_SIGNING_SECRET"
```

## Deploys

Define service tiers in `configs/policy.yaml`:

```yaml
services:
  billing-api:
    risk: tier_0
    owners:
      - billing-owner
      - sre
```

Run HubbleOps before the release step:

```bash
go run ./cmd/hubbleops preflight deploy \
  -service billing-api \
  -artifact "$GITHUB_SHA" \
  -idempotency-key "deploy:$GITHUB_SHA" \
  -policy configs/policy.yaml.example \
  -project acme \
  -session "$GITHUB_RUN_ID" \
  -actor agent:claude-code \
  -human-delegator "$GITHUB_ACTOR" \
  -env production \
  -receipt-secret "$HUBBLEOPS_RECEIPT_SIGNING_SECRET"
```

The default deploy idempotency ledger is `data/action-ledger.json`; override it
with `-action-ledger` or `HUBBLEOPS_ACTION_LEDGER` in CI workspaces.

## GitHub Pull Requests

Run the gate server:

```bash
go run ./cmd/gate \
  -policy configs/policy.yaml.example \
  -wal-dir data/wal \
  -approval-store data/approvals.json \
  -receipt-signer aws-kms \
  -receipt-kms-key-id "$HUBBLEOPS_RECEIPT_KMS_KEY_ID" \
  -receipt-kms-region "$HUBBLEOPS_RECEIPT_KMS_REGION" \
  -receipt-key-id "$HUBBLEOPS_RECEIPT_KEY_ID"
```

Create a GitHub App with these permissions:

- Contents: read
- Pull requests: read
- Checks: write
- Actions: read

Set the webhook URL to `https://YOUR_GATE_HOST/github/webhook` and subscribe to
pull request events. Configure:

```bash
export GITHUB_APP_ID=12345
export GITHUB_APP_PRIVATE_KEY_FILE=/run/secrets/github-app.pem
export GITHUB_WEBHOOK_SECRET=replace-with-random-secret
```

After the first check run appears, require `HubbleOps Action Firewall` in branch
protection for protected branches.

For Terraform PRs, upload the `terraform show -json` output as a GitHub Actions
artifact so the required check can run the Terraform detector server-side:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > terraform-plan.json
```

Name the artifact:

```text
hubbleops-terraform-plan-pr-<PR_NUMBER>-<HEAD_SHA>
```

The artifact zip should contain `terraform-plan.json` or `plan.json`. If a PR
touches Terraform files (`terraform/`, `*.tf`, `*.tfvars`, or `*.tf.json`) and
no matching plan artifact is available, the GitHub check fails closed as
`require_approval` / `action_required`. Raw plan JSON is scanned in memory and
is not written to receipts or approval records.

## Approvals

The gate server stores approval requests in `data/approvals.json` by default.
Override with `-approval-store` or `HUBBLEOPS_APPROVAL_STORE`. Set
`HUBBLEOPS_SLACK_WEBHOOK_URL` only when you want privacy-safe Slack notifications
for new approval requests.

Review an approval:

```bash
curl -s https://YOUR_GATE_HOST/v1/approvals/APPROVAL_ID/review \
  -H "Content-Type: application/json" \
  -d '{"reviewer":"sre","source":"api","decision":"approved"}'
```

The next identical preflight writes a signed receipt with reviewer fingerprint
evidence. Use `GET /v1/receipts/DECISION_ID` to fetch the latest receipt metadata.
Approval reviewer identifiers and comments are privacy-guarded: reviewer values
are fingerprinted when sensitive-looking, and comments are stored only as hashes.
Gate responses and Slack approval notifications include safe labels and
fingerprints, not raw PR bodies, SQL text, secrets, or customer data.

## Receipt Review

Receipts are JSONL in `data/wal` by default.

```bash
go run ./cmd/hubbleops verify-receipts \
  -receipt-public-keys "$HUBBLEOPS_RECEIPT_PUBLIC_KEYS" \
  -require-signatures \
  data/wal/*.jsonl
```

## Rollout Checklist

1. Start with `require_approval` policies for risky changes.
2. Review generated receipts and false positives.
3. Promote only high-confidence destructive patterns to `block`.
4. Use AWS KMS signing in prod and publish `HUBBLEOPS_RECEIPT_PUBLIC_KEYS` for verification.
5. Use S3 Object Lock COMPLIANCE anchors for prod WAL checkpoints; see `docs/S3_OBJECT_LOCK_ANCHOR.md`.
6. Export/share only anonymized reviewed labels by default.
7. Use a stable deploy idempotency key, usually the release artifact or commit SHA.
8. Require the GitHub check only after reviewing false positives on real PRs.
