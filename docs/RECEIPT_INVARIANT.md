# Receipt Invariant

HubbleOps must not report an enforced `block` without first attempting to write
a decision receipt to the hash-chained WAL.

Every modern WAL record has an immutable chain position:

- `seq` starts at `1` for the first record in a chain.
- `seq` increments by exactly `1` for every following record.
- the first record has `prev_hash="genesis"`.
- every later record has `prev_hash` equal to the previous record's
  `record_hash`.
- the Ed25519 receipt signature covers both `seq` and `prev_hash`, so a signed
  receipt cannot be dropped, reordered, or rechained without invalidating the
  signature or creating a sequence gap.
- the chain head persists both `last_hash` and `last_seq`.

Gate starts one long-lived receipt writer and shares it across concurrent HTTP
requests. CLI and helper paths may still construct one-shot writers, but every
WAL writer serializes the `load chain head -> append record -> save chain head`
critical section with an advisory lock file in the WAL directory. This prevents
separate processes from assigning duplicate `seq` or `prev_hash` values when
they share a WAL directory.

End truncation requires an external anchor. A verifier cannot prove that missing
records existed after the local WAL ends unless it has a checkpoint outside that
WAL. HubbleOps publishes signed checkpoints:

- `seq`
- `head_hash`
- `count`
- `signed_at`
- `signature`

`verify-receipts -anchor <path>` requires a receipt public key, keyset, or
signing secret so it can verify the checkpoint signature. It fails when the
latest anchored `seq` is greater than the WAL's maximum `seq`, or when the WAL
record at the anchored `seq` does not match the anchored `head_hash`.

Local file anchors are useful for development and CI plumbing, but they are not
host-compromise proof when the checkpoint file lives beside the WAL. Production
truncation evidence must use an external immutable anchor such as S3 Object Lock
COMPLIANCE mode:

```bash
go run ./cmd/hubbleops preflight deploy \
  -anchor 's3://hubbleops-audit/checkpoints/prod?region=us-east-1&retention_days=30'
```

The equivalent environment configuration is:

- `HUBBLEOPS_WAL_ANCHOR=s3://hubbleops-audit/checkpoints/prod`
- `HUBBLEOPS_S3_ANCHOR_BUCKET=hubbleops-audit`
- `HUBBLEOPS_S3_ANCHOR_PREFIX=checkpoints/prod`
- `HUBBLEOPS_S3_ANCHOR_REGION=us-east-1` or `AWS_REGION`
- `HUBBLEOPS_S3_ANCHOR_RETENTION_DAYS=30`
- `HUBBLEOPS_S3_ANCHOR_ENDPOINT` and
  `HUBBLEOPS_S3_ANCHOR_FORCE_PATH_STYLE=true` for LocalStack/MinIO-style tests

Each S3 checkpoint is written once under a monotonic key:

```text
<prefix>/<20-digit zero-padded seq>.json
```

The writer sends `If-None-Match: *` plus Object Lock headers:

- `x-amz-object-lock-mode: COMPLIANCE`
- `x-amz-object-lock-retain-until-date: <now + retention_days>`

The audit bucket must have Object Lock enabled. The writer IAM role should have
only the minimum anchor permissions:

- allow `s3:PutObject`
- allow `s3:PutObjectRetention`
- allow `s3:GetObject`
- allow `s3:ListBucket`

The writer role must not have delete, lifecycle, or retention-bypass powers:

- no `s3:DeleteObject`
- no `s3:DeleteObjectVersion`
- no `s3:PutLifecycleConfiguration`
- no `s3:BypassGovernanceRetention`

Use COMPLIANCE mode retention for production anchors. Governance mode is not
sufficient if the writer or CI role can obtain bypass permission. A host-level
attacker who controls `data/wal` and local files still cannot rewrite or delete
the immutable external checkpoint during the retention window, so truncating the
WAL below the latest checkpoint makes `verify-receipts -anchor s3://...` fail.

See `docs/S3_OBJECT_LOCK_ANCHOR.md` for the deploy-time bucket, IAM, and
integration-test contract. The integration suite proves the hand-rolled S3
SigV4 client against MinIO and asserts that overwrite/delete attempts on a
retained checkpoint are denied.

## Signing Key Custody

The verifier path is public-key-only: auditors receive published Ed25519 public
keys keyed by `key_id`, and `verify-receipts -receipt-public-keys` accepts old
and new keys during rotation.

Receipt signing is pluggable:

- `LocalSecretSigner` derives an Ed25519 key from
  `HUBBLEOPS_RECEIPT_SIGNING_SECRET`. It is for development and tests only.
- `AwsKmsSigner` signs the same canonical receipt and checkpoint payloads with
  an asymmetric AWS KMS key. The private key never leaves KMS.
- GCP KMS and Vault transit signer types are reserved stubs until implemented.

Production gate startup fails if `LocalSecretSigner` or
`HUBBLEOPS_RECEIPT_SIGNING_SECRET` is configured. Required production settings:

```bash
export HUBBLEOPS_RECEIPT_SIGNER=aws-kms
export HUBBLEOPS_RECEIPT_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/...
export HUBBLEOPS_RECEIPT_KMS_REGION=us-east-1
export HUBBLEOPS_RECEIPT_KEY_ID=prod-2026-07
```

For preflight, the CLI:

1. computes a deterministic decision id
2. fingerprints intent, project, session, actor, human delegator, target,
   evidence, and idempotency key on the receipt path
3. assigns the WAL `seq` and `prev_hash`
4. signs the canonical receipt payload with the configured receipt signer
5. writes the receipt to the WAL in sync mode
6. publishes a signed checkpoint when `-anchor` or `HUBBLEOPS_WAL_ANCHOR` is set
7. prints the decision and exits nonzero for `block`

Required engineering receipt fields:

- `project`
- `session_id`
- `decision_id`
- `actor`
- `action`
- `decision`
- `policy_version`
- `decision_reason`

Verify with an external auditor key and anchor:

```bash
go run ./cmd/hubbleops verify-receipts \
  -receipt-public-key "$HUBBLEOPS_RECEIPT_PUBLIC_KEY" \
  -require-signatures \
  -anchor 's3://hubbleops-audit/checkpoints/prod?region=us-east-1&retention_days=30' \
  data/wal/*.jsonl
```

Legacy records without `seq` verify only when no anchor is supplied and
`verify-receipts -legacy` is set. The default verification path requires `seq`.

Readable receipt evidence is limited to HubbleOps-generated safe labels. Unknown
or caller-supplied evidence is stored as `evidence_fingerprint=sha256:...`.
