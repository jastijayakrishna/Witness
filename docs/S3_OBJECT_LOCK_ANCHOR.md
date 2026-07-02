# S3 Object Lock Anchor

Use S3 Object Lock anchors for production receipt verification. A local file
anchor can catch accidental truncation, but it is not evidence against an
attacker who controls the WAL host.

## Bucket Contract

Create the bucket with Object Lock enabled from the start. AWS does not let you
turn Object Lock on for an existing ordinary bucket.

```bash
aws s3api create-bucket \
  --bucket hubbleops-audit \
  --region us-east-1 \
  --object-lock-enabled-for-bucket

aws s3api put-bucket-versioning \
  --bucket hubbleops-audit \
  --versioning-configuration Status=Enabled
```

The writer stores checkpoints under monotonic keys:

```text
checkpoints/prod/<20-digit zero-padded seq>.json
```

Each put includes `If-None-Match: *` and Object Lock COMPLIANCE retention:

- `x-amz-object-lock-mode: COMPLIANCE`
- `x-amz-object-lock-retain-until-date: <now + retention_days>`

COMPLIANCE retention cannot be shortened, bypassed, overwritten, or deleted
during the retention window, including by the account root user.

## Writer IAM

Grant only the checkpoint operations the writer needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectRetention",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::hubbleops-audit",
        "arn:aws:s3:::hubbleops-audit/checkpoints/prod/*"
      ]
    }
  ]
}
```

Do not grant the writer role:

- `s3:DeleteObject`
- `s3:DeleteObjectVersion`
- `s3:PutLifecycleConfiguration`
- `s3:BypassGovernanceRetention`

`s3:BypassGovernanceRetention` is specifically a governance-mode escape hatch.
HubbleOps requires COMPLIANCE mode for production anchors, and the writer role
should never hold bypass permissions anyway.

## Configuration

```bash
export HUBBLEOPS_WAL_ANCHOR='s3://hubbleops-audit/checkpoints/prod'
export HUBBLEOPS_S3_ANCHOR_REGION=us-east-1
export HUBBLEOPS_S3_ANCHOR_RETENTION_DAYS=30
```

For MinIO or other path-style endpoints used by integration tests:

```bash
export HUBBLEOPS_S3_ANCHOR_ENDPOINT=http://127.0.0.1:9000
export HUBBLEOPS_S3_ANCHOR_FORCE_PATH_STYLE=true
```

Verify with a public receipt key:

```bash
go run ./cmd/hubbleops verify-receipts \
  -receipt-public-key "$HUBBLEOPS_RECEIPT_PUBLIC_KEY" \
  -require-signatures \
  -anchor 's3://hubbleops-audit/checkpoints/prod?region=us-east-1&retention_days=30' \
  data/wal/*.jsonl
```

If the latest immutable checkpoint says `seq=4` and the WAL only contains
records through `seq=3`, verification fails with:

```text
truncation detected: anchored seq=4, wal max seq=3
```

## Integration Proof

The integration lane starts MinIO, creates an Object-Lock-enabled versioned
bucket, and runs only tagged tests:

```bash
docker compose -f deploy/minio-objectlock-compose.yml up -d minio
docker compose -f deploy/minio-objectlock-compose.yml run --rm minio-init

AWS_ACCESS_KEY_ID=minioadmin \
AWS_SECRET_ACCESS_KEY=minioadmin \
AWS_REGION=us-east-1 \
HUBBLEOPS_INTEGRATION_S3_ENDPOINT=http://127.0.0.1:9000 \
HUBBLEOPS_INTEGRATION_S3_BUCKET=hubbleops-audit \
go test -tags "integration docker" ./...
```

The MinIO test must pass these negative checks:

- republishing an existing checkpoint key is denied
- deleting a retained checkpoint is denied
- truncating the WAL below the latest S3 checkpoint verifies as false
