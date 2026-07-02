# WAL Anchors

The WAL is tamper-evident only when the verifier sees both:

- a signed, contiguous receipt chain (`seq`, `prev_hash`, `record_hash`)
- an external checkpoint anchor for the latest expected tail

Writers also coordinate locally. `wal-chain.lock` lives in the WAL directory and
guards the chain-head scan, append, and `wal-chain-head.json` update so multiple
processes sharing one WAL directory cannot fork the sequence. The background
fsync ticker does not hold this lock while idle.

`FileAnchor` is for development and local CI plumbing. It does not survive a
host-level attacker who can rewrite both `data/wal` and the local checkpoint
file.

Production anchors should use `S3ObjectLockAnchor` with a bucket created with
Object Lock enabled and versioning on. Each checkpoint is written once under:

```text
<prefix>/<20-digit zero-padded seq>.json
```

The S3 writer sends:

- `If-None-Match: *`
- `x-amz-object-lock-mode: COMPLIANCE`
- `x-amz-object-lock-retain-until-date: <now + retention_days>`

The integration suite proves the hand-rolled S3 SigV4 path against MinIO and
asserts the WORM negative cases:

```bash
docker compose -f deploy/minio-objectlock-compose.yml up -d minio
docker compose -f deploy/minio-objectlock-compose.yml run --rm minio-init

AWS_ACCESS_KEY_ID=minioadmin \
AWS_SECRET_ACCESS_KEY=minioadmin \
AWS_REGION=us-east-1 \
HUBBLEOPS_INTEGRATION_S3_ENDPOINT=http://127.0.0.1:9000 \
HUBBLEOPS_INTEGRATION_S3_BUCKET=hubbleops-audit \
go test -tags "integration docker" ./internal/wal ./internal/receiptverify
```

The KMS integration suite uses an in-process strict SigV4 harness, not AWS. It
recomputes canonical requests and rejects a deliberately miscanonicalized
request so signer drift is caught before production.
