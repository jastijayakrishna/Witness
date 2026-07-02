# Roadmap: GCP KMS and Vault Transit Receipt Signers

Status: planned, not implemented. Configuring `-receipt-signer gcp-kms` or
`vault-transit` is rejected at startup (gate) and at flag validation (CLI)
with "not yet implemented". The reserved stub types live in
`internal/receipts/kms.go` (`GCPKMSSigner`, `VaultTransitSigner`) and return
`ErrExternalSignerNotImplemented` from every signing call.

Supported today: `none`, `local` (dev only — forbidden in production by
`config.Validate`), and `aws-kms`.

## Contract a real implementation must satisfy

An implementation replaces the stub behind the existing
`receipts.ReceiptSigner` interface — callers must not change:

```go
type ReceiptSigner interface {
    SignRecord(rec wal.Record) (sig string, keyID string, err error)
    SignCheckpoint(cp wal.Checkpoint) (wal.Checkpoint, error)
    PublicKeyBase64() string
    KeyID() string
}
```

Requirements, in order of importance:

1. **Ed25519 only.** Receipt signatures are verified with
   `ed25519.Verify` against `signatureVersion` (`hubbleopsreceipt_v4`)
   payloads from `canonicalPayload`. The signing key must be an Ed25519 key:
   - GCP KMS: `EC_SIGN_ED25519` key purpose `ASYMMETRIC_SIGN` (GA support
     required; verify signature length is exactly 64 bytes, as the AWS
     implementation does).
   - Vault Transit: key type `ed25519`, `prehashed=false`. Vault returns
     `vault:vN:<base64>`; the version prefix must be stripped and the key
     version mapped to the receipt key id story below.
2. **SignRecord binds the key id.** Set `rec.ReceiptKeyID = s.keyID` on the
   value copy BEFORE building `canonicalPayload`, exactly like
   `LocalSecretSigner.SignRecord` and `AwsKmsSigner.SignRecord`, so verifiers
   recompute an identical payload.
3. **SignCheckpoint** sets `cp.KeyID`, fills `cp.SignedAt` when zero, signs
   `canonicalCheckpointPayload`, and encodes with
   `encodeCheckpointSignature` (`hubbleopscheckpoint_v1`).
4. **PublicKeyBase64** returns the raw 32-byte Ed25519 public key in
   base64.RawURLEncoding (parse provider DER/PEM via `x509.ParsePKIXPublicKey`
   as `AwsKmsHTTPClient.PublicKey` does). Operators publish this for
   `verify-receipts -receipt-public-keys`.
5. **Fail at startup, not per write.** Provide an eager constructor that
   fetches the public key once (mirror `NewAwsKmsSigner` vs
   `NewLazyAwsKmsSigner`) so bad credentials or a non-Ed25519 key are caught
   when the gate boots.
6. **Credentials.** GCP: Application Default Credentials (workload identity,
   not static JSON keys). Vault: token or AppRole via env, with renewal.
7. **Unblocking config:** remove the mode from
   `config.CheckReceiptSignerImplemented`, add the mode's KMS-style key/region
   validation to `config.Validate`'s production branch, and update the flag
   help strings in `cmd/gate/main.go` and `cmd/hubbleops/main.go` plus
   README/.env.example.

## Test plan (mirror the AWS coverage)

- Unit: fake HTTP server for the provider API asserting request shape,
  signature length validation, key-id binding (see `kms_test.go`).
- Round trip: sign a record, verify with `VerifyRecordWithPublicKey` using
  the signer's `PublicKeyBase64`.
- Rotation: two key ids in a `KeySet`, old receipts still verify
  (see `rotation_test.go`).
- Startup rejection tests in `cmd/gate/startup_test.go` flip from
  "rejected as unimplemented" to "accepted with valid config".
