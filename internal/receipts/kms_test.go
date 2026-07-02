package receipts

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/wal"
)

type fakeAwsKmsClient struct {
	priv ed25519.PrivateKey
}

func newFakeAwsKmsClient(seed string) *fakeAwsKmsClient {
	return &fakeAwsKmsClient{priv: privateKeyFromSecret([]byte(seed))}
}

func (f *fakeAwsKmsClient) Sign(_ context.Context, _ string, payload []byte) ([]byte, error) {
	return ed25519.Sign(f.priv, payload), nil
}

func (f *fakeAwsKmsClient) PublicKey(context.Context, string) (ed25519.PublicKey, error) {
	return append(ed25519.PublicKey(nil), f.priv.Public().(ed25519.PublicKey)...), nil
}

func TestAwsKmsSignerVerifiesWithPublishedPublicKeyOnly(t *testing.T) {
	signer, err := NewAwsKmsSigner(context.Background(), "kms-2026", "arn:aws:kms:us-east-1:123:key/abc", newFakeAwsKmsClient("kms-secret"))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	rec := receiptRecord()
	rec.Seq = 1
	rec.PrevHash = "genesis"
	sig, keyID, err := signer.SignRecord(rec)
	if err != nil {
		t.Fatalf("sign record: %v", err)
	}
	rec.ReceiptSignature = sig
	rec.ReceiptKeyID = keyID

	pub, err := ParsePublicKey(signer.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if err := VerifyRecordWithPublicKey(pub, rec); err != nil {
		t.Fatalf("verify with published public key: %v", err)
	}

	tampered := rec
	tampered.DecisionReason = "tampered"
	if err := VerifyRecordWithPublicKey(pub, tampered); err == nil {
		t.Fatalf("tampered KMS-signed receipt verified")
	}
}

func TestAwsKmsSignerSignsCheckpoints(t *testing.T) {
	signer, err := NewAwsKmsSigner(context.Background(), "kms-2026", "arn:aws:kms:us-east-1:123:key/abc", newFakeAwsKmsClient("kms-secret"))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	cp, err := signer.SignCheckpoint(wal.Checkpoint{
		Seq:      4,
		HeadHash: "head",
		Count:    4,
		SignedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	pub, err := ParsePublicKey(signer.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if err := VerifyCheckpointWithPublicKey(pub, cp); err != nil {
		t.Fatalf("verify checkpoint: %v", err)
	}
	tampered := cp
	tampered.HeadHash = "attacker"
	if err := VerifyCheckpointWithPublicKey(pub, tampered); err == nil {
		t.Fatalf("tampered KMS checkpoint verified")
	}
}

func TestKeySetVerifiesAwsKmsRotation(t *testing.T) {
	oldSigner, err := NewAwsKmsSigner(context.Background(), "kms-2025", "arn:old", newFakeAwsKmsClient("old-kms"))
	if err != nil {
		t.Fatalf("old signer: %v", err)
	}
	newSigner, err := NewAwsKmsSigner(context.Background(), "kms-2026", "arn:new", newFakeAwsKmsClient("new-kms"))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	recOld := signedWithReceiptSigner(t, oldSigner, "d-old")
	recNew := signedWithReceiptSigner(t, newSigner, "d-new")

	oldPub, err := ParsePublicKey(oldSigner.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse old public key: %v", err)
	}
	newPub, err := ParsePublicKey(newSigner.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse new public key: %v", err)
	}
	ks := NewKeySet()
	ks.Add("kms-2025", oldPub)
	ks.Add("kms-2026", newPub)

	if err := ks.VerifyRecord(recOld); err != nil {
		t.Fatalf("old KMS receipt failed rotation verify: %v", err)
	}
	if err := ks.VerifyRecord(recNew); err != nil {
		t.Fatalf("new KMS receipt failed rotation verify: %v", err)
	}
}

func signedWithReceiptSigner(t *testing.T, signer ReceiptSigner, decisionID string) wal.Record {
	t.Helper()
	rec := wal.Record{
		Seq:        1,
		PrevHash:   "genesis",
		DecisionID: decisionID,
		Decision:   "block",
		Action:     "terraform.destroy",
		RiskScore:  95,
	}
	sig, keyID, err := signer.SignRecord(rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec.ReceiptSignature = sig
	rec.ReceiptKeyID = keyID
	return rec
}
