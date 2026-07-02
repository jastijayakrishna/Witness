package receipts

import (
	"testing"

	"github.com/hubbleops/hubbleops/internal/wal"
)

func signed(t *testing.T, s *Signer, decisionID string) wal.Record {
	t.Helper()
	rec := wal.Record{DecisionID: decisionID, Decision: "block", Action: "terraform.destroy", RiskScore: 95}
	sig, keyID, err := s.SignRecord(rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec.ReceiptSignature = sig
	rec.ReceiptKeyID = keyID
	return rec
}

// The key id must be inside the signed payload: re-attributing a receipt to a different
// key must invalidate the signature.
func TestSignatureBindsKeyID(t *testing.T) {
	s := NewSigner("kid-A", []byte("secret"))
	rec := signed(t, s, "d1")
	pub := PublicKeyFromSecret([]byte("secret"))
	if err := VerifyRecordWithPublicKey(pub, rec); err != nil {
		t.Fatalf("baseline verify: %v", err)
	}
	rec.ReceiptKeyID = "kid-B"
	if err := VerifyRecordWithPublicKey(pub, rec); err == nil {
		t.Fatalf("key id is not bound to the signature")
	}
}

// A KeySet verifies receipts signed by either the retired or the active key (rotation),
// and rejects a receipt whose actual signer is not in the set.
func TestKeySetVerifiesAcrossRotation(t *testing.T) {
	oldSigner := NewSigner("key-2025", []byte("old-secret"))
	newSigner := NewSigner("key-2026", []byte("new-secret"))
	recOld := signed(t, oldSigner, "d-old")
	recNew := signed(t, newSigner, "d-new")

	ks := NewKeySet()
	ks.Add("key-2025", PublicKeyFromSecret([]byte("old-secret")))
	ks.Add("key-2026", PublicKeyFromSecret([]byte("new-secret")))
	if err := ks.VerifyRecord(recOld); err != nil {
		t.Fatalf("rotation: old receipt failed: %v", err)
	}
	if err := ks.VerifyRecord(recNew); err != nil {
		t.Fatalf("rotation: new receipt failed: %v", err)
	}

	// A keyset that lacks the old key must reject the old receipt (the fallback key cannot
	// verify a signature it did not produce) — proving selection is real, not accept-all.
	onlyNew := NewKeySet()
	onlyNew.Add("key-2026", PublicKeyFromSecret([]byte("new-secret")))
	if err := onlyNew.VerifyRecord(recOld); err == nil {
		t.Fatalf("keyset without the old key must not verify the old receipt")
	}
}
