package receipts

import (
	"testing"

	"github.com/hubbleops/hubbleops/internal/wal"
)

func TestSignAndVerifyRecord(t *testing.T) {
	rec := receiptRecord()
	sig, err := SignRecord([]byte("receipt-secret"), rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec.ReceiptSignature = sig
	if err := VerifyRecord([]byte("receipt-secret"), rec); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRecordRejectsTamperedDecision(t *testing.T) {
	rec := receiptRecord()
	sig, err := SignRecord([]byte("receipt-secret"), rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec.ReceiptSignature = sig
	rec.DecisionReason = "tampered"
	if err := VerifyRecord([]byte("receipt-secret"), rec); err == nil {
		t.Fatalf("tampered receipt should not verify")
	}
}

// TestReceiptVerifiesWithPublicKeyOnly is the core of the asymmetric-signature property:
// an external auditor holding only the published public key (no secret) can verify a
// receipt's authenticity, and a tampered receipt fails that verification.
func TestReceiptVerifiesWithPublicKeyOnly(t *testing.T) {
	secret := []byte("receipt-secret")
	signer := NewSigner("prod-2026", secret)

	rec := receiptRecord()
	sig, keyID, err := signer.SignRecord(rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if keyID != "prod-2026" {
		t.Fatalf("key_id=%q want prod-2026", keyID)
	}
	rec.ReceiptSignature = sig

	// The auditor only ever receives this published string, never the secret.
	pub, err := ParsePublicKey(signer.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if err := VerifyRecordWithPublicKey(pub, rec); err != nil {
		t.Fatalf("public-key verify: %v", err)
	}

	tampered := rec
	tampered.AmountCents = 999999
	if err := VerifyRecordWithPublicKey(pub, tampered); err == nil {
		t.Fatalf("tampered receipt verified under public key")
	}
}

// TestSignatureUsesAsymmetricVersion guards against silently reverting to the v1 HMAC
// scheme an external verifier could also forge.
func TestSignatureUsesAsymmetricVersion(t *testing.T) {
	sig, err := SignRecord([]byte("receipt-secret"), receiptRecord())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got := sig[:len(signatureVersion)]; got != signatureVersion || signatureVersion != "hubbleopsreceipt_v2" {
		t.Fatalf("signature version=%q want hubbleopsreceipt_v2", got)
	}
}

func TestHashTokenDoesNotExposeToken(t *testing.T) {
	token := "witcap_v1.payload.signature"
	hash := HashToken(token)
	if hash == "" {
		t.Fatalf("hash should not be empty")
	}
	if hash == token {
		t.Fatalf("hash should not equal raw token")
	}
}

func receiptRecord() wal.Record {
	return wal.Record{
		Project:             "proj",
		Provider:            "_tool",
		Model:               "pre_tool",
		StatusCode:          429,
		SessionID:           "sess",
		TrajectoryID:        "traj",
		StepID:              "step-1",
		ToolSignature:       "refund_customer",
		ArgsFingerprint:     "args",
		DecisionStage:       "pre_tool",
		LoopAction:          "block",
		LoopSignalsFired:    "policy_amount_exceeded",
		LoopConfidence:      0.99,
		DetectorVersion:     "detector",
		DecisionID:          "dec_1",
		ActionRisk:          "write",
		IdempotencyKeyHash:  "sha256:refund",
		ResourceFingerprint: "sha256:invoice",
		AmountCents:         7500,
		MaxAmountCents:      5000,
		PolicyVersion:       "action-firewall/2",
		DecisionReason:      "amount exceeded",
		DecisionEvidence:    "amount_cents=7500; max_amount_cents=5000",
	}
}
