package receipts

import (
	"testing"

	"github.com/witness-proxy/witness-proxy/internal/wal"
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
		Project:          "proj",
		Provider:         "_tool",
		Model:            "pre_tool",
		StatusCode:       429,
		SessionID:        "sess",
		TrajectoryID:     "traj",
		StepID:           "step-1",
		ToolSignature:    "refund_customer",
		ArgsFingerprint:  "args",
		DecisionStage:    "pre_tool",
		LoopAction:       "block",
		LoopSignalsFired: "policy_amount_exceeded",
		LoopConfidence:   0.99,
		DetectorVersion:  "detector",
		DecisionID:       "dec_1",
		ActionRisk:       "write",
		IdempotencyKey:   "refund:1",
		ResourceID:       "invoice_1",
		AmountCents:      7500,
		MaxAmountCents:   5000,
		PolicyVersion:    "action-firewall/2",
		DecisionReason:   "amount exceeded",
		DecisionEvidence: "amount_cents=7500; max_amount_cents=5000",
	}
}
