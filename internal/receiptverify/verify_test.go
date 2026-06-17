package receiptverify

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/shadowreport"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func TestVerifyValidReceiptChain(t *testing.T) {
	records := []wal.Record{
		receiptRecord("dec_1", "genesis"),
		receiptRecord("dec_2", ""),
	}
	if err := wal.Chain(&records[0], "genesis"); err != nil {
		t.Fatalf("chain first: %v", err)
	}
	if err := wal.Chain(&records[1], records[0].RecordHash); err != nil {
		t.Fatalf("chain second: %v", err)
	}

	report := Verify(records)
	if !report.Verified {
		t.Fatalf("report not verified: %+v", report)
	}
	if report.ActionReceipts != 2 {
		t.Fatalf("action_receipts=%d want 2", report.ActionReceipts)
	}
	if report.ChainBrokenAt != -1 {
		t.Fatalf("chain_broken_at=%d want -1", report.ChainBrokenAt)
	}
}

func TestVerifyDetectsTamperedReceipt(t *testing.T) {
	rec := receiptRecord("dec_1", "genesis")
	if err := wal.Chain(&rec, "genesis"); err != nil {
		t.Fatalf("chain: %v", err)
	}
	rec.DecisionReason = "tampered after receipt was issued"

	report := Verify([]wal.Record{rec})
	if report.Verified {
		t.Fatalf("tampered report should not verify: %+v", report)
	}
	if report.HashMismatches != 1 {
		t.Fatalf("hash_mismatches=%d want 1", report.HashMismatches)
	}
}

func TestVerifyRejectsMissingHashes(t *testing.T) {
	rec := receiptRecord("dec_1", "")
	report := Verify([]wal.Record{rec})
	if report.Verified {
		t.Fatalf("missing hashes should not verify: %+v", report)
	}
	if report.MissingHashes != 1 {
		t.Fatalf("missing_hashes=%d want 1", report.MissingHashes)
	}
}

func TestVerifySignedReceipts(t *testing.T) {
	secret := "receipt-secret"
	rec := receiptRecord("dec_1", "genesis")
	sig, err := receipts.SignRecord([]byte(secret), rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec.ReceiptSignature = sig
	rec.ReceiptKeyID = "test"
	if err := wal.Chain(&rec, "genesis"); err != nil {
		t.Fatalf("chain: %v", err)
	}

	report := VerifyWithOptions([]wal.Record{rec}, Options{
		ReceiptSecret:     secret,
		RequireSignatures: true,
	})
	if !report.Verified {
		t.Fatalf("signed report did not verify: %+v", report)
	}
	if report.SignedReceipts != 1 || report.UnsignedReceipts != 0 {
		t.Fatalf("signed=%d unsigned=%d", report.SignedReceipts, report.UnsignedReceipts)
	}
}

func TestVerifyDetectsReceiptSignatureMismatch(t *testing.T) {
	secret := "receipt-secret"
	rec := receiptRecord("dec_1", "genesis")
	sig, err := receipts.SignRecord([]byte(secret), rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec.ReceiptSignature = sig
	rec.ReceiptKeyID = "test"
	rec.DecisionReason = "tampered before hash chain"
	if err := wal.Chain(&rec, "genesis"); err != nil {
		t.Fatalf("chain: %v", err)
	}

	report := VerifyWithOptions([]wal.Record{rec}, Options{
		ReceiptSecret:     secret,
		RequireSignatures: true,
	})
	if report.Verified {
		t.Fatalf("signature mismatch should not verify: %+v", report)
	}
	if report.HashMismatches != 0 {
		t.Fatalf("hash_mismatches=%d want 0", report.HashMismatches)
	}
	if report.SignatureMismatches != 1 {
		t.Fatalf("signature_mismatches=%d want 1", report.SignatureMismatches)
	}
}

func TestVerifyResultStageReceiptHasNoPolicyGap(t *testing.T) {
	// The post-execution (post_tool) result receipt records an outcome, not a policy
	// decision — the action firewall only runs at pre_tool — so it carries no action
	// policy version and must NOT be flagged as a field gap. Regression for the audit
	// reading verified=false on a fully intact, signed, chained WAL.
	rec := receiptRecord("dec_result", "genesis")
	rec.Model = "post_tool"
	rec.DecisionStage = "post_tool"
	rec.LoopAction = "allow"
	rec.LoopSignalsFired = ""
	rec.DecisionReason = "No loop pattern detected."
	rec.PolicyVersion = "" // result stage makes no policy decision
	if err := wal.Chain(&rec, "genesis"); err != nil {
		t.Fatalf("chain: %v", err)
	}

	report := Verify([]wal.Record{rec})
	if report.ReceiptFieldGaps != 0 {
		t.Fatalf("result-stage receipt flagged as a gap: %+v", report)
	}
	if !report.Verified {
		t.Fatalf("intact result-stage receipt should verify: %+v", report)
	}
}

func TestVerifyPreToolWriteStillRequiresPolicyVersion(t *testing.T) {
	// A pre_tool decision receipt for a write action that judged the action without a
	// policy version is still a real gap — the stage-scoping must not weaken this.
	rec := receiptRecord("dec_decision", "genesis")
	rec.PolicyVersion = ""
	if err := wal.Chain(&rec, "genesis"); err != nil {
		t.Fatalf("chain: %v", err)
	}

	report := Verify([]wal.Record{rec})
	if report.ReceiptFieldGaps != 1 {
		t.Fatalf("pre_tool write without policy_version must be a gap: %+v", report)
	}
	if report.Verified {
		t.Fatalf("decision receipt missing policy_version should not verify: %+v", report)
	}
}

func TestVerifyJSONLExport(t *testing.T) {
	records := []wal.Record{
		receiptRecord("dec_1", "genesis"),
		receiptRecord("dec_2", ""),
	}
	if err := wal.Chain(&records[0], "genesis"); err != nil {
		t.Fatalf("chain first: %v", err)
	}
	if err := wal.Chain(&records[1], records[0].RecordHash); err != nil {
		t.Fatalf("chain second: %v", err)
	}
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	enc := json.NewEncoder(f)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			t.Fatalf("encode fixture: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	in, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	loaded, err := shadowreport.ReadJSONL(in)
	if closeErr := in.Close(); closeErr != nil {
		t.Fatalf("close read fixture: %v", closeErr)
	}
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	report := Verify(loaded)
	if !report.Verified {
		t.Fatalf("JSONL export did not verify: %+v", report)
	}
}

func receiptRecord(decisionID, prevHash string) wal.Record {
	return wal.Record{
		Time:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Project:          "project",
		Provider:         "_tool",
		Model:            "pre_tool",
		PromptHash:       "prompt",
		StatusCode:       200,
		SessionID:        "session",
		ToolSignature:    "refund_customer",
		DecisionStage:    "pre_tool",
		LoopSignalsFired: loop.SignalDuplicateSideEffect,
		LoopConfidence:   1,
		LoopAction:       "block",
		LoopEvidence:     "duplicate side-effect blocked",
		PrevHash:         prevHash,
		DecisionID:       decisionID,
		ActionRisk:       "write",
		IdempotencyKey:   "refund:1",
		PolicyVersion:    loop.ActionPolicyVersion,
		DecisionReason:   "duplicate side-effect blocked",
		DecisionEvidence: "idempotency_key=repeated",
		DetectorVersion:  loop.DetectorVersion,
	}
}
