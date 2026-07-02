package receiptverify

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/action"
	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

// The streaming Verifier (constant memory) must produce the same verdict as the slice path,
// including detecting a chain break at the same index.
func TestStreamVerifierMatchesSliceVerify(t *testing.T) {
	records := []wal.Record{
		receiptRecord("dec_1", "genesis"),
		receiptRecord("dec_2", ""),
		receiptRecord("dec_3", ""),
	}
	_ = wal.Chain(&records[0], "genesis", 1)
	_ = wal.Chain(&records[1], records[0].RecordHash, 2)
	_ = wal.Chain(&records[2], records[1].RecordHash, 3)
	// Break the chain at index 2.
	records[2].PrevHash = "tampered"

	slice := VerifyWithOptions(records, Options{})

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range records {
		_ = enc.Encode(r)
	}
	v, err := NewVerifier(Options{})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	if err := v.AddStream(&buf); err != nil {
		t.Fatalf("add stream: %v", err)
	}
	stream := v.Report()

	if slice.ChainBrokenAt != 2 || stream.ChainBrokenAt != 2 {
		t.Fatalf("chain break: slice=%d stream=%d want 2", slice.ChainBrokenAt, stream.ChainBrokenAt)
	}
	if slice.Verified != stream.Verified || slice.TotalRecords != stream.TotalRecords || slice.ActionReceipts != stream.ActionReceipts {
		t.Fatalf("slice=%+v stream=%+v", slice, stream)
	}
}

// A chain whose receipts were signed by two different keys (a rotation) verifies when both
// public keys are supplied as a keyset.
func TestVerifyWithRotatedKeySet(t *testing.T) {
	oldSigner := receipts.NewSigner("k-old", []byte("old-secret"))
	newSigner := receipts.NewSigner("k-new", []byte("new-secret"))

	r1 := receiptRecord("dec_1", "genesis")
	r1.ReceiptKeyID = oldSigner.KeyID()
	if err := wal.Chain(&r1, "genesis", 1); err != nil {
		t.Fatalf("chain r1: %v", err)
	}
	s1, kid1, _ := oldSigner.SignRecord(r1)
	r1.ReceiptSignature, r1.ReceiptKeyID = s1, kid1
	if err := wal.Chain(&r1, "genesis", 1); err != nil {
		t.Fatalf("rechain signed r1: %v", err)
	}
	r2 := receiptRecord("dec_2", r1.RecordHash)
	r2.ReceiptKeyID = newSigner.KeyID()
	if err := wal.Chain(&r2, r1.RecordHash, 2); err != nil {
		t.Fatalf("chain r2: %v", err)
	}
	s2, kid2, _ := newSigner.SignRecord(r2)
	r2.ReceiptSignature, r2.ReceiptKeyID = s2, kid2
	if err := wal.Chain(&r2, r1.RecordHash, 2); err != nil {
		t.Fatalf("rechain signed r2: %v", err)
	}

	report := VerifyWithOptions([]wal.Record{r1, r2}, Options{
		ReceiptPublicKeys: map[string]string{
			"k-old": oldSigner.PublicKeyBase64(),
			"k-new": newSigner.PublicKeyBase64(),
		},
		RequireSignatures: true,
	})
	if !report.Verified || report.SignatureMismatches != 0 {
		t.Fatalf("rotated keyset did not verify: %+v", report)
	}
}

func TestVerifyValidReceiptChain(t *testing.T) {
	records := []wal.Record{
		receiptRecord("dec_1", "genesis"),
		receiptRecord("dec_2", ""),
	}
	if err := wal.Chain(&records[0], "genesis", 1); err != nil {
		t.Fatalf("chain first: %v", err)
	}
	if err := wal.Chain(&records[1], records[0].RecordHash, 2); err != nil {
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

func TestRechainedSignedWALDropIsRejected(t *testing.T) {
	secret := "receipt-secret"
	records := signedReceiptChain(t, secret, "dec_allow_1", "dec_block", "dec_allow_2")
	attacker := rechainForTest([]wal.Record{records[0], records[2]})
	anchor := signedAnchorForTest(t, secret, records[len(records)-1])

	report := VerifyWithOptions(attacker, Options{ReceiptSecret: secret, RequireSignatures: true})
	if report.Verified {
		t.Fatalf("drop/rechain attack should not verify: %+v", report)
	}
	if report.SignatureMismatches == 0 && report.SeqGaps == 0 {
		t.Fatalf("drop/rechain should be caught by signature binding or sequence gap: %+v", report)
	}
	anchored := VerifyWithOptions(attacker, Options{ReceiptSecret: secret, RequireSignatures: true, Anchor: anchor})
	if anchored.Verified || anchored.AnchorMismatches == 0 {
		t.Fatalf("drop/rechain attack should also fail anchored verification: %+v", anchored)
	}
}

func TestRechainedSignedWALTruncateBelowAnchorIsRejected(t *testing.T) {
	secret := "receipt-secret"
	records := signedReceiptChain(t, secret, "dec_allow_1", "dec_block", "dec_allow_2")
	attacker := rechainForTest(records[:2])
	anchor := signedAnchorForTest(t, secret, records[len(records)-1])

	report := VerifyWithOptions(attacker, Options{ReceiptSecret: secret, RequireSignatures: true, Anchor: anchor})
	if report.Verified {
		t.Fatalf("truncation below anchor should not verify: %+v", report)
	}
	if report.AnchorMismatches != 1 {
		t.Fatalf("truncation should be caught by anchor mismatch: %+v", report)
	}
	want := "truncation detected: anchored seq=3, wal max seq=2"
	if report.Recommendation != want {
		t.Fatalf("recommendation=%q want %q", report.Recommendation, want)
	}
}

func TestRechainedSignedWALTruncateWithoutAnchorStillVerifies(t *testing.T) {
	secret := "receipt-secret"
	records := signedReceiptChain(t, secret, "dec_allow_1", "dec_block", "dec_allow_2")
	truncated := records[:2]

	report := VerifyWithOptions(truncated, Options{ReceiptSecret: secret, RequireSignatures: true})
	if !report.Verified {
		t.Fatalf("local-only verification cannot prove end truncation without an anchor: %+v", report)
	}
}

func TestRechainedSignedWALReorderIsRejected(t *testing.T) {
	secret := "receipt-secret"
	records := signedReceiptChain(t, secret, "dec_allow_1", "dec_block", "dec_allow_2")
	attacker := rechainForTest([]wal.Record{records[1], records[0], records[2]})
	anchor := signedAnchorForTest(t, secret, records[len(records)-1])

	report := VerifyWithOptions(attacker, Options{ReceiptSecret: secret, RequireSignatures: true})
	if report.Verified {
		t.Fatalf("reorder/rechain attack should not verify: %+v", report)
	}
	if report.SignatureMismatches == 0 && report.SeqGaps == 0 && report.ChainBrokenAt == -1 {
		t.Fatalf("reorder/rechain should be caught by signature, sequence, or chain check: %+v", report)
	}
	anchored := VerifyWithOptions(attacker, Options{ReceiptSecret: secret, RequireSignatures: true, Anchor: anchor})
	if anchored.Verified || anchored.AnchorMismatches == 0 {
		t.Fatalf("reorder/rechain attack should also fail anchored verification: %+v", anchored)
	}
}

func TestVerifyDetectsTamperedReceipt(t *testing.T) {
	rec := receiptRecord("dec_1", "genesis")
	if err := wal.Chain(&rec, "genesis", 1); err != nil {
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
	rec.ReceiptKeyID = "test"
	if err := wal.Chain(&rec, "genesis", 1); err != nil {
		t.Fatalf("chain: %v", err)
	}
	sig, err := receipts.SignRecord([]byte(secret), rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec.ReceiptSignature = sig
	if err := wal.Chain(&rec, "genesis", 1); err != nil {
		t.Fatalf("rechain signed: %v", err)
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
	rec.ReceiptKeyID = "test"
	if err := wal.Chain(&rec, "genesis", 1); err != nil {
		t.Fatalf("chain: %v", err)
	}
	sig, err := receipts.SignRecord([]byte(secret), rec)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	rec.ReceiptSignature = sig
	rec.DecisionReason = "tampered before hash chain"
	if err := wal.Chain(&rec, "genesis", 1); err != nil {
		t.Fatalf("rechain tampered: %v", err)
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
	if err := wal.Chain(&rec, "genesis", 1); err != nil {
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
	if err := wal.Chain(&rec, "genesis", 1); err != nil {
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
	if err := wal.Chain(&records[0], "genesis", 1); err != nil {
		t.Fatalf("chain first: %v", err)
	}
	if err := wal.Chain(&records[1], records[0].RecordHash, 2); err != nil {
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
	loaded, err := readJSONLRecords(in)
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

func TestVerifyPreflightReceiptRequiresEngineeringFields(t *testing.T) {
	rec := preflightReceiptRecord("dec_preflight", "genesis")
	if err := wal.Chain(&rec, "genesis", 1); err != nil {
		t.Fatalf("chain: %v", err)
	}
	if report := Verify([]wal.Record{rec}); !report.Verified {
		t.Fatalf("complete preflight receipt should verify: %+v", report)
	}

	rec.Action = ""
	if err := wal.Chain(&rec, "genesis", 1); err != nil {
		t.Fatalf("rechain: %v", err)
	}
	report := Verify([]wal.Record{rec})
	if report.ReceiptFieldGaps != 1 {
		t.Fatalf("missing action should be a field gap: %+v", report)
	}
}

func TestLegacyRecordsRequireExplicitLegacyMode(t *testing.T) {
	rec := receiptRecord("dec_legacy", "genesis")
	if err := wal.Chain(&rec, "genesis"); err != nil {
		t.Fatalf("chain legacy: %v", err)
	}

	report := Verify([]wal.Record{rec})
	if report.Verified {
		t.Fatalf("legacy record should not verify by default: %+v", report)
	}
	if report.MissingSeq != 1 {
		t.Fatalf("missing_seq=%d want 1: %+v", report.MissingSeq, report)
	}

	report = VerifyWithOptions([]wal.Record{rec}, Options{Legacy: true})
	if !report.Verified {
		t.Fatalf("legacy record should verify with explicit legacy mode and no anchor: %+v", report)
	}
}

func TestLegacyModeRejectedWithAnchor(t *testing.T) {
	secret := "receipt-secret"
	records := signedReceiptChain(t, secret, "dec_1")
	anchor := signedAnchorForTest(t, secret, records[0])
	rec := records[0]
	rec.Seq = 0
	if err := wal.Chain(&rec, "genesis"); err != nil {
		t.Fatalf("rechain legacy: %v", err)
	}

	report := VerifyWithOptions([]wal.Record{rec}, Options{Legacy: true, Anchor: anchor})
	if report.Verified {
		t.Fatalf("legacy verification with an anchor should be rejected: %+v", report)
	}
	if report.Recommendation != "legacy verification cannot be used with an anchor" {
		t.Fatalf("recommendation=%q", report.Recommendation)
	}
}

func TestAnchorRequiresVerificationKey(t *testing.T) {
	secret := "receipt-secret"
	records := signedReceiptChain(t, secret, "dec_1")
	anchor := signedAnchorForTest(t, secret, records[0])

	report := VerifyWithOptions(records, Options{Anchor: anchor})
	if report.Verified {
		t.Fatalf("anchored verification without key should fail closed: %+v", report)
	}
	if report.Recommendation != "anchor verification requires a receipt public key, keyset, or secret" {
		t.Fatalf("recommendation=%q", report.Recommendation)
	}
}

func readJSONLRecords(r io.Reader) ([]wal.Record, error) {
	dec := json.NewDecoder(r)
	var records []wal.Record
	for {
		var rec wal.Record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				return records, nil
			}
			return nil, err
		}
		records = append(records, rec)
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

func preflightReceiptRecord(decisionID, prevHash string) wal.Record {
	return wal.Record{
		Time:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Project:          "project",
		Provider:         "_preflight",
		Model:            "preflight",
		PromptHash:       "prompt",
		StatusCode:       200,
		SessionID:        "session",
		DecisionStage:    "preflight",
		PrevHash:         prevHash,
		DecisionID:       decisionID,
		PolicyVersion:    action.PolicyVersion,
		DecisionReason:   "destructive engineering action detected",
		DecisionEvidence: "terraform_action=delete",
		DetectorVersion:  "preflight",
		Actor:            "agent:claude-code",
		HumanDelegator:   "krish",
		Action:           "terraform.destroy",
		Target:           "aws_s3_bucket.audit_logs_prod",
		Environment:      "production",
		IntentHash:       "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EvidenceHashes:   []string{"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		BlastRadius:      "high",
		RiskScore:        95,
		Decision:         action.DecisionBlock,
	}
}

func signedReceiptChain(t *testing.T, secret string, decisionIDs ...string) []wal.Record {
	t.Helper()
	records := make([]wal.Record, 0, len(decisionIDs))
	signer := receipts.NewSigner("test", []byte(secret))
	prev := "genesis"
	for i, id := range decisionIDs {
		seq := uint64(i + 1)
		rec := receiptRecord(id, prev)
		rec.ReceiptKeyID = signer.KeyID()
		if err := wal.Chain(&rec, prev, seq); err != nil {
			t.Fatalf("chain %s: %v", id, err)
		}
		sig, kid, err := signer.SignRecord(rec)
		if err != nil {
			t.Fatalf("sign %s: %v", id, err)
		}
		rec.ReceiptSignature, rec.ReceiptKeyID = sig, kid
		if err := wal.Chain(&rec, prev, seq); err != nil {
			t.Fatalf("rechain signed %s: %v", id, err)
		}
		prev = rec.RecordHash
		records = append(records, rec)
	}
	return records
}

func signedAnchorForTest(t *testing.T, secret string, rec wal.Record) wal.Anchor {
	t.Helper()
	anchor := wal.NewFileAnchor(filepath.Join(t.TempDir(), "checkpoints.jsonl"))
	signer := receipts.NewSigner("test", []byte(secret))
	cp, err := signer.SignCheckpoint(wal.Checkpoint{
		Seq:      rec.Seq,
		HeadHash: rec.RecordHash,
		Count:    rec.Seq,
		SignedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	if err := anchor.Publish(context.Background(), cp); err != nil {
		t.Fatalf("publish checkpoint: %v", err)
	}
	return anchor
}

func rechainForTest(records []wal.Record) []wal.Record {
	out := append([]wal.Record(nil), records...)
	prev := "genesis"
	for i := range out {
		_ = wal.Chain(&out[i], prev, out[i].Seq)
		prev = out[i].RecordHash
	}
	return out
}
