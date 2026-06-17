package evidencepack

import (
	"strings"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func signedChain(t *testing.T, secret string, recs []wal.Record) []wal.Record {
	t.Helper()
	prev := "genesis"
	for i := range recs {
		sig, err := receipts.SignRecord([]byte(secret), recs[i])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		recs[i].ReceiptSignature = sig
		recs[i].ReceiptKeyID = "test"
		if err := wal.Chain(&recs[i], prev); err != nil {
			t.Fatalf("chain: %v", err)
		}
		prev = recs[i].RecordHash
	}
	return recs
}

func baseRecord(decisionID string, when time.Time) wal.Record {
	return wal.Record{
		Time:            when,
		Project:         "acme",
		Provider:        "_tool",
		Model:           "pre_tool",
		DecisionStage:   "pre_tool",
		DecisionID:      decisionID,
		ToolSignature:   "refund_customer",
		ActionRisk:      "write",
		PolicyVersion:   loop.ActionPolicyVersion,
		DetectorVersion: loop.DetectorVersion,
		DecisionReason:  "decision",
	}
}

func TestBuildEvidencePackCountsAndControls(t *testing.T) {
	secret := "evidence-secret"
	when := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

	dup := baseRecord("dec_dup", when)
	dup.LoopAction = "shadow_would_block"
	dup.LoopSignalsFired = loop.SignalDuplicateSideEffect
	dup.ResultClass = "duplicate"

	policy := baseRecord("dec_policy", when)
	policy.LoopAction = "block"
	policy.ImmediateOutcome = "blocked"
	policy.LoopSignalsFired = loop.SignalPolicyAmountExceeded

	records := signedChain(t, secret, []wal.Record{dup, policy})

	pub := receipts.NewSigner("test", []byte(secret)).PublicKeyBase64()
	pack := Build(records, Options{
		Project:          "acme",
		Since:            time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		Until:            time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		ReceiptPublicKey: pub,
	})

	if pack.TotalActionDecisions != 2 {
		t.Fatalf("total_action_decisions=%d want 2", pack.TotalActionDecisions)
	}
	if !pack.Integrity.Verified {
		t.Fatalf("integrity not verified: %+v", pack.Integrity)
	}
	if !pack.Integrity.HashChainIntact || pack.Integrity.SignatureMismatches != 0 {
		t.Fatalf("integrity weak: %+v", pack.Integrity)
	}

	got := map[string]LineItem{}
	for _, item := range pack.LineItems {
		got[item.Category] = item
	}
	if got["Duplicate side-effect actions prevented"].Count != 1 {
		t.Fatalf("duplicate count=%d want 1", got["Duplicate side-effect actions prevented"].Count)
	}
	if got["Policy violations blocked"].Count != 1 {
		t.Fatalf("policy count=%d want 1", got["Policy violations blocked"].Count)
	}
	if _, ok := got["Tamper-evident decision log"]; !ok {
		t.Fatalf("missing tamper-evident decision log line item")
	}

	// Each enforced line item must carry at least one EU AI Act control reference.
	for name, item := range got {
		hasAIAct := false
		for _, c := range item.Controls {
			if c.Framework == "EU AI Act" {
				hasAIAct = true
			}
		}
		if !hasAIAct {
			t.Fatalf("line item %q has no EU AI Act control mapping", name)
		}
	}

	md := RenderMarkdown(pack)
	if !strings.Contains(md, "HubbleOps Evidence Pack") || !strings.Contains(md, "Article 12") {
		t.Fatalf("markdown missing headline/control: %s", md)
	}
	if !strings.Contains(md, "not an audit") {
		t.Fatalf("markdown missing honesty notice")
	}
}

func TestBuildEvidencePackDetectsTampering(t *testing.T) {
	secret := "evidence-secret"
	when := time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)
	rec := baseRecord("dec_1", when)
	rec.LoopSignalsFired = loop.SignalDuplicateSideEffect
	records := signedChain(t, secret, []wal.Record{rec})

	// Tamper after signing+chaining.
	records[0].ActionRisk = "read"

	pub := receipts.NewSigner("test", []byte(secret)).PublicKeyBase64()
	pack := Build(records, Options{ReceiptPublicKey: pub})
	if pack.Integrity.Verified {
		t.Fatalf("tampered pack reported verified")
	}
	if pack.Integrity.SignatureMismatches == 0 && pack.Integrity.HashMismatches == 0 {
		t.Fatalf("tampering not detected: %+v", pack.Integrity)
	}
}

func TestBuildEvidencePackFiltersByRange(t *testing.T) {
	secret := "evidence-secret"
	inRange := baseRecord("dec_in", time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC))
	outOfRange := baseRecord("dec_out", time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC))
	records := signedChain(t, secret, []wal.Record{outOfRange, inRange})

	pack := Build(records, Options{
		Since: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
		Until: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
	})
	if pack.TotalActionDecisions != 1 {
		t.Fatalf("range filter total=%d want 1", pack.TotalActionDecisions)
	}
}
