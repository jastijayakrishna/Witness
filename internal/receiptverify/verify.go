package receiptverify

import (
	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/wal"
)

type Report struct {
	TotalRecords                     int    `json:"total_records"`
	ActionReceipts                   int    `json:"action_receipts"`
	SignedReceipts                   int    `json:"signed_receipts"`
	UnsignedReceipts                 int    `json:"unsigned_receipts"`
	MissingHashes                    int    `json:"missing_hashes"`
	HashMismatches                   int    `json:"hash_mismatches"`
	SignatureMismatches              int    `json:"signature_mismatches"`
	ChainBrokenAt                    int    `json:"chain_broken_at"`
	ReceiptFieldGaps                 int    `json:"receipt_field_gaps"`
	MissingSeq                       int    `json:"missing_seq"`
	SeqGaps                          int    `json:"seq_gaps"`
	AnchorMismatches                 int    `json:"anchor_mismatches"`
	AnchorSignatureMismatches        int    `json:"anchor_signature_mismatches"`
	LastRecordHash                   string `json:"last_record_hash,omitempty"`
	MaxSeq                           uint64 `json:"max_seq,omitempty"`
	Verified                         bool   `json:"verified"`
	Recommendation                   string `json:"recommendation,omitempty"`
	FirstGapDecisionID               string `json:"first_gap_decision_id,omitempty"`
	FirstSeqGapDecisionID            string `json:"first_seq_gap_decision_id,omitempty"`
	ChainBrokenDecisionID            string `json:"chain_broken_decision_id,omitempty"`
	FirstSignatureMismatchDecisionID string `json:"first_signature_mismatch_decision_id,omitempty"`
	AnchorSeq                        uint64 `json:"anchor_seq,omitempty"`
	AnchorHeadHash                   string `json:"anchor_head_hash,omitempty"`
}

func Verify(records []wal.Record) Report {
	return VerifyWithOptions(records, Options{})
}

type Options struct {
	ReceiptSecret     string
	ReceiptPublicKey  string
	ReceiptPublicKeys map[string]string // key_id -> base64 public key, for verifying across rotation
	RequireSignatures bool
	Legacy            bool
	Anchor            wal.Anchor
}

// VerifyWithOptions verifies an in-memory slice by feeding it through the streaming
// Verifier, so the slice and streaming paths share identical logic.
func VerifyWithOptions(records []wal.Record, opts Options) Report {
	v, err := NewVerifier(opts)
	if err != nil {
		return Report{ChainBrokenAt: -1, Verified: false, Recommendation: err.Error()}
	}
	for i := range records {
		v.Add(records[i])
	}
	return v.Report()
}

func receiptHasGap(rec wal.Record) bool {
	if rec.Provider == "_preflight" {
		return rec.Project == "" ||
			rec.SessionID == "" ||
			rec.DecisionID == "" ||
			rec.Actor == "" ||
			rec.Action == "" ||
			rec.Decision == "" ||
			rec.PolicyVersion == "" ||
			rec.DecisionReason == ""
	}
	if rec.Provider != "_tool" {
		return false
	}
	if rec.DetectorVersion == "" || rec.LoopAction == "" || rec.DecisionReason == "" {
		return true
	}
	// A policy version is only expected on the decision-stage (pre_tool) receipt that
	// actually judged the action. The post_tool result receipt records the outcome of a
	// side effect, not a policy decision, so it legitimately carries no action policy
	// version and must not be flagged — doing so dragged verified=false on intact WALs.
	risk := loop.NormalizeActionRisk(rec.ActionRisk)
	if rec.DecisionStage == "pre_tool" && risk != loop.ActionRiskRead && risk != "" {
		return rec.PolicyVersion == ""
	}
	return false
}
