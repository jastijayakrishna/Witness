package receiptverify

import (
	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/receipts"
	"github.com/witness-proxy/witness-proxy/internal/wal"
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
	LastRecordHash                   string `json:"last_record_hash,omitempty"`
	Verified                         bool   `json:"verified"`
	Recommendation                   string `json:"recommendation,omitempty"`
	FirstGapDecisionID               string `json:"first_gap_decision_id,omitempty"`
	FirstSignatureMismatchDecisionID string `json:"first_signature_mismatch_decision_id,omitempty"`
}

func Verify(records []wal.Record) Report {
	return VerifyWithOptions(records, Options{})
}

type Options struct {
	ReceiptSecret     string
	RequireSignatures bool
}

func VerifyWithOptions(records []wal.Record, opts Options) Report {
	report := Report{TotalRecords: len(records), ChainBrokenAt: -1, Verified: true}
	for i, rec := range records {
		if rec.PrevHash == "" || rec.RecordHash == "" {
			report.MissingHashes++
		} else {
			if wal.RecomputeHash(rec) != rec.RecordHash {
				report.HashMismatches++
			}
		}
		if rec.RecordHash != "" {
			report.LastRecordHash = rec.RecordHash
		}
		if rec.DecisionID != "" {
			report.ActionReceipts++
			if rec.ReceiptSignature == "" {
				report.UnsignedReceipts++
			} else {
				report.SignedReceipts++
				if opts.ReceiptSecret != "" {
					if err := receipts.VerifyRecord([]byte(opts.ReceiptSecret), rec); err != nil {
						report.SignatureMismatches++
						if report.FirstSignatureMismatchDecisionID == "" {
							report.FirstSignatureMismatchDecisionID = rec.DecisionID
						}
					}
				}
			}
			if receiptHasGap(rec) {
				report.ReceiptFieldGaps++
				if report.FirstGapDecisionID == "" {
					report.FirstGapDecisionID = rec.DecisionID
				}
			}
		}
		if i > 0 && rec.PrevHash != records[i-1].RecordHash && report.ChainBrokenAt == -1 {
			report.ChainBrokenAt = i
		}
	}
	report.Verified = report.MissingHashes == 0 &&
		report.HashMismatches == 0 &&
		report.SignatureMismatches == 0 &&
		report.ChainBrokenAt == -1 &&
		report.ReceiptFieldGaps == 0 &&
		(!opts.RequireSignatures || report.UnsignedReceipts == 0)
	if !report.Verified {
		report.Recommendation = "treat this audit export as untrusted until hash mismatches, signature mismatches, chain breaks, and receipt field gaps are resolved"
	}
	return report
}

func receiptHasGap(rec wal.Record) bool {
	if rec.Provider != "_tool" {
		return false
	}
	if rec.DetectorVersion == "" || rec.LoopAction == "" || rec.DecisionReason == "" {
		return true
	}
	risk := loop.NormalizeActionRisk(rec.ActionRisk)
	if risk != loop.ActionRiskRead && risk != "" {
		return rec.PolicyVersion == ""
	}
	return false
}
