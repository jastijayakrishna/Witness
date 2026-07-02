package receiptverify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

// Verifier checks a receipt chain one record at a time, holding O(1) memory regardless of
// how many receipts it processes — so verifying a 10M-record WAL never materializes the
// whole log. The chain check only needs the previous record's hash, and all other checks
// are per-record counters.
type Verifier struct {
	opts             Options
	verify           func(wal.Record) error
	verifyCheckpoint func(wal.Checkpoint) error
	report           Report
	index            int
	prevHash         string
	prevSet          bool
	expectedSeq      uint64
	anchorCheckpoint wal.Checkpoint
	hasAnchor        bool
	anchorHashSeen   string
}

func NewVerifier(opts Options) (*Verifier, error) {
	if opts.Legacy && opts.Anchor != nil {
		return nil, fmt.Errorf("legacy verification cannot be used with an anchor")
	}
	verify, err := buildVerify(opts)
	if err != nil {
		return nil, err
	}
	verifyCheckpoint, err := buildCheckpointVerify(opts)
	if err != nil {
		return nil, err
	}
	if opts.Anchor != nil && verifyCheckpoint == nil {
		return nil, fmt.Errorf("anchor verification requires a receipt public key, keyset, or secret")
	}
	v := &Verifier{opts: opts, verify: verify, verifyCheckpoint: verifyCheckpoint, report: Report{ChainBrokenAt: -1}, expectedSeq: 1}
	if opts.Anchor != nil {
		cp, err := opts.Anchor.Latest(context.Background())
		if err != nil {
			return nil, fmt.Errorf("read anchor: %w", err)
		}
		v.anchorCheckpoint = cp
		v.hasAnchor = true
		v.report.AnchorSeq = cp.Seq
		v.report.AnchorHeadHash = cp.HeadHash
		if verifyCheckpoint != nil {
			if err := verifyCheckpoint(cp); err != nil {
				v.report.AnchorSignatureMismatches++
				v.report.Recommendation = "anchor signature mismatch: " + err.Error()
			}
		}
	}
	return v, nil
}

// buildVerify selects the signature-verification strategy: a multi-key keyset (rotation), a
// single public key (auditor), or the operator secret. Nil means signatures are not checked.
func buildVerify(opts Options) (func(wal.Record) error, error) {
	if len(opts.ReceiptPublicKeys) > 0 {
		ks := receipts.NewKeySet()
		for keyID, encoded := range opts.ReceiptPublicKeys {
			pub, err := receipts.ParsePublicKey(encoded)
			if err != nil {
				return nil, fmt.Errorf("invalid receipt public key for key_id %s: %w", keyID, err)
			}
			ks.Add(keyID, pub)
		}
		return func(rec wal.Record) error {
			if err := ks.VerifyRecord(rec); err != nil {
				if opts.Legacy && rec.Seq == 0 {
					return ks.VerifyLegacyRecord(rec)
				}
				return err
			}
			return nil
		}, nil
	}
	if opts.ReceiptPublicKey != "" {
		pub, err := receipts.ParsePublicKey(opts.ReceiptPublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid receipt public key: %w", err)
		}
		return func(rec wal.Record) error {
			if err := receipts.VerifyRecordWithPublicKey(pub, rec); err != nil {
				if opts.Legacy && rec.Seq == 0 {
					return receipts.VerifyLegacyRecordWithPublicKey(pub, rec)
				}
				return err
			}
			return nil
		}, nil
	}
	if opts.ReceiptSecret != "" {
		secret := []byte(opts.ReceiptSecret)
		pub := receipts.PublicKeyFromSecret(secret)
		return func(rec wal.Record) error {
			if err := receipts.VerifyRecordWithPublicKey(pub, rec); err != nil {
				if opts.Legacy && rec.Seq == 0 {
					return receipts.VerifyLegacyRecordWithPublicKey(pub, rec)
				}
				return err
			}
			return nil
		}, nil
	}
	return nil, nil
}

func buildCheckpointVerify(opts Options) (func(wal.Checkpoint) error, error) {
	if len(opts.ReceiptPublicKeys) > 0 {
		ks := receipts.NewKeySet()
		for keyID, encoded := range opts.ReceiptPublicKeys {
			pub, err := receipts.ParsePublicKey(encoded)
			if err != nil {
				return nil, fmt.Errorf("invalid receipt public key for key_id %s: %w", keyID, err)
			}
			ks.Add(keyID, pub)
		}
		return func(cp wal.Checkpoint) error { return ks.VerifyCheckpoint(cp) }, nil
	}
	if opts.ReceiptPublicKey != "" {
		pub, err := receipts.ParsePublicKey(opts.ReceiptPublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid receipt public key: %w", err)
		}
		return func(cp wal.Checkpoint) error { return receipts.VerifyCheckpointWithPublicKey(pub, cp) }, nil
	}
	if opts.ReceiptSecret != "" {
		pub := receipts.PublicKeyFromSecret([]byte(opts.ReceiptSecret))
		return func(cp wal.Checkpoint) error { return receipts.VerifyCheckpointWithPublicKey(pub, cp) }, nil
	}
	return nil, nil
}

// Add processes one record in chain order.
func (v *Verifier) Add(rec wal.Record) {
	if rec.PrevHash == "" || rec.RecordHash == "" {
		v.report.MissingHashes++
	} else if wal.RecomputeHash(rec) != rec.RecordHash {
		v.report.HashMismatches++
	}
	if rec.RecordHash != "" {
		v.report.LastRecordHash = rec.RecordHash
	}
	if rec.Seq > v.report.MaxSeq {
		v.report.MaxSeq = rec.Seq
	}
	if !v.opts.Legacy {
		v.verifySequence(rec)
	}
	if rec.DecisionID != "" {
		v.report.ActionReceipts++
		if rec.ReceiptSignature == "" {
			v.report.UnsignedReceipts++
		} else {
			v.report.SignedReceipts++
			if v.verify != nil {
				if err := v.verify(rec); err != nil {
					v.report.SignatureMismatches++
					if v.report.FirstSignatureMismatchDecisionID == "" {
						v.report.FirstSignatureMismatchDecisionID = rec.DecisionID
					}
				}
			}
		}
		if receiptHasGap(rec) {
			v.report.ReceiptFieldGaps++
			if v.report.FirstGapDecisionID == "" {
				v.report.FirstGapDecisionID = rec.DecisionID
			}
		}
	}
	if !v.prevSet && rec.PrevHash != "genesis" && v.report.ChainBrokenAt == -1 {
		v.report.ChainBrokenAt = v.index
		v.report.ChainBrokenDecisionID = rec.DecisionID
	}
	if v.prevSet && rec.PrevHash != v.prevHash && v.report.ChainBrokenAt == -1 {
		v.report.ChainBrokenAt = v.index
		v.report.ChainBrokenDecisionID = rec.DecisionID
	}
	if v.hasAnchor && rec.Seq == v.anchorCheckpoint.Seq {
		v.anchorHashSeen = rec.RecordHash
	}
	v.prevHash = rec.RecordHash
	v.prevSet = true
	v.index++
}

func (v *Verifier) verifySequence(rec wal.Record) {
	if rec.Seq == 0 {
		v.report.MissingSeq++
		if v.report.FirstSeqGapDecisionID == "" {
			v.report.FirstSeqGapDecisionID = rec.DecisionID
		}
		return
	}
	if rec.Seq != v.expectedSeq {
		v.report.SeqGaps++
		if v.report.FirstSeqGapDecisionID == "" {
			v.report.FirstSeqGapDecisionID = rec.DecisionID
		}
		v.expectedSeq = rec.Seq + 1
		return
	}
	v.expectedSeq++
}

// AddStream decodes a JSONL WAL reader and feeds each record through Add without ever
// holding more than one record in memory.
func (v *Verifier) AddStream(r io.Reader) error {
	dec := json.NewDecoder(r)
	for {
		var rec wal.Record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		v.Add(rec)
	}
}

// Report finalizes the verdict.
func (v *Verifier) Report() Report {
	report := v.report
	report.TotalRecords = v.index
	if v.hasAnchor {
		switch {
		case v.anchorCheckpoint.Seq > report.MaxSeq:
			report.AnchorMismatches++
			report.Recommendation = fmt.Sprintf("truncation detected: anchored seq=%d, wal max seq=%d", v.anchorCheckpoint.Seq, report.MaxSeq)
		case v.anchorCheckpoint.Seq > 0 && v.anchorHashSeen == "":
			report.AnchorMismatches++
			report.Recommendation = fmt.Sprintf("anchor seq %d was not present in WAL", v.anchorCheckpoint.Seq)
		case v.anchorHashSeen != "" && v.anchorHashSeen != v.anchorCheckpoint.HeadHash:
			report.AnchorMismatches++
			report.Recommendation = fmt.Sprintf("anchor head hash mismatch at seq=%d", v.anchorCheckpoint.Seq)
		}
	}
	report.Verified = report.MissingHashes == 0 &&
		report.HashMismatches == 0 &&
		report.SignatureMismatches == 0 &&
		report.ChainBrokenAt == -1 &&
		report.MissingSeq == 0 &&
		report.SeqGaps == 0 &&
		report.AnchorMismatches == 0 &&
		report.AnchorSignatureMismatches == 0 &&
		report.ReceiptFieldGaps == 0 &&
		(!v.opts.RequireSignatures || report.UnsignedReceipts == 0)
	if !report.Verified {
		if report.Recommendation == "" {
			switch {
			case report.MissingSeq > 0:
				report.Recommendation = fmt.Sprintf("missing sequence at decision_id=%s", report.FirstSeqGapDecisionID)
			case report.SeqGaps > 0:
				report.Recommendation = fmt.Sprintf("sequence gap or reorder at decision_id=%s", report.FirstSeqGapDecisionID)
			case report.ChainBrokenAt != -1:
				report.Recommendation = fmt.Sprintf("prev_hash chain break at decision_id=%s", report.ChainBrokenDecisionID)
			default:
				report.Recommendation = "treat this audit export as untrusted until hash mismatches, signature mismatches, sequence gaps, chain breaks, anchor mismatches, and receipt field gaps are resolved"
			}
		}
	}
	return report
}
