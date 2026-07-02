package receiptverify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func init() {
	log.Logger = zerolog.Nop()
}

type goldenWALFixture struct {
	Records    []wal.Record
	Anchor     *wal.FileAnchor
	Signer     *receipts.LocalSecretSigner
	PublicKeys map[string]string
}

func TestAttackMatrix(t *testing.T) {
	signedFieldMutators := []struct {
		name   string
		mutate func(*wal.Record)
	}{
		{name: "decision", mutate: func(rec *wal.Record) { rec.Decision = "require_approval" }},
		{name: "risk_score", mutate: func(rec *wal.Record) { rec.RiskScore++ }},
		{name: "target", mutate: func(rec *wal.Record) { rec.Target += "_tampered" }},
		{name: "action", mutate: func(rec *wal.Record) { rec.Action = "terraform.apply" }},
		{name: "approvers", mutate: func(rec *wal.Record) { rec.RequiredApprovers = append(rec.RequiredApprovers, "attacker") }},
		{name: "evidence_hashes", mutate: func(rec *wal.Record) {
			rec.EvidenceHashes = []string{"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
		}},
		{name: "seq", mutate: func(rec *wal.Record) { rec.Seq++ }},
		{name: "prev_hash", mutate: func(rec *wal.Record) { rec.PrevHash = "attacker-prev-hash" }},
	}

	type attackCase struct {
		name       string
		mutate     func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor)
		wantReason string
		assert     func(t *testing.T, report Report)
	}
	var attacks []attackCase
	attacks = append(attacks,
		attackCase{
			name: "drop_middle_record",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				return []wal.Record{fx.Records[0], fx.Records[2]}, nil
			},
			wantReason: "sequence gap or reorder at decision_id=",
			assert: func(t *testing.T, report Report) {
				if report.SeqGaps == 0 {
					t.Fatalf("SeqGaps=0, report=%+v", report)
				}
			},
		},
		attackCase{
			name: "drop_first_record_non_genesis_head",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				return append([]wal.Record(nil), fx.Records[1:]...), nil
			},
			wantReason: "sequence gap or reorder at decision_id=",
			assert: func(t *testing.T, report Report) {
				if report.SeqGaps == 0 && report.MissingSeq == 0 && report.ChainBrokenAt == -1 {
					t.Fatalf("drop-first was not attributed to seq/chain failure: %+v", report)
				}
			},
		},
		attackCase{
			name: "reorder_two_records",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				return []wal.Record{fx.Records[0], fx.Records[2], fx.Records[1]}, nil
			},
			wantReason: "sequence gap or reorder at decision_id=",
			assert: func(t *testing.T, report Report) {
				if report.SeqGaps == 0 {
					t.Fatalf("SeqGaps=0, report=%+v", report)
				}
			},
		},
		attackCase{
			name: "truncate_tail_with_anchor",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				return append([]wal.Record(nil), fx.Records[:len(fx.Records)-1]...), fx.Anchor
			},
			wantReason: "truncation detected",
			assert: func(t *testing.T, report Report) {
				if report.AnchorMismatches == 0 {
					t.Fatalf("AnchorMismatches=0, report=%+v", report)
				}
			},
		},
		attackCase{
			name: "splice_record_from_another_run",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				other := buildActualSignedAnchoredWAL(t, "splice_a", "splice_b", "splice_c")
				out := append([]wal.Record(nil), fx.Records...)
				out[1] = other.Records[1]
				return out, nil
			},
			wantReason: "prev_hash chain break at decision_id=",
			assert: func(t *testing.T, report Report) {
				if report.ChainBrokenAt == -1 && report.SeqGaps == 0 {
					t.Fatalf("splice was not attributed to chain/seq failure: %+v", report)
				}
			},
		},
		attackCase{
			name: "duplicate_record_replay",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				out := append([]wal.Record(nil), fx.Records[:2]...)
				out = append(out, fx.Records[1])
				out = append(out, fx.Records[2])
				return out, nil
			},
			wantReason: "sequence gap or reorder at decision_id=",
			assert: func(t *testing.T, report Report) {
				if report.SeqGaps == 0 {
					t.Fatalf("SeqGaps=0, report=%+v", report)
				}
			},
		},
		attackCase{
			name: "reattribute_to_unknown_key_id",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				out := append([]wal.Record(nil), fx.Records...)
				i := len(out) - 1
				out[i].ReceiptKeyID = "unknown-attacker-key"
				out[i].RecordHash = wal.RecomputeHash(out[i])
				return out, nil
			},
			wantReason: "signature mismatches",
			assert: func(t *testing.T, report Report) {
				if report.SignatureMismatches == 0 {
					t.Fatalf("SignatureMismatches=0, report=%+v", report)
				}
			},
		},
		attackCase{
			name: "tamper_anchor_head_hash",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				return fx.Records, tamperedAnchor(t, fx.Anchor, func(cp *wal.Checkpoint) { cp.HeadHash = "attacker-head" })
			},
			wantReason: "anchor head hash mismatch",
			assert:     assertAnchorTamperDetected,
		},
		attackCase{
			name: "tamper_anchor_seq",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				return fx.Records, tamperedAnchor(t, fx.Anchor, func(cp *wal.Checkpoint) { cp.Seq++ })
			},
			wantReason: "truncation detected",
			assert:     assertAnchorTamperDetected,
		},
		attackCase{
			name: "tamper_anchor_count",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				return fx.Records, tamperedAnchor(t, fx.Anchor, func(cp *wal.Checkpoint) { cp.Count++ })
			},
			wantReason: "anchor signature mismatch",
			assert:     assertAnchorTamperDetected,
		},
		attackCase{
			name: "unsigned_block_receipt_require_signatures",
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				out := append([]wal.Record(nil), fx.Records...)
				i := len(out) - 1
				out[i].Decision = "block"
				out[i].RiskScore = 95
				out[i].ReceiptSignature = ""
				out[i].ReceiptKeyID = ""
				out[i].RecordHash = wal.RecomputeHash(out[i])
				return out, nil
			},
			wantReason: "untrusted",
			assert: func(t *testing.T, report Report) {
				if report.UnsignedReceipts == 0 {
					t.Fatalf("UnsignedReceipts=0, report=%+v", report)
				}
			},
		},
	)
	for _, signedField := range signedFieldMutators {
		sf := signedField
		attacks = append(attacks, attackCase{
			name: "edit_signed_field_" + sf.name,
			mutate: func(t *testing.T, fx goldenWALFixture) ([]wal.Record, wal.Anchor) {
				out := append([]wal.Record(nil), fx.Records...)
				i := len(out) - 1
				sf.mutate(&out[i])
				switch sf.name {
				case "seq", "prev_hash":
					out[i].RecordHash = wal.RecomputeHash(out[i])
				default:
					if err := wal.Chain(&out[i], out[i-1].RecordHash, out[i].Seq); err != nil {
						t.Fatalf("recompute signed-field mutation: %v", err)
					}
				}
				return out, nil
			},
			wantReason: signedFieldReason(sf.name),
			assert: func(t *testing.T, report Report) {
				if report.SignatureMismatches == 0 {
					t.Fatalf("SignatureMismatches=0 after editing %s: %+v", sf.name, report)
				}
			},
		})
	}

	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			fx := buildActualSignedAnchoredWAL(t, "dec_allow_1", "dec_block", "dec_allow_2")
			records, anchor := attack.mutate(t, fx)
			report := VerifyWithOptions(records, Options{
				ReceiptPublicKeys: fx.PublicKeys,
				RequireSignatures: true,
				Anchor:            anchor,
			})
			if report.Verified {
				t.Fatalf("attack verified=true: %+v", report)
			}
			if attack.wantReason != "" && !strings.Contains(report.Recommendation, attack.wantReason) {
				t.Fatalf("recommendation=%q does not contain %q; report=%+v", report.Recommendation, attack.wantReason, report)
			}
			attack.assert(t, report)
		})
	}

	t.Run("torn_partial_last_line", func(t *testing.T) {
		fx := buildActualSignedAnchoredWAL(t, "dec_allow_1", "dec_block", "dec_allow_2")
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		for _, rec := range fx.Records {
			if err := enc.Encode(rec); err != nil {
				t.Fatalf("encode record: %v", err)
			}
		}
		buf.WriteString(`{"seq":4,"decision_id":"torn"`)
		v, err := NewVerifier(Options{ReceiptPublicKeys: fx.PublicKeys, RequireSignatures: true})
		if err != nil {
			t.Fatalf("new verifier: %v", err)
		}
		err = v.AddStream(&buf)
		if err == nil && v.Report().Verified {
			t.Fatalf("torn stream produced verified=true")
		}
		if err == nil {
			t.Fatalf("torn stream decoded without error; report=%+v", v.Report())
		}
	})
}

func signedFieldReason(name string) string {
	switch name {
	case "seq":
		return "sequence gap or reorder at decision_id="
	case "prev_hash":
		return "prev_hash chain break at decision_id="
	default:
		return "signature mismatches"
	}
}

func TestKnownLimitation_TailTruncationWithoutAnchor(t *testing.T) {
	fx := buildActualSignedAnchoredWAL(t, "dec_allow_1", "dec_block", "dec_allow_2")
	truncated := append([]wal.Record(nil), fx.Records[:len(fx.Records)-1]...)

	report := VerifyWithOptions(truncated, Options{
		ReceiptPublicKeys: fx.PublicKeys,
		RequireSignatures: true,
	})
	if !report.Verified {
		t.Fatalf("tail truncation without an external anchor is the documented limitation; got %+v", report)
	}
}

func TestPropertyRandomValidChainsVerify(t *testing.T) {
	prop := func(seed uint8) bool {
		count := int(seed%8) + 1
		ids := make([]string, count)
		for i := range ids {
			ids[i] = fmt.Sprintf("prop_%02x_%02d", seed, i+1)
		}
		fx := buildActualSignedAnchoredWAL(t, ids...)
		report := VerifyWithOptions(fx.Records, Options{
			ReceiptPublicKeys: fx.PublicKeys,
			RequireSignatures: true,
			Anchor:            fx.Anchor,
		})
		return report.Verified
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 32, Rand: rand.New(rand.NewSource(20260702))}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertySingleSignedFieldMutationFailsVerify(t *testing.T) {
	mutators := []func([]wal.Record) []wal.Record{
		func(in []wal.Record) []wal.Record {
			out := append([]wal.Record(nil), in...)
			i := len(out) - 1
			out[i].Decision = "require_approval"
			_ = wal.Chain(&out[i], out[i-1].RecordHash, out[i].Seq)
			return out
		},
		func(in []wal.Record) []wal.Record {
			out := append([]wal.Record(nil), in...)
			i := len(out) - 1
			out[i].RiskScore++
			_ = wal.Chain(&out[i], out[i-1].RecordHash, out[i].Seq)
			return out
		},
		func(in []wal.Record) []wal.Record {
			out := append([]wal.Record(nil), in...)
			i := len(out) - 1
			out[i].Target += "_tampered"
			_ = wal.Chain(&out[i], out[i-1].RecordHash, out[i].Seq)
			return out
		},
		func(in []wal.Record) []wal.Record {
			out := append([]wal.Record(nil), in...)
			i := len(out) - 1
			out[i].EvidenceHashes = append(out[i].EvidenceHashes, "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
			_ = wal.Chain(&out[i], out[i-1].RecordHash, out[i].Seq)
			return out
		},
		func(in []wal.Record) []wal.Record {
			out := append([]wal.Record(nil), in...)
			i := len(out) - 1
			out[i].Seq++
			out[i].RecordHash = wal.RecomputeHash(out[i])
			return out
		},
	}
	prop := func(seed uint8) bool {
		fx := buildActualSignedAnchoredWAL(t, "prop_mut_1", "prop_mut_2", "prop_mut_3")
		mutate := mutators[int(seed)%len(mutators)]
		report := VerifyWithOptions(mutate(fx.Records), Options{
			ReceiptPublicKeys: fx.PublicKeys,
			RequireSignatures: true,
		})
		return !report.Verified && report.SignatureMismatches > 0
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 64, Rand: rand.New(rand.NewSource(20260703))}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyStreamingReportMatchesSliceReport(t *testing.T) {
	prop := func(seed uint8) bool {
		fx := buildActualSignedAnchoredWAL(t, "prop_stream_1", "prop_stream_2", "prop_stream_3")
		records := append([]wal.Record(nil), fx.Records...)
		switch seed % 4 {
		case 1:
			records = []wal.Record{records[0], records[2]}
		case 2:
			records = []wal.Record{records[1], records[0], records[2]}
		case 3:
			records = append(records, records[1])
		}
		opts := Options{ReceiptPublicKeys: fx.PublicKeys, RequireSignatures: true}
		slice := VerifyWithOptions(records, opts)
		stream, err := verifyViaStream(records, opts)
		return err == nil && reflect.DeepEqual(slice, stream)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 64, Rand: rand.New(rand.NewSource(20260704))}); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyVerifierIdempotence(t *testing.T) {
	prop := func(seed uint8) bool {
		fx := buildActualSignedAnchoredWAL(t, "prop_idem_1", "prop_idem_2", "prop_idem_3")
		records := append([]wal.Record(nil), fx.Records...)
		if seed%2 == 1 {
			records = []wal.Record{records[0], records[2]}
		}
		opts := Options{ReceiptPublicKeys: fx.PublicKeys, RequireSignatures: true}
		first := VerifyWithOptions(records, opts)
		second := VerifyWithOptions(records, opts)
		return reflect.DeepEqual(first, second)
	}
	if err := quick.Check(prop, &quick.Config{MaxCount: 64, Rand: rand.New(rand.NewSource(20260705))}); err != nil {
		t.Fatal(err)
	}
}

func assertAnchorTamperDetected(t *testing.T, report Report) {
	t.Helper()
	if report.AnchorSignatureMismatches == 0 && report.AnchorMismatches == 0 {
		t.Fatalf("anchor tamper was not detected: %+v", report)
	}
}

func buildActualSignedAnchoredWAL(t *testing.T, decisionIDs ...string) goldenWALFixture {
	t.Helper()
	if len(decisionIDs) == 0 {
		decisionIDs = []string{"dec_1"}
	}
	dir := t.TempDir()
	walDir := filepath.Join(dir, "wal")
	anchorPath := filepath.Join(dir, "checkpoints.jsonl")
	anchor := wal.NewFileAnchor(anchorPath)
	signer := receipts.NewSigner("threat-test", []byte("receipt-threat-model-secret"))
	writer, err := wal.NewWriterWithOptions(walDir, wal.WriterOptions{
		SyncMode:         wal.SyncModeSync,
		Anchor:           anchor,
		CheckpointSigner: signer.SignCheckpoint,
		CheckpointEveryN: 1,
	})
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	for i, id := range decisionIDs {
		rec := preflightReceiptRecord(id, "")
		rec.Decision = []string{"allow", "block", "allow"}[i%3]
		if rec.Decision == "allow" {
			rec.RiskScore = 10
			rec.DecisionReason = "allowed engineering action"
		}
		if err := writer.WriteSigned(rec, signer.SignRecord); err != nil {
			t.Fatalf("write signed %s: %v", id, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl"))
	if err != nil {
		t.Fatalf("glob wal: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("wal files=%v, want exactly one", files)
	}
	f, err := os.Open(files[0])
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	records, readErr := readJSONLRecords(f)
	closeErr := f.Close()
	if readErr != nil {
		t.Fatalf("read wal: %v", readErr)
	}
	if closeErr != nil {
		t.Fatalf("close wal: %v", closeErr)
	}
	fx := goldenWALFixture{
		Records: records,
		Anchor:  anchor,
		Signer:  signer,
		PublicKeys: map[string]string{
			signer.KeyID(): signer.PublicKeyBase64(),
		},
	}
	report := VerifyWithOptions(fx.Records, Options{
		ReceiptPublicKeys: fx.PublicKeys,
		RequireSignatures: true,
		Anchor:            fx.Anchor,
	})
	if !report.Verified {
		t.Fatalf("golden fixture did not verify: %+v", report)
	}
	return fx
}

func tamperedAnchor(t *testing.T, anchor *wal.FileAnchor, mutate func(*wal.Checkpoint)) wal.Anchor {
	t.Helper()
	cp, err := anchor.Latest(context.Background())
	if err != nil {
		t.Fatalf("latest anchor: %v", err)
	}
	mutate(&cp)
	path := filepath.Join(t.TempDir(), "tampered-checkpoints.jsonl")
	data, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal tampered checkpoint: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write tampered checkpoint: %v", err)
	}
	return wal.NewFileAnchor(path)
}

func verifyViaStream(records []wal.Record, opts Options) (Report, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return Report{}, err
		}
	}
	v, err := NewVerifier(opts)
	if err != nil {
		return Report{}, err
	}
	if err := v.AddStream(&buf); err != nil {
		return Report{}, err
	}
	return v.Report(), nil
}
