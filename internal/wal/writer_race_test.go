package wal_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/receiptverify"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func TestWriter_ConcurrentWriteSigned(t *testing.T) {
	dir := t.TempDir()
	anchor := wal.NewFileAnchor(filepath.Join(dir, "checkpoints.jsonl"))
	signer := receipts.NewSigner("race-wal", []byte("race-wal-secret"))
	writer, err := wal.NewWriterWithOptions(filepath.Join(dir, "wal"), wal.WriterOptions{
		SyncMode:         wal.SyncModeBatch,
		Anchor:           anchor,
		CheckpointSigner: signer.SignCheckpoint,
		CheckpointEveryN: 11,
	})
	if err != nil {
		t.Fatalf("NewWriterWithOptions: %v", err)
	}

	const goroutines = 24
	const writesPerGoroutine = 40
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < writesPerGoroutine; i++ {
				rec := signedRaceRecord(fmt.Sprintf("dec_%02d_%03d", g, i))
				if err := writer.WriteSigned(rec, signer.SignRecord); err != nil {
					t.Errorf("WriteSigned g=%d i=%d: %v", g, i, err)
					return
				}
				if i%7 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}(g)
	}
	wg.Wait()

	var closeWG sync.WaitGroup
	for i := 0; i < 8; i++ {
		closeWG.Add(1)
		go func() {
			defer closeWG.Done()
			if err := writer.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		}()
	}
	closeWG.Wait()

	records := readRaceWALRecords(t, filepath.Join(dir, "wal"))
	want := goroutines * writesPerGoroutine
	if len(records) != want {
		t.Fatalf("records=%d want %d", len(records), want)
	}
	seen := map[uint64]string{}
	for _, rec := range records {
		if rec.Seq == 0 {
			t.Fatalf("record with missing seq: %+v", rec)
		}
		if previous, ok := seen[rec.Seq]; ok {
			t.Fatalf("duplicate seq=%d previous=%s current=%s", rec.Seq, previous, rec.DecisionID)
		}
		seen[rec.Seq] = rec.DecisionID
	}
	for seq := uint64(1); seq <= uint64(want); seq++ {
		if _, ok := seen[seq]; !ok {
			t.Fatalf("missing seq=%d", seq)
		}
	}

	report := receiptverify.VerifyWithOptions(records, receiptverify.Options{
		ReceiptPublicKeys: map[string]string{signer.KeyID(): signer.PublicKeyBase64()},
		RequireSignatures: true,
		Anchor:            anchor,
	})
	if !report.Verified {
		t.Fatalf("concurrent signed WAL did not verify: %+v", report)
	}
}

func TestAnchorPublish_ConcurrentWithWrites(t *testing.T) {
	dir := t.TempDir()
	anchor := wal.NewFileAnchor(filepath.Join(dir, "checkpoints.jsonl"))
	signer := receipts.NewSigner("race-anchor", []byte("race-anchor-secret"))
	writer, err := wal.NewWriterWithOptions(filepath.Join(dir, "wal"), wal.WriterOptions{
		SyncMode:         wal.SyncModeBatch,
		Anchor:           anchor,
		CheckpointSigner: signer.SignCheckpoint,
		CheckpointEveryN: 3,
	})
	if err != nil {
		t.Fatalf("NewWriterWithOptions: %v", err)
	}

	var wg sync.WaitGroup
	for g := 0; g < 12; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if err := writer.WriteSigned(signedRaceRecord(fmt.Sprintf("dec_anchor_%02d_%03d", g, i)), signer.SignRecord); err != nil {
					t.Errorf("WriteSigned: %v", err)
					return
				}
			}
		}(g)
	}
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				cp, err := signer.SignCheckpoint(wal.Checkpoint{
					Seq:      uint64(g*1000 + i + 1),
					HeadHash: fmt.Sprintf("manual-head-%02d-%03d", g, i),
					Count:    uint64(i + 1),
					SignedAt: time.Now().UTC(),
				})
				if err != nil {
					t.Errorf("SignCheckpoint: %v", err)
					return
				}
				if err := anchor.Publish(context.Background(), cp); err != nil {
					t.Errorf("Publish: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	cp, err := anchor.Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest anchor after concurrent publishes: %v", err)
	}
	pub, err := receipts.ParsePublicKey(signer.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if err := receipts.VerifyCheckpointWithPublicKey(pub, cp); err != nil {
		t.Fatalf("latest checkpoint signature: %v", err)
	}
}

func signedRaceRecord(decisionID string) wal.Record {
	return wal.Record{
		Project:          "race-project",
		Provider:         "_preflight",
		Model:            "preflight",
		StatusCode:       200,
		SessionID:        "race-session",
		DecisionStage:    "preflight",
		DecisionID:       decisionID,
		PolicyVersion:    "race-policy/v1",
		DecisionReason:   "race test decision",
		DecisionEvidence: "race=true",
		Actor:            "agent:race",
		Action:           "deploy.release",
		Target:           "service/race",
		Environment:      "production",
		IntentHash:       "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		EvidenceHashes:   []string{"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		RiskScore:        95,
		Decision:         "block",
	}
}

func readRaceWALRecords(t *testing.T, dir string) []wal.Record {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "wal-*.jsonl"))
	if err != nil {
		t.Fatalf("glob WAL: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("wal files=%v, want one", files)
	}
	f, err := os.Open(files[0])
	if err != nil {
		t.Fatalf("open WAL: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var records []wal.Record
	for scanner.Scan() {
		var rec wal.Record
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("decode WAL line %d: %v", len(records)+1, err)
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan WAL: %v", err)
	}
	return records
}
