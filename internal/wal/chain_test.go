package wal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestChain(t *testing.T) {
	rec := Record{
		Time:         time.Now().UTC(),
		Project:      "test",
		Provider:     "openai",
		Model:        "gpt-4o-mini",
		PromptHash:   "abc123",
		InputTokens:  10,
		OutputTokens: 20,
		TotalTokens:  30,
		Cost:         0.00015,
		LatencyMs:    100,
		StatusCode:   200,
		CacheHit:     false,
		Stream:       false,
	}

	// Chain with genesis
	if err := Chain(&rec, "genesis"); err != nil {
		t.Fatalf("Chain: %v", err)
	}

	if rec.PrevHash != "genesis" {
		t.Errorf("expected prev_hash=genesis, got %s", rec.PrevHash)
	}

	if rec.RecordHash == "" {
		t.Error("record_hash should not be empty")
	}

	if len(rec.RecordHash) != 64 {
		t.Errorf("expected 64-char hex hash, got %d chars", len(rec.RecordHash))
	}

	// Chain a second record
	rec2 := rec
	rec2.InputTokens = 15
	firstHash := rec.RecordHash

	if err := Chain(&rec2, firstHash); err != nil {
		t.Fatalf("Chain rec2: %v", err)
	}

	if rec2.PrevHash != firstHash {
		t.Errorf("expected prev_hash=%s, got %s", firstHash, rec2.PrevHash)
	}

	if rec2.RecordHash == firstHash {
		t.Error("second record should have different hash")
	}
}

func TestChainDeterministic(t *testing.T) {
	rec1 := Record{
		Time:         time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Project:      "test",
		Provider:     "openai",
		Model:        "gpt-4o-mini",
		PromptHash:   "abc123",
		InputTokens:  10,
		OutputTokens: 20,
		TotalTokens:  30,
		Cost:         0.00015,
		LatencyMs:    100,
		StatusCode:   200,
	}

	rec2 := rec1

	if err := Chain(&rec1, "genesis"); err != nil {
		t.Fatalf("Chain rec1: %v", err)
	}
	if err := Chain(&rec2, "genesis"); err != nil {
		t.Fatalf("Chain rec2: %v", err)
	}

	if rec1.RecordHash != rec2.RecordHash {
		t.Error("identical records should produce identical hashes")
	}
}

func TestVerifyChain(t *testing.T) {
	records := make([]Record, 5)
	prevHash := "genesis"

	for i := range records {
		records[i] = Record{
			Time:         time.Now().UTC(),
			Project:      "test",
			Provider:     "openai",
			Model:        "gpt-4o-mini",
			InputTokens:  i * 10,
			OutputTokens: i * 20,
		}
		if err := Chain(&records[i], prevHash); err != nil {
			t.Fatalf("Chain %d: %v", i, err)
		}
		prevHash = records[i].RecordHash
	}

	// Valid chain
	if idx := VerifyChain(records); idx != -1 {
		t.Errorf("expected valid chain, got broken link at %d", idx)
	}

	// Break the chain
	records[2].PrevHash = "invalid"
	if idx := VerifyChain(records); idx != 2 {
		t.Errorf("expected broken link at 2, got %d", idx)
	}
}

func TestRecomputeHash(t *testing.T) {
	rec := Record{
		Time:         time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
		Project:      "test",
		Provider:     "openai",
		Model:        "gpt-4o-mini",
		PromptHash:   "abc123",
		InputTokens:  10,
		OutputTokens: 20,
		TotalTokens:  30,
		Cost:         0.00015,
	}

	if err := Chain(&rec, "genesis"); err != nil {
		t.Fatalf("Chain: %v", err)
	}
	originalHash := rec.RecordHash

	// Recompute should match
	recomputed := RecomputeHash(rec)
	if recomputed != originalHash {
		t.Errorf("recomputed hash %s != original %s", recomputed, originalHash)
	}

	// Tampering should be detected
	rec.Cost = 999.99
	recomputed = RecomputeHash(rec)
	if recomputed == originalHash {
		t.Error("tampered record should produce different hash")
	}
}

func TestChainHeadSaveLoad(t *testing.T) {
	tmpDir := t.TempDir()

	hash1 := "abc123def456"

	// Save
	if err := saveChainHead(tmpDir, hash1); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// Load
	loaded, err := loadChainHead(tmpDir)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if loaded != hash1 {
		t.Errorf("expected %s, got %s", hash1, loaded)
	}

	// Overwrite
	hash2 := "xyz789"
	if err := saveChainHead(tmpDir, hash2); err != nil {
		t.Fatalf("save2 failed: %v", err)
	}

	loaded, err = loadChainHead(tmpDir)
	if err != nil {
		t.Fatalf("load2 failed: %v", err)
	}

	if loaded != hash2 {
		t.Errorf("expected %s, got %s", hash2, loaded)
	}
}

func TestChainHeadLoadGenesis(t *testing.T) {
	tmpDir := t.TempDir()

	// No file exists - should return genesis
	loaded, err := loadChainHead(tmpDir)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if loaded != "genesis" {
		t.Errorf("expected genesis, got %s", loaded)
	}
}

func TestChainHeadAtomicWrite(t *testing.T) {
	tmpDir := t.TempDir()

	// Save
	if err := saveChainHead(tmpDir, "hash1"); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// Verify no temp file remains
	tmpFile := filepath.Join(tmpDir, chainHeadFile+".tmp")
	if _, err := os.Stat(tmpFile); !os.IsNotExist(err) {
		t.Error("temp file should not exist after save")
	}

	// Verify final file exists
	finalFile := filepath.Join(tmpDir, chainHeadFile)
	if _, err := os.Stat(finalFile); err != nil {
		t.Errorf("final file should exist: %v", err)
	}
}

func TestLastRecordHashOnDisk_NoFiles(t *testing.T) {
	dir := t.TempDir()
	hash, err := LastRecordHashOnDisk(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != "" {
		t.Errorf("expected empty hash for empty dir, got %q", hash)
	}
}

func TestLastRecordHashOnDisk_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "wal-2026-05-25.jsonl"), []byte(""), 0644)
	hash, err := LastRecordHashOnDisk(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != "" {
		t.Errorf("expected empty hash for empty file, got %q", hash)
	}
}

func TestLastRecordHashOnDisk_ReturnsLastRecord(t *testing.T) {
	dir := t.TempDir()

	// Write 5 chained records
	prevHash := "genesis"
	var lastHash string
	f, _ := os.Create(filepath.Join(dir, "wal-2026-05-25.jsonl"))
	for i := 0; i < 5; i++ {
		rec := Record{
			Time:        time.Now().UTC(),
			Project:     "test",
			Provider:    "openai",
			Model:       "gpt-4o-mini",
			InputTokens: i,
			StatusCode:  200,
		}
		if err := Chain(&rec, prevHash); err != nil {
			t.Fatalf("Chain %d: %v", i, err)
		}
		prevHash = rec.RecordHash
		lastHash = rec.RecordHash
		line, _ := json.Marshal(rec)
		fmt.Fprintf(f, "%s\n", line)
	}
	f.Close()

	hash, err := LastRecordHashOnDisk(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != lastHash {
		t.Errorf("expected %s, got %s", lastHash, hash)
	}
}

func TestLastRecordHashOnDisk_PicksLatestFile(t *testing.T) {
	dir := t.TempDir()

	// Day 1 file
	rec1 := Record{Time: time.Now().UTC(), Project: "test", StatusCode: 200}
	if err := Chain(&rec1, "genesis"); err != nil {
		t.Fatalf("Chain rec1: %v", err)
	}
	f1, _ := os.Create(filepath.Join(dir, "wal-2026-05-25.jsonl"))
	line1, _ := json.Marshal(rec1)
	fmt.Fprintf(f1, "%s\n", line1)
	f1.Close()

	// Day 2 file (this should be picked)
	rec2 := Record{Time: time.Now().UTC(), Project: "test", StatusCode: 200}
	if err := Chain(&rec2, rec1.RecordHash); err != nil {
		t.Fatalf("Chain rec2: %v", err)
	}
	f2, _ := os.Create(filepath.Join(dir, "wal-2026-05-26.jsonl"))
	line2, _ := json.Marshal(rec2)
	fmt.Fprintf(f2, "%s\n", line2)
	f2.Close()

	hash, err := LastRecordHashOnDisk(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != rec2.RecordHash {
		t.Errorf("expected day-2 hash %s, got %s", rec2.RecordHash, hash)
	}
}

func TestLastRecordHashOnDisk_SkipsMalformedTrailingLines(t *testing.T) {
	dir := t.TempDir()

	rec := Record{Time: time.Now().UTC(), Project: "test", StatusCode: 200}
	if err := Chain(&rec, "genesis"); err != nil {
		t.Fatalf("Chain: %v", err)
	}
	f, _ := os.Create(filepath.Join(dir, "wal-2026-05-25.jsonl"))
	line, _ := json.Marshal(rec)
	fmt.Fprintf(f, "%s\n", line)
	fmt.Fprintf(f, "{\"broken json\n")
	fmt.Fprintf(f, "\n")
	f.Close()

	hash, err := LastRecordHashOnDisk(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash != rec.RecordHash {
		t.Errorf("expected %s, got %s", rec.RecordHash, hash)
	}
}

// TestCrashGapRecovery simulates the crash scenario:
// 1. Write 60 records (fsync at 50, chain head saved at 50)
// 2. Manually revert chain head to record 50 (simulating crash)
// 3. Create new writer — should detect gap and write restart marker on first Write
// 4. Verify chain is unbroken through the marker
func TestCrashGapRecovery(t *testing.T) {
	dir := t.TempDir()

	// Write 60 records and close normally
	w1, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	var hash50 string
	for i := 0; i < 60; i++ {
		err := w1.Write(Record{
			Project:    "test",
			Provider:   "openai",
			Model:      "gpt-4o-mini",
			StatusCode: 200,
		})
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
		if i == 49 {
			// Capture hash at record 50 (after fsync boundary)
			w1.mu.Lock()
			hash50 = w1.lastHash
			w1.mu.Unlock()
		}
	}
	w1.Close()

	// Simulate crash: overwrite chain head with the hash at record 50.
	// On disk: 60 records. Chain head file: hash of record 50.
	if err := saveChainHead(dir, hash50); err != nil {
		t.Fatalf("save stale chain head: %v", err)
	}

	// Verify crash gap is detectable
	diskHash, _ := LastRecordHashOnDisk(dir)
	if diskHash == hash50 {
		t.Fatal("disk hash should differ from stale chain head")
	}

	// Create new writer — should detect gap
	w2, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter after crash: %v", err)
	}

	// Write one record to trigger the restart marker
	err = w2.Write(Record{
		Project:    "test",
		Provider:   "openai",
		Model:      "gpt-4o-mini",
		StatusCode: 200,
	})
	if err != nil {
		t.Fatalf("Write after crash: %v", err)
	}
	w2.Close()

	// Read all records and verify the chain is unbroken
	records := readAllRecords(t, dir)

	// Should be 60 (original) + 1 (restart marker) + 1 (new record) = 62
	if len(records) != 62 {
		t.Fatalf("expected 62 records, got %d", len(records))
	}

	// Record 60 (index 60) should be the chain restart marker
	if !records[60].ChainRestart {
		t.Error("record 60 should be a chain restart marker")
	}
	if records[60].Project != "_chain" {
		t.Errorf("marker project = %q, want _chain", records[60].Project)
	}

	// Verify full chain integrity
	if idx := VerifyChain(records); idx != -1 {
		t.Errorf("chain broken at index %d", idx)
	}

	// Verify every hash recomputes correctly
	for i, rec := range records {
		if RecomputeHash(rec) != rec.RecordHash {
			t.Errorf("hash mismatch at index %d", i)
		}
	}
}

// TestCrashGapRecovery_NoGap verifies no marker is written when chain head matches disk.
func TestCrashGapRecovery_NoGap(t *testing.T) {
	dir := t.TempDir()

	// Write 10 records and close normally (chain head saved at close)
	w1, _ := NewWriter(dir, "batch")
	for i := 0; i < 10; i++ {
		w1.Write(Record{Project: "test", Provider: "openai", Model: "gpt-4o-mini", StatusCode: 200})
	}
	w1.Close()

	// Create new writer — no crash gap
	w2, _ := NewWriter(dir, "batch")
	w2.Write(Record{Project: "test", Provider: "openai", Model: "gpt-4o-mini", StatusCode: 200})
	w2.Close()

	records := readAllRecords(t, dir)
	// Should be 11 records, no restart marker
	if len(records) != 11 {
		t.Fatalf("expected 11 records, got %d", len(records))
	}
	for i, rec := range records {
		if rec.ChainRestart {
			t.Errorf("unexpected chain restart marker at index %d", i)
		}
	}
	if idx := VerifyChain(records); idx != -1 {
		t.Errorf("chain broken at index %d", idx)
	}
}

func BenchmarkChain(b *testing.B) {
	rec := Record{
		Time:         time.Now().UTC(),
		Project:      "test",
		Provider:     "openai",
		Model:        "gpt-4o-mini",
		InputTokens:  10,
		OutputTokens: 20,
	}
	prevHash := "genesis"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Chain(&rec, prevHash)
		prevHash = rec.RecordHash
	}
}

func BenchmarkVerifyChain(b *testing.B) {
	// Create a chain of 100 records
	records := make([]Record, 100)
	prevHash := "genesis"
	for i := range records {
		records[i] = Record{
			Time:         time.Now().UTC(),
			Project:      "test",
			InputTokens:  i,
			OutputTokens: i * 2,
		}
		_ = Chain(&records[i], prevHash)
		prevHash = records[i].RecordHash
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyChain(records)
	}
}
