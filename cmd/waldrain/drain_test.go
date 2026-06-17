package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/wal"
)

// TestDrainOffsetReset is a regression test for the critical midnight UTC bug:
// offset accumulated across files instead of resetting at file boundaries,
// causing day-2+ files to silently stop draining after the first batch.
func TestDrainOffsetReset(t *testing.T) {
	walDir := t.TempDir()

	// Create a continuous chain across 2 day-files (just like the real proxy does).
	// Day 1: 250 records, Day 2: 150 records — chain is unbroken across the boundary.
	lastHash := writeChainedWALFile(t, walDir, "wal-2026-05-25.jsonl", 250, "genesis")
	_ = writeChainedWALFile(t, walDir, "wal-2026-05-26.jsonl", 150, lastHash)

	var totalInserted int
	drainer := &mockDrainer{
		walDir: walDir,
		onInsert: func(records []wal.Record) error {
			totalInserted += len(records)
			return nil
		},
	}

	ctx := context.Background()
	// Run enough iterations to drain everything (each drains one batch per file)
	for i := 0; i < 20; i++ {
		if err := drainer.drainOnce(ctx); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	// --- Assert: every record drained ---
	if totalInserted != 400 {
		t.Fatalf("drained %d records, want 400 (250 + 150)", totalInserted)
	}

	// --- Assert: offset is on the correct file ---
	offset, _ := drainer.loadOffset()
	if offset.File != "wal-2026-05-26.jsonl" {
		t.Errorf("offset.File = %q, want wal-2026-05-26.jsonl", offset.File)
	}

	// ByteOffset should equal the file size of day-2 file
	day2Size := fileSize(t, filepath.Join(walDir, "wal-2026-05-26.jsonl"))
	if offset.ByteOffset != day2Size {
		t.Errorf("offset.ByteOffset = %d, want %d (day-2 file size)", offset.ByteOffset, day2Size)
	}
}

// TestDrainOffsetReset_ThreeDays extends the regression test across three files.
func TestDrainOffsetReset_ThreeDays(t *testing.T) {
	walDir := t.TempDir()

	h := writeChainedWALFile(t, walDir, "wal-2026-05-25.jsonl", 350, "genesis")
	h = writeChainedWALFile(t, walDir, "wal-2026-05-26.jsonl", 120, h)
	_ = writeChainedWALFile(t, walDir, "wal-2026-05-27.jsonl", 80, h)

	var totalInserted int
	drainer := &mockDrainer{
		walDir: walDir,
		onInsert: func(records []wal.Record) error {
			totalInserted += len(records)
			return nil
		},
	}

	ctx := context.Background()
	for i := 0; i < 30; i++ {
		if err := drainer.drainOnce(ctx); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	if totalInserted != 550 {
		t.Fatalf("drained %d records, want 550 (350+120+80)", totalInserted)
	}

	offset, _ := drainer.loadOffset()
	if offset.File != "wal-2026-05-27.jsonl" {
		t.Errorf("offset.File = %q, want wal-2026-05-27.jsonl", offset.File)
	}
	day3Size := fileSize(t, filepath.Join(walDir, "wal-2026-05-27.jsonl"))
	if offset.ByteOffset != day3Size {
		t.Errorf("offset.ByteOffset = %d, want %d (day-3 file size)", offset.ByteOffset, day3Size)
	}
}

// TestDrainCrashGapMarker verifies the drainer processes chain restart markers
// without chain violations. Simulates: 10 records, crash gap, restart marker, 5 more.
func TestDrainCrashGapMarker(t *testing.T) {
	walDir := t.TempDir()

	// Write 10 records, then a chain restart marker, then 5 more records.
	// This simulates what the WAL file looks like after a crash + recovery.
	h := writeChainedWALFile(t, walDir, "wal-2026-05-25.jsonl", 10, "genesis")

	// Append a chain restart marker
	path := filepath.Join(walDir, "wal-2026-05-25.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("open for append: %v", err)
	}
	marker := wal.Record{
		Time:         time.Now().UTC(),
		Project:      "_chain",
		Provider:     "_system",
		Model:        "_restart",
		ChainRestart: true,
	}
	wal.Chain(&marker, h)
	markerLine, _ := json.Marshal(marker)
	fmt.Fprintf(f, "%s\n", markerLine)

	// Write 5 more records continuing from the marker
	prevHash := marker.RecordHash
	for i := 0; i < 5; i++ {
		rec := wal.Record{
			Time:         time.Now().UTC(),
			Project:      "test-project",
			Provider:     "openai",
			Model:        "gpt-4o-mini",
			PromptHash:   fmt.Sprintf("post-crash-%d", i),
			InputTokens:  i * 10,
			OutputTokens: i * 5,
			TotalTokens:  i * 15,
			Cost:         float64(i) * 0.001,
			StatusCode:   200,
		}
		wal.Chain(&rec, prevHash)
		prevHash = rec.RecordHash
		line, _ := json.Marshal(rec)
		fmt.Fprintf(f, "%s\n", line)
	}
	f.Close()

	var totalInserted int
	var restartMarkersSeen int
	drainer := &mockDrainer{
		walDir: walDir,
		onInsert: func(records []wal.Record) error {
			for _, rec := range records {
				if rec.ChainRestart {
					restartMarkersSeen++
				}
			}
			totalInserted += len(records)
			return nil
		},
	}

	if err := drainer.drainOnce(context.Background()); err != nil {
		t.Fatalf("drainOnce: %v", err)
	}

	// 10 + 1 marker + 5 = 16 total records
	if totalInserted != 16 {
		t.Fatalf("drained %d records, want 16 (10 + 1 marker + 5)", totalInserted)
	}
	if restartMarkersSeen != 1 {
		t.Errorf("restart markers seen = %d, want 1", restartMarkersSeen)
	}
}

// TestDrainChainVerification ensures the drain worker catches tampered records.
func TestDrainChainVerification(t *testing.T) {
	walDir := t.TempDir()
	writeChainedWALFile(t, walDir, "wal-2026-05-25.jsonl", 10, "genesis")

	// Tamper with a record: overwrite line 5 with a different cost
	tamperWALRecord(t, walDir, "wal-2026-05-25.jsonl", 5)

	drainer := &mockDrainer{
		walDir:   walDir,
		onInsert: func(records []wal.Record) error { return nil },
	}

	err := drainer.drainOnce(context.Background())
	if err == nil {
		t.Fatal("expected chain violation error, got nil")
	}
}

// TestDrainThroughput is a regression test for the throughput ceiling bug:
// Previously drainOnce processed exactly one batch per tick, so at 100 req/s
// with batchSize=100 and pollInterval=5s, the drainer fell permanently behind.
// Now drainOnce loops drainFile until the file is exhausted per tick.
func TestDrainThroughput(t *testing.T) {
	walDir := t.TempDir()

	// 500 records in one file = 5 batches at batchSize=100.
	// A single drainOnce call must drain all 500.
	h := writeChainedWALFile(t, walDir, "wal-2026-05-25.jsonl", 500, "genesis")
	// 200 records in a second file = 2 batches.
	_ = writeChainedWALFile(t, walDir, "wal-2026-05-26.jsonl", 200, h)

	var totalInserted int
	var batchCalls int
	drainer := &mockDrainer{
		walDir: walDir,
		onInsert: func(records []wal.Record) error {
			totalInserted += len(records)
			batchCalls++
			return nil
		},
	}

	// ONE call to drainOnce should drain everything across both files.
	if err := drainer.drainOnce(context.Background()); err != nil {
		t.Fatalf("drainOnce: %v", err)
	}

	if totalInserted != 700 {
		t.Fatalf("drained %d records in one drainOnce, want 700 (500+200)", totalInserted)
	}

	// Should have been 7 batch calls (5 + 2)
	if batchCalls != 7 {
		t.Errorf("batch calls = %d, want 7 (5 batches of 100 + 2 batches of 100)", batchCalls)
	}

	offset, _ := drainer.loadOffset()
	if offset.File != "wal-2026-05-26.jsonl" {
		t.Errorf("offset.File = %q, want wal-2026-05-26.jsonl", offset.File)
	}
	day2Size := fileSize(t, filepath.Join(walDir, "wal-2026-05-26.jsonl"))
	if offset.ByteOffset != day2Size {
		t.Errorf("offset.ByteOffset = %d, want %d", offset.ByteOffset, day2Size)
	}
}

// TestDrainBlankLines verifies that blank lines interspersed in the WAL file
// don't desync the byte offset. The offset must track bytes consumed,
// including blanks.
func TestDrainBlankLines(t *testing.T) {
	walDir := t.TempDir()

	// Write a WAL file with 10 valid records + blank lines between them.
	lastHash := writeChainedWALFileWithBlanks(t, walDir, "wal-2026-05-25.jsonl", 10, "genesis")

	var totalInserted int
	drainer := &mockDrainer{
		walDir: walDir,
		onInsert: func(records []wal.Record) error {
			totalInserted += len(records)
			return nil
		},
	}

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := drainer.drainOnce(ctx); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	if totalInserted != 10 {
		t.Fatalf("drained %d records, want 10", totalInserted)
	}

	// offset.ByteOffset should equal file size
	fsize := fileSize(t, filepath.Join(walDir, "wal-2026-05-25.jsonl"))
	offset, _ := drainer.loadOffset()
	if offset.ByteOffset != fsize {
		t.Errorf("offset.ByteOffset = %d, want %d (file size)", offset.ByteOffset, fsize)
	}

	// Subsequent drains should be no-ops (no double counting)
	beforeCount := totalInserted
	for i := 0; i < 3; i++ {
		if err := drainer.drainOnce(ctx); err != nil {
			t.Fatalf("post-drain iteration %d: %v", i, err)
		}
	}
	if totalInserted != beforeCount {
		t.Errorf("drained %d extra records on re-drain, want 0", totalInserted-beforeCount)
	}

	_ = lastHash
}

// TestDrainMalformedLines verifies that malformed JSON lines are skipped but
// still counted in the byte offset, preventing re-reads.
func TestDrainMalformedLines(t *testing.T) {
	walDir := t.TempDir()

	// Write 10 records with 3 malformed lines interspersed.
	lastHash := writeChainedWALFileWithMalformed(t, walDir, "wal-2026-05-25.jsonl", 10, "genesis")

	var totalInserted int
	drainer := &mockDrainer{
		walDir: walDir,
		onInsert: func(records []wal.Record) error {
			totalInserted += len(records)
			return nil
		},
	}

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := drainer.drainOnce(ctx); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	if totalInserted != 10 {
		t.Fatalf("drained %d records, want 10", totalInserted)
	}

	// offset.ByteOffset should equal file size
	fsize := fileSize(t, filepath.Join(walDir, "wal-2026-05-25.jsonl"))
	offset, _ := drainer.loadOffset()
	if offset.ByteOffset != fsize {
		t.Errorf("offset.ByteOffset = %d, want %d (file size)", offset.ByteOffset, fsize)
	}

	// Subsequent drains must not re-insert anything
	beforeCount := totalInserted
	for i := 0; i < 3; i++ {
		if err := drainer.drainOnce(ctx); err != nil {
			t.Fatalf("post-drain iteration %d: %v", i, err)
		}
	}
	if totalInserted != beforeCount {
		t.Errorf("drained %d extra records on re-drain, want 0", totalInserted-beforeCount)
	}

	_ = lastHash
}

// TestDrainBlankLinesCrossFile verifies byte offset tracking works across
// multiple files with blank lines. Ensures offset resets per file.
func TestDrainBlankLinesCrossFile(t *testing.T) {
	walDir := t.TempDir()

	// Day 1: 10 records + 10 blanks
	h := writeChainedWALFileWithBlanks(t, walDir, "wal-2026-05-25.jsonl", 10, "genesis")
	// Day 2: 5 records + 5 blanks
	_ = writeChainedWALFileWithBlanks(t, walDir, "wal-2026-05-26.jsonl", 5, h)

	var totalInserted int
	drainer := &mockDrainer{
		walDir: walDir,
		onInsert: func(records []wal.Record) error {
			totalInserted += len(records)
			return nil
		},
	}

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := drainer.drainOnce(ctx); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}

	if totalInserted != 15 {
		t.Fatalf("drained %d records, want 15 (10+5)", totalInserted)
	}

	offset, _ := drainer.loadOffset()
	if offset.File != "wal-2026-05-26.jsonl" {
		t.Errorf("offset.File = %q, want wal-2026-05-26.jsonl", offset.File)
	}
	day2Size := fileSize(t, filepath.Join(walDir, "wal-2026-05-26.jsonl"))
	if offset.ByteOffset != day2Size {
		t.Errorf("offset.ByteOffset = %d, want %d (day-2 file size)", offset.ByteOffset, day2Size)
	}
}

// --- helpers ---

// fileSize returns the size of a file in bytes.
func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

// writeChainedWALFile writes count records to a WAL file continuing the chain
// from prevHash. Returns the hash of the last record written.
func writeChainedWALFile(t *testing.T, dir, filename string, count int, prevHash string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", filename, err)
	}
	defer f.Close()

	for i := 0; i < count; i++ {
		rec := wal.Record{
			Time:         time.Now().UTC(),
			Project:      "test-project",
			Provider:     "openai",
			Model:        "gpt-4o-mini",
			PromptHash:   fmt.Sprintf("%s-hash-%d", filename, i),
			InputTokens:  i * 10,
			OutputTokens: i * 5,
			TotalTokens:  i * 15,
			Cost:         float64(i) * 0.001,
			StatusCode:   200,
		}
		wal.Chain(&rec, prevHash)
		prevHash = rec.RecordHash

		line, _ := json.Marshal(rec)
		fmt.Fprintf(f, "%s\n", line)
	}
	return prevHash
}

// writeChainedWALFileWithBlanks writes count records with a blank line after each one.
func writeChainedWALFileWithBlanks(t *testing.T, dir, filename string, count int, prevHash string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", filename, err)
	}
	defer f.Close()

	for i := 0; i < count; i++ {
		rec := wal.Record{
			Time:         time.Now().UTC(),
			Project:      "test-project",
			Provider:     "openai",
			Model:        "gpt-4o-mini",
			PromptHash:   fmt.Sprintf("%s-hash-%d", filename, i),
			InputTokens:  i * 10,
			OutputTokens: i * 5,
			TotalTokens:  i * 15,
			Cost:         float64(i) * 0.001,
			StatusCode:   200,
		}
		wal.Chain(&rec, prevHash)
		prevHash = rec.RecordHash

		line, _ := json.Marshal(rec)
		fmt.Fprintf(f, "%s\n", line)
		fmt.Fprintf(f, "\n") // blank line
	}
	return prevHash
}

// writeChainedWALFileWithMalformed writes count records with malformed JSON lines
// inserted after records 2, 5, and 8 (3 malformed lines total, assuming count >= 10).
func writeChainedWALFileWithMalformed(t *testing.T, dir, filename string, count int, prevHash string) string {
	t.Helper()
	path := filepath.Join(dir, filename)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", filename, err)
	}
	defer f.Close()

	malformedAt := map[int]bool{2: true, 5: true, 8: true}
	for i := 0; i < count; i++ {
		rec := wal.Record{
			Time:         time.Now().UTC(),
			Project:      "test-project",
			Provider:     "openai",
			Model:        "gpt-4o-mini",
			PromptHash:   fmt.Sprintf("%s-hash-%d", filename, i),
			InputTokens:  i * 10,
			OutputTokens: i * 5,
			TotalTokens:  i * 15,
			Cost:         float64(i) * 0.001,
			StatusCode:   200,
		}
		wal.Chain(&rec, prevHash)
		prevHash = rec.RecordHash

		line, _ := json.Marshal(rec)
		fmt.Fprintf(f, "%s\n", line)

		if malformedAt[i] {
			fmt.Fprintf(f, "{\"broken json\n") // malformed line
		}
	}
	return prevHash
}

// tamperWALRecord changes the cost field of record at lineIdx, breaking the chain.
func tamperWALRecord(t *testing.T, dir, filename string, lineIdx int) {
	t.Helper()
	path := filepath.Join(dir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if lineIdx >= len(lines) {
		t.Fatalf("lineIdx %d out of range (file has %d lines)", lineIdx, len(lines))
	}

	var rec wal.Record
	json.Unmarshal([]byte(lines[lineIdx]), &rec)
	rec.Cost = 999.99 // tamper — hash no longer matches
	tampered, _ := json.Marshal(rec)
	lines[lineIdx] = string(tampered)

	out := strings.Join(lines, "\n") + "\n"
	os.WriteFile(path, []byte(out), 0644)
}

// mockDrainer simulates the drain worker without Postgres.
// Mirrors the exact byte offset logic from cmd/waldrain/main.go.
type mockDrainer struct {
	walDir   string
	onInsert func([]wal.Record) error
}

func (d *mockDrainer) drainOnce(ctx context.Context) error {
	offset, err := d.loadOffset()
	if err != nil {
		return err
	}

	files, err := filepath.Glob(filepath.Join(d.walDir, "wal-*.jsonl"))
	if err != nil {
		return err
	}

	for _, file := range files {
		baseName := filepath.Base(file)

		if offset.File != "" && baseName < offset.File {
			continue
		}

		var startByte int64
		if baseName == offset.File {
			startByte = offset.ByteOffset
		}

		// Drain the current file to EOF before moving to the next.
		// Mirrors the inner loop in main.go's drainOnce.
		for {
			batch, bytesConsumed, lastHash, err := d.readBatch(file, startByte)
			if err != nil {
				return err
			}

			if len(batch) == 0 {
				// File fully drained — break to next file
				break
			}

			// Verify chain — mirrors the real drainer exactly
			expectedPrev := offset.LastHash
			if expectedPrev == "" {
				expectedPrev = "genesis"
			}
			if batch[0].PrevHash != expectedPrev {
				return fmt.Errorf("chain violation: expected prev_hash=%s, got %s",
					expectedPrev, batch[0].PrevHash)
			}
			if brokenLink := wal.VerifyChain(batch); brokenLink != -1 {
				return fmt.Errorf("chain violation at index %d", brokenLink)
			}
			for i, rec := range batch {
				if wal.RecomputeHash(rec) != rec.RecordHash {
					return fmt.Errorf("chain violation: record hash mismatch at index %d", i)
				}
			}

			if err := d.onInsert(batch); err != nil {
				return err
			}

			// --- THIS IS THE CODE UNDER TEST (mirrors main.go exactly) ---
			if baseName != offset.File {
				offset.File = baseName
				offset.ByteOffset = startByte + bytesConsumed
			} else {
				offset.ByteOffset += bytesConsumed
			}
			offset.LastHash = lastHash
			startByte = offset.ByteOffset

			if err := d.saveOffset(offset); err != nil {
				return err
			}
		}
	}

	return nil
}

// readBatch mirrors drainFile from main.go: uses file.Seek for O(1) positioning,
// returns bytes consumed (not line count).
func (d *mockDrainer) readBatch(path string, startByte int64) (batch []wal.Record, bytesConsumed int64, lastHash string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, "", err
	}
	defer f.Close()

	if startByte > 0 {
		if _, err := f.Seek(startByte, io.SeekStart); err != nil {
			return nil, 0, "", err
		}
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	// Read batch — track bytes consumed.
	for scanner.Scan() && len(batch) < batchSize {
		line := scanner.Text()
		bytesConsumed += int64(len(line)) + 1 // +1 for newline
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec wal.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			// Skip malformed lines (matches main.go behavior)
			continue
		}
		batch = append(batch, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, "", err
	}
	if len(batch) == 0 {
		return nil, 0, "", nil
	}
	return batch, bytesConsumed, batch[len(batch)-1].RecordHash, nil
}

func (d *mockDrainer) loadOffset() (drainOffset, error) {
	path := filepath.Join(d.walDir, offsetFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return drainOffset{}, nil
	}
	if err != nil {
		return drainOffset{}, err
	}
	var o drainOffset
	if err := json.Unmarshal(data, &o); err != nil {
		return drainOffset{}, err
	}
	return o, nil
}

func (d *mockDrainer) saveOffset(o drainOffset) error {
	data, _ := json.Marshal(o)
	tmp := filepath.Join(d.walDir, offsetFile+".tmp")
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d.walDir, offsetFile))
}
