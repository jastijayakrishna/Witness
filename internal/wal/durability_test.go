package wal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDurability_WriteCloseReopen writes N records, closes, then reads them all back.
// Simulates a clean shutdown recovery scenario.
func TestDurability_WriteCloseReopen(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	n := 500
	for i := 0; i < n; i++ {
		err := w.Write(Record{
			Project:      fmt.Sprintf("proj-%d", i%5),
			Provider:     "openai",
			Model:        "gpt-4o-mini",
			PromptHash:   fmt.Sprintf("hash-%d", i),
			InputTokens:  i * 10,
			OutputTokens: i * 5,
			TotalTokens:  i * 15,
			Cost:         float64(i) * 0.001,
			LatencyMs:    int64(i),
			StatusCode:   200,
			CacheHit:     i%3 == 0,
			Stream:       i%2 == 0,
		})
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	// Close cleanly
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read back everything
	records := readAllRecords(t, dir)
	if len(records) != n {
		t.Fatalf("recovered %d records, want %d", len(records), n)
	}

	// Verify each record's data integrity
	for i, rec := range records {
		if rec.PromptHash != fmt.Sprintf("hash-%d", i) {
			t.Errorf("record %d: prompt_hash = %q, want hash-%d", i, rec.PromptHash, i)
		}
		if rec.InputTokens != i*10 {
			t.Errorf("record %d: input_tokens = %d, want %d", i, rec.InputTokens, i*10)
		}
		if rec.OutputTokens != i*5 {
			t.Errorf("record %d: output_tokens = %d, want %d", i, rec.OutputTokens, i*5)
		}
		if rec.CacheHit != (i%3 == 0) {
			t.Errorf("record %d: cache_hit = %v, want %v", i, rec.CacheHit, i%3 == 0)
		}
		if rec.Stream != (i%2 == 0) {
			t.Errorf("record %d: stream = %v, want %v", i, rec.Stream, i%2 == 0)
		}
	}
}

// TestDurability_HighConcurrency runs many goroutines writing simultaneously
// and verifies zero records are lost.
func TestDurability_HighConcurrency(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	goroutines := 50
	writesPerGoroutine := 100
	expectedTotal := goroutines * writesPerGoroutine
	var errors atomic.Int64

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < writesPerGoroutine; i++ {
				err := w.Write(Record{
					Project:      fmt.Sprintf("goroutine-%d", id),
					Provider:     "openai",
					Model:        "gpt-4o-mini",
					PromptHash:   fmt.Sprintf("g%d-i%d", id, i),
					InputTokens:  id*1000 + i,
					OutputTokens: 1,
					TotalTokens:  id*1000 + i + 1,
					StatusCode:   200,
				})
				if err != nil {
					errors.Add(1)
				}
			}
		}(g)
	}

	wg.Wait()
	w.Close()

	if e := errors.Load(); e > 0 {
		t.Errorf("%d write errors occurred", e)
	}

	records := readAllRecords(t, dir)
	if len(records) != expectedTotal {
		t.Fatalf("recovered %d records, want %d (lost %d)",
			len(records), expectedTotal, expectedTotal-len(records))
	}

	// Verify every record is valid JSON with correct structure
	for i, rec := range records {
		if rec.Project == "" {
			t.Errorf("record %d: empty project", i)
		}
		if rec.StatusCode != 200 {
			t.Errorf("record %d: status_code = %d", i, rec.StatusCode)
		}
		if rec.Time.IsZero() {
			t.Errorf("record %d: zero time", i)
		}
	}
}

// TestDurability_BatchFsyncThreshold verifies that exactly at the 50-record boundary,
// an fsync has occurred (records are durable even without close).
func TestDurability_BatchFsyncThreshold(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Write exactly 50 records (the batch fsync threshold)
	for i := 0; i < 50; i++ {
		w.Write(Record{
			Project:    "batch-test",
			Provider:   "openai",
			Model:      "gpt-4o-mini",
			StatusCode: 200,
		})
	}

	// Records should be fsynced at this point without calling Close
	// Read directly from disk
	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(dir, "wal-"+today+".jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	count := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if scanner.Text() != "" {
			count++
		}
	}
	if count != 50 {
		t.Errorf("expected 50 fsynced records, got %d", count)
	}
}

// TestDurability_AppendAfterReopen verifies that opening a new writer for the
// same directory appends to the existing file (doesn't overwrite).
func TestDurability_AppendAfterReopen(t *testing.T) {
	dir := t.TempDir()

	// First writer: write 10 records
	w1, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter 1: %v", err)
	}
	for i := 0; i < 10; i++ {
		w1.Write(Record{Project: "first", Provider: "openai", Model: "gpt-4o-mini", StatusCode: 200, InputTokens: i})
	}
	w1.Close()

	// Second writer: write 10 more records
	w2, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter 2: %v", err)
	}
	for i := 0; i < 10; i++ {
		w2.Write(Record{Project: "second", Provider: "openai", Model: "gpt-4o-mini", StatusCode: 200, InputTokens: i + 100})
	}
	w2.Close()

	// Should have all 20 records
	records := readAllRecords(t, dir)
	if len(records) != 20 {
		t.Fatalf("expected 20 records, got %d", len(records))
	}

	// First 10 should be "first", last 10 should be "second"
	for i := 0; i < 10; i++ {
		if records[i].Project != "first" {
			t.Errorf("record %d: project = %q, want first", i, records[i].Project)
		}
	}
	for i := 10; i < 20; i++ {
		if records[i].Project != "second" {
			t.Errorf("record %d: project = %q, want second", i, records[i].Project)
		}
	}
}

// TestDurability_JSONLIntegrity verifies every line in the WAL is independently
// parseable as valid JSON (the whole point of JSONL format).
func TestDurability_JSONLIntegrity(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Write records with special characters
	specialStrings := []string{
		`normal project`,
		`project with "quotes"`,
		`project with\nnewline`,
		`project/with/slashes`,
		`project with emoji 🚀`,
		`项目`, // Chinese characters
		``,   // empty string
	}

	for _, s := range specialStrings {
		w.Write(Record{
			Project:    s,
			Provider:   "openai",
			Model:      "gpt-4o-mini",
			PromptHash: s,
			StatusCode: 200,
		})
	}
	w.Close()

	// Every line must be valid JSON
	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(dir, "wal-"+today+".jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	lineNum := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		if !json.Valid([]byte(line)) {
			t.Errorf("line %d is not valid JSON: %s", lineNum, line)
		}
		lineNum++
	}
	if lineNum != len(specialStrings) {
		t.Errorf("expected %d lines, got %d", len(specialStrings), lineNum)
	}
}

// --- helper ---

func readAllRecords(t *testing.T, dir string) []Record {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	var records []Record
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Skip non-WAL files (e.g., wal-chain-head.json, wal-offset.json)
		if !strings.HasPrefix(entry.Name(), "wal-") || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("readfile: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var rec Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("unmarshal: %v\nline: %s", err, line)
			}
			records = append(records, rec)
		}
	}
	return records
}
