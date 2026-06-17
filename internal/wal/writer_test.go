package wal

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

func TestWriter_SingleWrite(t *testing.T) {
	dir := tempDir(t)
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	err = w.Write(Record{
		Project:      "test-project",
		Provider:     "openai",
		Model:        "gpt-4o-mini",
		PromptHash:   "abc123",
		InputTokens:  10,
		OutputTokens: 5,
		TotalTokens:  15,
		Cost:         0.000045,
		LatencyMs:    150,
		StatusCode:   200,
		CacheHit:     false,
		Stream:       false,
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	w.Close()

	// Verify the file exists and contains valid JSONL
	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(dir, "wal-"+today+".jsonl")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read wal file: %v", err)
	}

	var rec Record
	if err := json.Unmarshal(data[:len(data)-1], &rec); err != nil { // -1 for trailing newline
		t.Fatalf("unmarshal record: %v", err)
	}

	if rec.Project != "test-project" {
		t.Errorf("project = %q, want %q", rec.Project, "test-project")
	}
	if rec.Provider != "openai" {
		t.Errorf("provider = %q, want %q", rec.Provider, "openai")
	}
	if rec.Model != "gpt-4o-mini" {
		t.Errorf("model = %q, want %q", rec.Model, "gpt-4o-mini")
	}
	if rec.InputTokens != 10 {
		t.Errorf("input_tokens = %d, want 10", rec.InputTokens)
	}
	if rec.OutputTokens != 5 {
		t.Errorf("output_tokens = %d, want 5", rec.OutputTokens)
	}
	if rec.Cost != 0.000045 {
		t.Errorf("cost = %f, want 0.000045", rec.Cost)
	}
	if rec.Time.IsZero() {
		t.Error("time should be set automatically")
	}
}

func TestWriter_MultipleWrites_JSONL(t *testing.T) {
	dir := tempDir(t)
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	n := 100
	for i := 0; i < n; i++ {
		err := w.Write(Record{
			Project:     "proj",
			Provider:    "openai",
			Model:       "gpt-4o-mini",
			StatusCode:  200,
			InputTokens: i,
		})
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	w.Close()

	// Count lines — should be exactly n
	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(dir, "wal-"+today+".jsonl")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line %d: invalid JSON: %v\nline: %s", count, err, line)
		}
		if rec.InputTokens != count {
			t.Errorf("line %d: input_tokens = %d, want %d", count, rec.InputTokens, count)
		}
		count++
	}
	if count != n {
		t.Errorf("line count = %d, want %d", count, n)
	}
}

func TestWriter_ConcurrentWrites(t *testing.T) {
	dir := tempDir(t)
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	goroutines := 10
	writesPerGoroutine := 50
	total := goroutines * writesPerGoroutine

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < writesPerGoroutine; i++ {
				err := w.Write(Record{
					Project:    "concurrent",
					Provider:   "openai",
					Model:      "gpt-4o-mini",
					StatusCode: 200,
				})
				if err != nil {
					t.Errorf("goroutine %d write %d: %v", id, i, err)
				}
			}
		}(g)
	}

	wg.Wait()
	w.Close()

	// Count lines — should be exactly total
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
	if count != total {
		t.Errorf("line count = %d, want %d (concurrent writes lost data)", count, total)
	}
}

func TestWriter_FileNaming(t *testing.T) {
	dir := tempDir(t)
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	w.Write(Record{Project: "test", Provider: "openai", Model: "gpt-4o-mini", StatusCode: 200})
	w.Close()

	today := time.Now().UTC().Format("2006-01-02")
	expected := filepath.Join(dir, "wal-"+today+".jsonl")
	if _, err := os.Stat(expected); os.IsNotExist(err) {
		t.Errorf("expected WAL file %s to exist", expected)
	}
}

func TestWriter_CloseFsyncs(t *testing.T) {
	dir := tempDir(t)
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	// Write fewer than 50 records (below batch fsync threshold)
	for i := 0; i < 5; i++ {
		w.Write(Record{Project: "test", Provider: "openai", Model: "gpt-4o-mini", StatusCode: 200})
	}

	// Close should fsync
	w.Close()

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
	if count != 5 {
		t.Errorf("expected 5 records after close, got %d", count)
	}
}

func TestWriter_TimestampIsUTC(t *testing.T) {
	dir := tempDir(t)
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	before := time.Now().UTC()
	w.Write(Record{Project: "test", Provider: "openai", Model: "gpt-4o-mini", StatusCode: 200})
	after := time.Now().UTC()
	w.Close()

	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(dir, "wal-"+today+".jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var rec Record
	json.Unmarshal(data[:len(data)-1], &rec)

	if rec.Time.Before(before) || rec.Time.After(after) {
		t.Errorf("time %v not between %v and %v", rec.Time, before, after)
	}
	if rec.Time.Location() != time.UTC {
		t.Errorf("time location = %v, want UTC", rec.Time.Location())
	}
}

func TestWriter_RecordSerializesAllFields(t *testing.T) {
	dir := tempDir(t)
	w, err := NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	w.Write(Record{
		Project:      "myproj",
		Provider:     "anthropic",
		Model:        "claude-3-5-sonnet-20241022",
		PromptHash:   "deadbeef",
		InputTokens:  100,
		OutputTokens: 50,
		TotalTokens:  150,
		Cost:         0.0021,
		LatencyMs:    342,
		StatusCode:   200,
		CacheHit:     true,
		Stream:       true,
	})
	w.Close()

	today := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(dir, "wal-"+today+".jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// Verify all fields are present in JSON
	var raw map[string]any
	json.Unmarshal(data[:len(data)-1], &raw)

	requiredFields := []string{
		"time", "project", "provider", "model", "prompt_hash",
		"input_tokens", "output_tokens", "total_tokens",
		"cost", "latency_ms", "status_code", "cache_hit", "stream",
	}
	for _, field := range requiredFields {
		if _, ok := raw[field]; !ok {
			t.Errorf("missing field %q in WAL record JSON", field)
		}
	}
}

// TestWriter_SyncMode_Sync verifies that sync mode fsyncs on every write,
// so a record is on disk immediately without waiting for Close or 100ms tick.
func TestWriter_SyncMode_Sync(t *testing.T) {
	dir := tempDir(t)
	w, err := NewWriter(dir, "sync")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	// Write a single record (below batch threshold of 50)
	err = w.Write(Record{
		Project:    "sync-test",
		Provider:   "openai",
		Model:      "gpt-4o-mini",
		StatusCode: 200,
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// In sync mode, record should be on disk immediately (fsynced).
	// Read directly from disk without calling Close.
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
	if count != 1 {
		t.Errorf("expected 1 fsynced record in sync mode, got %d", count)
	}
}

func TestWriter_CheckWritableDoesNotAppendRecord(t *testing.T) {
	dir := tempDir(t)
	w, err := NewWriter(dir, "sync")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	if err := w.CheckWritable(); err != nil {
		t.Fatalf("CheckWritable: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "wal-") && strings.HasSuffix(entry.Name(), ".jsonl") {
			t.Fatalf("CheckWritable created WAL record file %s", entry.Name())
		}
	}
}

// TestWriter_SyncMode_Default verifies that empty or unknown sync mode
// defaults to batch mode behavior.
func TestWriter_SyncMode_Default(t *testing.T) {
	dir := tempDir(t)

	// Empty string should default to batch mode (no panic, no error)
	w1, err := NewWriter(dir, "")
	if err != nil {
		t.Fatalf("NewWriter with empty sync_mode: %v", err)
	}
	w1.Close()

	// Unknown string should also default to batch mode
	dir2 := t.TempDir()
	w2, err := NewWriter(dir2, "unknown-mode")
	if err != nil {
		t.Fatalf("NewWriter with unknown sync_mode: %v", err)
	}
	w2.Close()
}
