package wal

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDeadLetterEnqueueAndDrain(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, SyncModeSync)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	defer w.Close()

	dl, err := NewDeadLetter(dir)
	if err != nil {
		t.Fatalf("new dead-letter: %v", err)
	}

	decisionTime := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	for i := 0; i < 3; i++ {
		rec := Record{
			Project:          "p",
			Provider:         "_tool",
			DecisionID:       "dec_" + string(rune('a'+i)),
			LoopAction:       "block",
			Time:             decisionTime,
			ReceiptSignature: "sig",
		}
		if err := dl.Enqueue(rec); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	if pending, _ := dl.Pending(); pending != 3 {
		t.Fatalf("pending=%d want 3", pending)
	}

	recovered, remaining, err := dl.Drain(w)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if recovered != 3 {
		t.Fatalf("recovered=%d want 3", recovered)
	}
	if remaining != 0 {
		t.Fatalf("remaining=%d want 0", remaining)
	}
	if pending, _ := dl.Pending(); pending != 0 {
		t.Fatalf("pending after drain=%d want 0", pending)
	}

	// The recovered receipts must be in the WAL with their original decision time preserved.
	w.Close()
	records := readAllRecords(t, dir)
	var blocks int
	for _, rec := range records {
		if rec.LoopAction == "block" {
			blocks++
			if !rec.Time.Equal(decisionTime) {
				t.Fatalf("recovered record time=%s want preserved %s", rec.Time, decisionTime)
			}
			if rec.RecordHash == "" || rec.PrevHash == "" {
				t.Fatalf("recovered record not chained: %+v", rec)
			}
		}
	}
	if blocks != 3 {
		t.Fatalf("found %d block records in WAL want 3", blocks)
	}
	if idx := VerifyChain(records); idx != -1 {
		t.Fatalf("WAL chain broken at index %d after recovery", idx)
	}
}

func TestDeadLetterSurvivesRestart(t *testing.T) {
	dir := t.TempDir()

	// First "process": enqueue receipts, then go away without draining.
	dl1, err := NewDeadLetter(dir)
	if err != nil {
		t.Fatalf("new dead-letter: %v", err)
	}
	if err := dl1.Enqueue(Record{Project: "p", DecisionID: "dec_x", LoopAction: "block"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Second "process": fresh writer + fresh dead-letter pointing at the same dir
	// picks up what the previous run left behind.
	w, err := NewWriter(dir, SyncModeSync)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	defer w.Close()
	dl2, err := NewDeadLetter(dir)
	if err != nil {
		t.Fatalf("reopen dead-letter: %v", err)
	}
	if pending, _ := dl2.Pending(); pending != 1 {
		t.Fatalf("pending after restart=%d want 1", pending)
	}
	recovered, _, err := dl2.Drain(w)
	if err != nil {
		t.Fatalf("drain after restart: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered after restart=%d want 1", recovered)
	}
}

func TestDeadLetterCorruptEntryIsSetAside(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, SyncModeSync)
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	defer w.Close()
	dl, err := NewDeadLetter(dir)
	if err != nil {
		t.Fatalf("new dead-letter: %v", err)
	}

	// Write a corrupt entry directly into the queue dir.
	bad := filepath.Join(dir, "deadletter", "01CORRUPT"+deadLetterSuffix)
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if err := dl.Enqueue(Record{Project: "p", DecisionID: "dec_ok", LoopAction: "block"}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	recovered, _, err := dl.Drain(w)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("recovered=%d want 1 (corrupt entry must not block the good one)", recovered)
	}
	// The corrupt entry should no longer be a live queue file (moved to .bad).
	if pending, _ := dl.Pending(); pending != 0 {
		t.Fatalf("pending=%d want 0 (corrupt set aside)", pending)
	}
	if _, statErr := os.Stat(bad + ".bad"); statErr != nil {
		t.Fatalf("corrupt entry not set aside as .bad: %v", statErr)
	}
}
