package wal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DeadLetter is a durable, on-disk queue for decision receipts that could not be
// written to the WAL (e.g. a transient I/O failure or a closed file handle while a
// high-risk block is being enforced fail-closed). Each queued receipt is a single
// JSON file holding a fully-built, signed, fingerprinted wal.Record — so nothing
// sensitive is stored in the clear and recovery does not re-run any decision-side
// effects. The queue lives under the WAL directory, so it survives process restarts:
// on the next boot the drainer picks up whatever was left behind and replays it.
type DeadLetter struct {
	dir string
	mu  sync.Mutex // serializes Drain so two drains can't race on the same files
}

const deadLetterSuffix = ".receipt.json"

// NewDeadLetter creates (or opens) the dead-letter directory under the WAL dir.
func NewDeadLetter(walDir string) (*DeadLetter, error) {
	dir := filepath.Join(walDir, "deadletter")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create dead-letter dir: %w", err)
	}
	return &DeadLetter{dir: dir}, nil
}

// Enqueue durably persists a record that failed to write. The write is atomic
// (temp file + rename) so a crash mid-enqueue never leaves a half-written entry
// that the drainer could choke on.
func (d *DeadLetter) Enqueue(rec Record) error {
	if d == nil {
		return fmt.Errorf("dead-letter queue not configured")
	}
	if rec.Time.IsZero() {
		// Capture the decision time now so the recovered receipt is timestamped close
		// to when the decision was actually made, not when the WAL later recovered.
		rec.Time = time.Now().UTC()
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal dead-letter record: %w", err)
	}
	// ULID names sort chronologically, so the drainer replays in decision order.
	base := newULID() + deadLetterSuffix
	final := filepath.Join(d.dir, base)
	tmp := final + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write dead-letter temp: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("publish dead-letter entry: %w", err)
	}
	return nil
}

// Drain replays every queued receipt through the writer, preserving each record's
// original decision time. Entries that write successfully are removed; entries that
// fail are left in place for the next drain. Entries that cannot be parsed are moved
// aside (.bad) so one corrupt file can never wedge recovery forever.
//
// It returns how many receipts were recovered and how many remain queued.
func (d *DeadLetter) Drain(w *Writer) (recovered int, remaining int, err error) {
	if d == nil {
		return 0, 0, nil
	}
	if w == nil {
		return 0, 0, fmt.Errorf("nil writer")
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	names, err := d.entries()
	if err != nil {
		return 0, 0, err
	}
	for _, name := range names {
		path := filepath.Join(d.dir, name)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			remaining++
			continue
		}
		var rec Record
		if json.Unmarshal(data, &rec) != nil {
			_ = os.Rename(path, path+".bad")
			continue
		}
		if writeErr := w.WriteRecovered(rec); writeErr != nil {
			// WAL still unhealthy — stop early; the rest will be retried next tick.
			remaining += len(names) - recovered
			return recovered, remaining, writeErr
		}
		_ = os.Remove(path)
		recovered++
	}
	return recovered, remaining, nil
}

// Pending reports how many receipts are currently queued for recovery.
func (d *DeadLetter) Pending() (int, error) {
	if d == nil {
		return 0, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	names, err := d.entries()
	if err != nil {
		return 0, err
	}
	return len(names), nil
}

// entries returns the queued receipt filenames in chronological (filename) order.
func (d *DeadLetter) entries() ([]string, error) {
	dirEntries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, fmt.Errorf("read dead-letter dir: %w", err)
	}
	out := make([]string, 0, len(dirEntries))
	for _, e := range dirEntries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), deadLetterSuffix) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}
