package wal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Record is a single WAL entry written as one JSONL line.
type Record struct {
	Time         time.Time `json:"time"`
	Project      string    `json:"project"`
	Provider     string    `json:"provider"`
	Model        string    `json:"model"`
	PromptHash   string    `json:"prompt_hash"`
	InputTokens  int       `json:"input_tokens"`
	OutputTokens int       `json:"output_tokens"`
	TotalTokens  int       `json:"total_tokens"`
	Cost         float64   `json:"cost"`
	LatencyMs    int64     `json:"latency_ms"`
	StatusCode   int       `json:"status_code"`
	CacheHit     bool      `json:"cache_hit"`
	Stream       bool      `json:"stream"`
}

// Writer is an append-only WAL writer that fsyncs in batches.
type Writer struct {
	dir       string
	mu        sync.Mutex
	file      *os.File
	fileDate  string
	pending   int
	done      chan struct{}
	closeOnce sync.Once
}

// NewWriter creates a WAL writer that writes to the given directory.
// It starts a background goroutine that fsyncs every 100ms.
func NewWriter(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create wal dir: %w", err)
	}
	w := &Writer{
		dir:  dir,
		done: make(chan struct{}),
	}
	go w.syncLoop()
	return w, nil
}

// Write appends a record to the WAL. It blocks until the record is written
// and fsynced (either via the batch threshold or the sync loop).
func (w *Writer) Write(rec Record) error {
	rec.Time = time.Now().UTC()

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal wal record: %w", err)
	}
	line = append(line, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.ensureFile(); err != nil {
		return err
	}

	if _, err := w.file.Write(line); err != nil {
		return fmt.Errorf("write wal: %w", err)
	}

	w.pending++

	// Fsync every 50 records for throughput.
	if w.pending >= 50 {
		if err := w.file.Sync(); err != nil {
			return fmt.Errorf("fsync wal: %w", err)
		}
		w.pending = 0
	}

	return nil
}

// Close shuts down the sync loop and closes the file. Safe to call multiple times.
func (w *Writer) Close() error {
	var err error
	w.closeOnce.Do(func() {
		close(w.done)
		w.mu.Lock()
		defer w.mu.Unlock()
		if w.file != nil {
			_ = w.file.Sync()
			err = w.file.Close()
		}
	})
	return err
}

func (w *Writer) ensureFile() error {
	today := time.Now().UTC().Format("2006-01-02")
	if w.file != nil && w.fileDate == today {
		return nil
	}
	// Close old file if date rolled over.
	if w.file != nil {
		_ = w.file.Sync()
		_ = w.file.Close()
		w.pending = 0
	}
	path := filepath.Join(w.dir, fmt.Sprintf("wal-%s.jsonl", today))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open wal file: %w", err)
	}
	w.file = f
	w.fileDate = today
	return nil
}

// syncLoop fsyncs the WAL file every 100ms if there are pending writes.
func (w *Writer) syncLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			w.mu.Lock()
			if w.file != nil && w.pending > 0 {
				if err := w.file.Sync(); err != nil {
					log.Error().Err(err).Msg("wal fsync error")
				}
				w.pending = 0
			}
			w.mu.Unlock()
		}
	}
}
