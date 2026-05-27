package wal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	chainHeadFile = "wal-chain-head.json"
	genesisHash   = "genesis"
)

// chainHead stores the hash of the last written record.
type chainHead struct {
	LastHash string `json:"last_hash"`
}

// Chain computes the record hash and sets prev_hash from the last committed record.
// Called in writer.go before appending each line.
func Chain(record *Record, prevHash string) {
	// Set the previous hash
	record.PrevHash = prevHash

	// Marshal the record WITHOUT the record_hash field to compute the hash
	// We'll compute it by temporarily setting it to empty
	oldRecordHash := record.RecordHash
	record.RecordHash = ""

	b, err := json.Marshal(record)
	if err != nil {
		// Should never happen for valid Record structs
		record.RecordHash = oldRecordHash
		return
	}

	// Compute SHA256 hash
	h := sha256.Sum256(b)
	record.RecordHash = hex.EncodeToString(h[:])
}

// loadChainHead loads the last record hash from wal-chain-head.json.
// Returns "genesis" if the file doesn't exist (first boot).
func loadChainHead(dir string) (string, error) {
	path := filepath.Join(dir, chainHeadFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return genesisHash, nil
	}
	if err != nil {
		return "", fmt.Errorf("read chain head: %w", err)
	}

	var head chainHead
	if err := json.Unmarshal(data, &head); err != nil {
		return "", fmt.Errorf("parse chain head: %w", err)
	}

	if head.LastHash == "" {
		return genesisHash, nil
	}

	return head.LastHash, nil
}

// saveChainHead atomically writes the last record hash to wal-chain-head.json.
// Uses write-temp + rename for atomicity.
func saveChainHead(dir string, lastHash string) error {
	head := chainHead{LastHash: lastHash}
	data, err := json.Marshal(head)
	if err != nil {
		return fmt.Errorf("marshal chain head: %w", err)
	}

	// Write to temp file
	tmpPath := filepath.Join(dir, chainHeadFile+".tmp")
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write chain head temp: %w", err)
	}

	// Atomic rename
	finalPath := filepath.Join(dir, chainHeadFile)
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("rename chain head: %w", err)
	}

	return nil
}

// VerifyChain verifies that a sequence of records forms an unbroken hash chain.
// Returns the index of the first broken link, or -1 if the chain is valid.
func VerifyChain(records []Record) int {
	for i := 1; i < len(records); i++ {
		if records[i].PrevHash != records[i-1].RecordHash {
			return i
		}
	}
	return -1
}

// RecomputeHash recomputes and returns the hash of a record without modifying it.
func RecomputeHash(record Record) string {
	// Clear the record_hash field for computation
	record.RecordHash = ""

	b, err := json.Marshal(record)
	if err != nil {
		return ""
	}

	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// LastRecordHashOnDisk reads the most recent WAL file in dir and returns the
// record_hash of its last valid JSONL line. Returns "" if no WAL files exist
// or the file is empty. Used at startup to detect crash gaps where the saved
// chain head is stale relative to what actually made it to disk.
func LastRecordHashOnDisk(dir string) (string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "wal-*.jsonl"))
	if err != nil {
		return "", fmt.Errorf("glob wal files: %w", err)
	}
	if len(files) == 0 {
		return "", nil
	}

	// Files are date-sorted (wal-YYYY-MM-DD.jsonl); take the last one.
	lastFile := files[len(files)-1]

	f, err := os.Open(lastFile)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", filepath.Base(lastFile), err)
	}
	defer f.Close()

	// Read last 64KB — more than enough for the last few records.
	stat, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", filepath.Base(lastFile), err)
	}
	if stat.Size() == 0 {
		return "", nil
	}

	readSize := int64(64 * 1024)
	offset := stat.Size() - readSize
	if offset < 0 {
		offset = 0
		readSize = stat.Size()
	}

	buf := make([]byte, readSize)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read tail of %s: %w", filepath.Base(lastFile), err)
	}
	buf = buf[:n]

	// Find the last valid JSONL line by scanning backwards.
	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue // skip malformed (might be a truncated first line from offset read)
		}
		return rec.RecordHash, nil
	}

	return "", nil
}
