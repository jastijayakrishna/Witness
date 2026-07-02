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

// chainHead stores the hash and sequence of the last written record.
type chainHead struct {
	LastHash string `json:"last_hash"`
	LastSeq  uint64 `json:"last_seq"`
}

// Chain computes the record hash and sets prev_hash from the last committed record.
// Called in writer.go before appending each line.
func Chain(record *Record, prevHash string, seq ...uint64) error {
	if len(seq) > 0 {
		record.Seq = seq[0]
	}
	record.PrevHash = prevHash

	oldHash := record.RecordHash
	record.RecordHash = ""

	b, err := json.Marshal(record)
	if err != nil {
		record.RecordHash = oldHash
		return fmt.Errorf("failed to hash record: %w", err)
	}

	h := sha256.Sum256(b)
	record.RecordHash = hex.EncodeToString(h[:])
	return nil
}

// loadChainHead loads the last record hash from wal-chain-head.json.
// Returns "genesis" if the file doesn't exist (first boot).
func loadChainHead(dir string) (string, uint64, error) {
	path := filepath.Join(dir, chainHeadFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return genesisHash, 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("read chain head: %w", err)
	}

	var head chainHead
	if err := json.Unmarshal(data, &head); err != nil {
		return "", 0, fmt.Errorf("parse chain head: %w", err)
	}

	if head.LastHash == "" {
		return genesisHash, 0, nil
	}

	return head.LastHash, head.LastSeq, nil
}

// saveChainHead atomically writes the last record hash to wal-chain-head.json.
// Uses write-temp + rename for atomicity.
func saveChainHead(dir string, lastHash string, lastSeq uint64) error {
	head := chainHead{LastHash: lastHash, LastSeq: lastSeq}
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
//
// Uses iterative 64KB chunk scanning (up to 16MB) so it handles WAL files
// where the tail is corrupted or contains many malformed trailing lines.
func LastRecordHashOnDisk(dir string) (string, error) {
	hash, _, err := LastRecordHeadOnDisk(dir)
	return hash, err
}

// LastRecordHeadOnDisk returns the hash and sequence of the last valid WAL record.
func LastRecordHeadOnDisk(dir string) (string, uint64, error) {
	files, err := filepath.Glob(filepath.Join(dir, "wal-*.jsonl"))
	if err != nil {
		return "", 0, fmt.Errorf("glob wal files: %w", err)
	}
	if len(files) == 0 {
		return "", 0, nil
	}

	// Files are date-sorted (wal-YYYY-MM-DD.jsonl); take the last one.
	lastFile := files[len(files)-1]

	f, err := os.Open(lastFile)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", filepath.Base(lastFile), err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("stat %s: %w", filepath.Base(lastFile), err)
	}
	if stat.Size() == 0 {
		return "", 0, nil
	}

	const maxScan = 16 << 20 // 16MB ceiling
	chunkSize := int64(64 * 1024)
	offset := stat.Size()
	var tailData []byte

	for offset > 0 && int64(len(tailData)) < maxScan {
		readSize := chunkSize
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize

		buf := make([]byte, readSize)
		if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
			return "", 0, fmt.Errorf("read tail of %s: %w", filepath.Base(lastFile), err)
		}

		tailData = append(buf, tailData...)

		// Scan accumulated data backwards for the last valid JSONL line.
		lines := strings.Split(strings.TrimSpace(string(tailData)), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			line := strings.TrimSpace(lines[i])
			if line == "" {
				continue
			}
			var rec Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				continue // skip malformed (truncated first line from offset read)
			}
			return rec.RecordHash, rec.Seq, nil
		}
	}

	return "", 0, nil
}
