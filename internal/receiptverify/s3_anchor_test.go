package receiptverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func TestS3AnchorDetectsTruncatedWAL(t *testing.T) {
	secret := "receipt-secret"
	signer := receipts.NewSigner("test", []byte(secret))
	fakeS3 := newReceiptVerifyWORMS3Fake()
	anchor := &wal.S3ObjectLockAnchor{
		Bucket:        "external-audit",
		Prefix:        "hubbleops/checkpoints",
		Region:        "us-east-1",
		RetentionDays: 30,
		Client:        fakeS3,
		Now:           func() time.Time { return time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC) },
	}

	walDir := t.TempDir()
	writer, err := wal.NewWriterWithOptions(walDir, wal.WriterOptions{
		SyncMode:         wal.SyncModeSync,
		Anchor:           anchor,
		CheckpointSigner: signer.SignCheckpoint,
		CheckpointEveryN: 1000,
	})
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	for i := 1; i <= 4; i++ {
		rec := wal.Record{
			Project:        "proj-a",
			Provider:       "_preflight",
			Model:          "preflight",
			StatusCode:     200,
			SessionID:      "sess-a",
			Actor:          "agent:local-cli",
			DecisionID:     fmt.Sprintf("dec_%d", i),
			Decision:       "allow",
			Action:         "deploy.release",
			PolicyVersion:  "test",
			DecisionReason: "test",
		}
		if err := writer.WriteSigned(rec, signer.SignRecord); err != nil {
			t.Fatalf("write signed %d: %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	records := readS3AnchorWALRecords(t, walDir)
	if len(records) != 4 {
		t.Fatalf("records=%d want 4", len(records))
	}
	truncatedPath := filepath.Join(t.TempDir(), "truncated.jsonl")
	truncated, err := os.Create(truncatedPath)
	if err != nil {
		t.Fatalf("create truncated wal: %v", err)
	}
	enc := json.NewEncoder(truncated)
	for _, rec := range records[:3] {
		if err := enc.Encode(rec); err != nil {
			t.Fatalf("write truncated record: %v", err)
		}
	}
	if err := truncated.Close(); err != nil {
		t.Fatalf("close truncated wal: %v", err)
	}

	verifier, err := NewVerifier(Options{
		ReceiptSecret:     secret,
		RequireSignatures: true,
		Anchor:            anchor,
	})
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	f, err := os.Open(truncatedPath)
	if err != nil {
		t.Fatalf("open truncated wal: %v", err)
	}
	if err := verifier.AddStream(f); err != nil {
		t.Fatalf("verify stream: %v", err)
	}
	_ = f.Close()

	report := verifier.Report()
	if report.Verified || report.AnchorMismatches == 0 {
		t.Fatalf("truncated WAL verified unexpectedly: %+v", report)
	}
	if !strings.Contains(report.Recommendation, "truncation detected: anchored seq=4, wal max seq=3") {
		t.Fatalf("recommendation=%q", report.Recommendation)
	}
}

func readS3AnchorWALRecords(t *testing.T, dir string) []wal.Record {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "wal-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("wal files=%v err=%v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	var records []wal.Record
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var rec wal.Record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decode wal: %v", err)
		}
		records = append(records, rec)
	}
	return records
}

type receiptVerifyWORMS3Fake struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newReceiptVerifyWORMS3Fake() *receiptVerifyWORMS3Fake {
	return &receiptVerifyWORMS3Fake{objects: map[string][]byte{}}
}

func (f *receiptVerifyWORMS3Fake) PutCheckpoint(ctx context.Context, bucket, key string, body []byte, retentionUntil time.Time) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	id := bucket + "/" + key
	if _, ok := f.objects[id]; ok {
		return wal.ErrS3AnchorObjectExists
	}
	f.objects[id] = append([]byte(nil), body...)
	return nil
}

func (f *receiptVerifyWORMS3Fake) ListCheckpoints(ctx context.Context, bucket, prefix string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for id := range f.objects {
		gotBucket, key, _ := strings.Cut(id, "/")
		if gotBucket == bucket && strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (f *receiptVerifyWORMS3Fake) GetCheckpoint(ctx context.Context, bucket, key string) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	body, ok := f.objects[bucket+"/"+key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), body...), nil
}

var _ wal.S3AnchorClient = (*receiptVerifyWORMS3Fake)(nil)
