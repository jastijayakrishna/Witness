package wal_test

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/receiptverify"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func TestWriter_MultipleInstancesPreserveReceiptChain(t *testing.T) {
	dir := t.TempDir()

	const writers = 8
	const writesPerWriter = 12
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < writers; w++ {
		wg.Add(1)
		ready.Add(1)
		go func(writerID int) {
			defer wg.Done()
			writer, err := wal.NewWriterWithOptions(dir, wal.WriterOptions{
				SyncMode: wal.SyncModeSync,
			})
			if err != nil {
				ready.Done()
				t.Errorf("NewWriterWithOptions writer=%d: %v", writerID, err)
				return
			}
			defer func() {
				if err := writer.Close(); err != nil {
					t.Errorf("Close writer=%d: %v", writerID, err)
				}
			}()
			ready.Done()
			<-start
			for i := 0; i < writesPerWriter; i++ {
				rec := signedRaceRecord(fmt.Sprintf("dec_multi_%02d_%03d", writerID, i))
				if err := writer.WriteSigned(rec, nil); err != nil {
					t.Errorf("WriteSigned writer=%d i=%d: %v", writerID, i, err)
					return
				}
				if i%5 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
		}(w)
	}
	ready.Wait()
	close(start)
	wg.Wait()

	records := readRaceWALRecords(t, dir)
	want := writers * writesPerWriter
	if len(records) != want {
		t.Fatalf("records=%d want %d", len(records), want)
	}
	report := receiptverify.Verify(records)
	if !report.Verified {
		t.Fatalf("multi-writer WAL did not verify: %+v", report)
	}
	if report.SeqGaps != 0 || report.ChainBrokenAt != -1 {
		t.Fatalf("unexpected chain report: %+v", report)
	}

	headHash, headSeq, err := wal.LastRecordHeadOnDisk(filepath.Clean(dir))
	if err != nil {
		t.Fatalf("LastRecordHeadOnDisk: %v", err)
	}
	if headSeq != uint64(want) {
		t.Fatalf("disk head seq=%d want %d", headSeq, want)
	}
	if headHash != records[len(records)-1].RecordHash {
		t.Fatalf("disk head hash=%q want last record hash %q", headHash, records[len(records)-1].RecordHash)
	}
}
