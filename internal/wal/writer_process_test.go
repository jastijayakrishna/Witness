package wal_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/receiptverify"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func TestWriter_ConcurrentProcessesPreserveReceiptChain(t *testing.T) {
	if os.Getenv("HUBBLEOPS_WAL_WRITER_HELPER") == "1" {
		t.Skip("helper is run directly by the parent test")
	}
	dir := t.TempDir()
	startPath := filepath.Join(dir, "start")
	const processes = 6
	const writesPerProcess = 6

	type childResult struct {
		Index string `json:"index"`
		Error string `json:"error,omitempty"`
	}
	type childProc struct {
		cmd    *exec.Cmd
		output *bytes.Buffer
	}
	children := make([]childProc, 0, processes)
	for i := 0; i < processes; i++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestWriterProcessHelper$")
		cmd.Env = append(os.Environ(),
			"HUBBLEOPS_WAL_WRITER_HELPER=1",
			"HUBBLEOPS_WAL_WRITER_DIR="+dir,
			"HUBBLEOPS_WAL_WRITER_START="+startPath,
			"HUBBLEOPS_WAL_WRITER_INDEX="+fmt.Sprintf("%02d", i),
			"HUBBLEOPS_WAL_WRITER_COUNT="+fmt.Sprintf("%d", writesPerProcess),
		)
		out := &bytes.Buffer{}
		cmd.Stdout = out
		cmd.Stderr = out
		if err := cmd.Start(); err != nil {
			t.Fatalf("start helper %d: %v", i, err)
		}
		children = append(children, childProc{cmd: cmd, output: out})
	}
	if err := os.WriteFile(startPath, []byte("go"), 0600); err != nil {
		t.Fatalf("release helpers: %v", err)
	}

	for i := range children {
		err := children[i].cmd.Wait()
		raw := strings.TrimSpace(children[i].output.String())
		if err != nil {
			t.Fatalf("helper %d failed: %v output=%s", i, err, raw)
		}
		var res childResult
		jsonLine := firstProcessJSONLine(raw)
		if err := json.Unmarshal([]byte(jsonLine), &res); err != nil {
			t.Fatalf("helper %d invalid JSON %q: %v", i, raw, err)
		}
		if res.Error != "" {
			t.Fatalf("helper %d error: %s", i, res.Error)
		}
	}

	records := readRaceWALRecords(t, dir)
	want := processes * writesPerProcess
	if len(records) != want {
		t.Fatalf("records=%d want %d", len(records), want)
	}
	report := receiptverify.Verify(records)
	if !report.Verified {
		t.Fatalf("process WAL did not verify: %+v", report)
	}
}

func TestWriterProcessHelper(t *testing.T) {
	if os.Getenv("HUBBLEOPS_WAL_WRITER_HELPER") != "1" {
		return
	}
	dir := os.Getenv("HUBBLEOPS_WAL_WRITER_DIR")
	startPath := os.Getenv("HUBBLEOPS_WAL_WRITER_START")
	index := os.Getenv("HUBBLEOPS_WAL_WRITER_INDEX")
	count := 1
	if raw := strings.TrimSpace(os.Getenv("HUBBLEOPS_WAL_WRITER_COUNT")); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &count); err != nil {
			printWriterHelperResult(index, err.Error())
			return
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(startPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			printWriterHelperResult(index, "start file never appeared")
			return
		}
		time.Sleep(2 * time.Millisecond)
	}

	writer, err := wal.NewWriterWithOptions(dir, wal.WriterOptions{SyncMode: wal.SyncModeSync})
	if err != nil {
		printWriterHelperResult(index, err.Error())
		return
	}
	defer writer.Close()
	for i := 0; i < count; i++ {
		rec := signedRaceRecord(fmt.Sprintf("dec_process_%s_%03d", index, i))
		if err := writer.WriteSigned(rec, nil); err != nil {
			printWriterHelperResult(index, err.Error())
			return
		}
	}
	printWriterHelperResult(index, "")
}

func firstProcessJSONLine(raw string) string {
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "{") {
			return line
		}
	}
	return raw
}

func printWriterHelperResult(index, errText string) {
	result := map[string]string{"index": index}
	if errText != "" {
		result["error"] = errText
	}
	data, _ := json.Marshal(result)
	_, _ = os.Stdout.Write(append(data, '\n'))
}
