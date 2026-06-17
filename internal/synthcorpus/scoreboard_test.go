package synthcorpus

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/hubbleops/hubbleops/internal/loop"
)

const (
	minDetectRate = 0.95
	maxWarnRate   = 0.01
)

// TestSyntheticCorpusScoreboard replays the full starter corpus through the real
// detector + firewall and enforces the world-class bar per family. Misses are
// written to out/scoreboard_misses.jsonl for triage — fix the product, not the test.
//
// HUBBLEOPS_CORPUS_DIR overrides the corpus location so held-out seeds (data the
// thresholds were never tuned on) can be scored with the same gate:
//
//	python synthgen.py --out out/heldout8 --sessions 10000 --seed 8
//	HUBBLEOPS_CORPUS_DIR=out/heldout8/corpus go test ./internal/synthcorpus/ -run TestSyntheticCorpusScoreboard -v
func TestSyntheticCorpusScoreboard(t *testing.T) {
	dir := filepath.Join("..", "..", "starter_corpus_3000", "corpus")
	if override := os.Getenv("HUBBLEOPS_CORPUS_DIR"); override != "" {
		dir = filepath.Join("..", "..", override)
	}
	events, err := ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	sessions := GroupSessions(events)
	if len(sessions) < 2900 {
		t.Fatalf("sessions=%d, expected ~3000 — corpus incomplete", len(sessions))
	}

	results := make([]SessionResult, 0, len(sessions))
	for _, sess := range sessions {
		// Fresh ledger per session: corpus sessions are independent scenarios.
		res, err := ReplaySession(context.Background(), sess.Events, loop.DefaultConfig(), loop.NewMemoryActionStore())
		if err != nil {
			t.Fatalf("replay %s/%s: %v", sess.Project, sess.SessionID, err)
		}
		results = append(results, res)
	}

	sb := Score(results)
	t.Logf("\n%s", sb.Format())

	if len(sb.Misses) > 0 {
		writeMisses(t, sessions, sb.Misses)
	}
	for _, failure := range sb.GateFailures(minDetectRate, maxWarnRate) {
		t.Errorf("GATE: %s", failure)
	}
}

// writeMisses dumps the raw events of every missed/false-flagged session so they
// can be replayed individually while fixing the detector.
func writeMisses(t *testing.T, sessions []Session, misses []SessionResult) {
	t.Helper()
	bySession := map[string][]Event{}
	for _, s := range sessions {
		bySession[s.Project+"/"+s.SessionID] = s.Events
	}
	outDir := filepath.Join("..", "..", "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}
	path := filepath.Join(outDir, "scoreboard_misses.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create misses file: %v", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, miss := range misses {
		for _, ev := range bySession[miss.Project+"/"+miss.SessionID] {
			if err := enc.Encode(ev); err != nil {
				t.Fatalf("write miss: %v", err)
			}
		}
	}
	t.Logf("wrote %d missed sessions to %s", len(misses), path)
}
