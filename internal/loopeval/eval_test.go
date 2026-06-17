package loopeval

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hubbleops/hubbleops/internal/loop"
)

func TestEvaluateReportsProductionMetrics(t *testing.T) {
	events := append(runawayEvents(), legitEvents()...)
	report := Evaluate(events, loop.DefaultConfig(), DefaultGateConfig())

	if len(report.GateFailures) != 0 {
		t.Fatalf("gate failures: %v", report.GateFailures)
	}
	if report.TotalTraces != 2 {
		t.Fatalf("traces=%d want 2", report.TotalTraces)
	}
	if report.RunawayRecall != 1 {
		t.Fatalf("runaway recall=%.4f want 1", report.RunawayRecall)
	}
	if report.BlockPrecision != 1 {
		t.Fatalf("block precision=%.4f want 1", report.BlockPrecision)
	}
	if report.FalsePositiveBlockRate != 0 {
		t.Fatalf("fp block rate=%.4f want 0", report.FalsePositiveBlockRate)
	}
	if report.SavedCostUSD <= 0 {
		t.Fatalf("saved cost=%.4f want >0", report.SavedCostUSD)
	}
}

func TestEvaluateGateFailures(t *testing.T) {
	events := legitEvents()
	for i := range events {
		events[i].Label = "true_runaway"
		events[i].ExpectedAction = "block"
	}
	report := Evaluate(events, loop.DefaultConfig(), DefaultGateConfig())
	if report.MissedRunaways != 1 {
		t.Fatalf("missed runaways=%d want 1", report.MissedRunaways)
	}
	if len(report.GateFailures) == 0 {
		t.Fatalf("expected gate failure")
	}
}

func TestReadAndWriteJSONL(t *testing.T) {
	input := strings.NewReader(`{"project":"p","session_id":"s","tool_name":"search","label":"valid_exploration"}` + "\n")
	events, err := ReadJSONL(input, "test")
	if err != nil {
		t.Fatalf("read jsonl: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events=%d want 1", len(events))
	}
	var out bytes.Buffer
	if err := WriteJSONL(&out, events); err != nil {
		t.Fatalf("write jsonl: %v", err)
	}
	if !strings.Contains(out.String(), `"tool_name":"search"`) {
		t.Fatalf("missing tool name in output: %s", out.String())
	}
}

func TestAnonymizeFingerprintsSensitiveData(t *testing.T) {
	events := []Event{{
		Project:        "real-customer",
		SessionID:      "user@example.com",
		StepID:         "step-1",
		ToolName:       "send_email",
		Args:           map[string]any{"email": "user@example.com"},
		Result:         map[string]any{"ok": true, "secret": "token"},
		StateDeltaHash: "state-raw",
	}}
	anonymized := Anonymize(events, "salt")
	encoded := mustJSON(anonymized)
	if strings.Contains(encoded, "user@example.com") || strings.Contains(encoded, "token") || strings.Contains(encoded, "state-raw") {
		t.Fatalf("anonymized output leaked sensitive data: %s", encoded)
	}
	if !strings.Contains(encoded, "hubbleops_capture") {
		t.Fatalf("anonymized output missing fingerprint marker: %s", encoded)
	}
}

func TestRealShadowCorpusGate(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "real_shadow", "*.jsonl"))
	if err != nil {
		t.Fatalf("glob real shadow corpus: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no real shadow corpus files found")
	}

	var events []Event
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			t.Fatalf("open %s: %v", file, err)
		}
		fileEvents, readErr := ReadJSONL(f, file)
		closeErr := f.Close()
		if readErr != nil {
			t.Fatalf("read %s: %v", file, readErr)
		}
		if closeErr != nil {
			t.Fatalf("close %s: %v", file, closeErr)
		}
		events = append(events, fileEvents...)
	}

	report := Evaluate(events, loop.DefaultConfig(), DefaultGateConfig())
	if len(report.GateFailures) != 0 {
		t.Fatalf("real shadow corpus gate failures: %v", report.GateFailures)
	}
}

func runawayEvents() []Event {
	var events []Event
	for i := 0; i < 8; i++ {
		events = append(events, Event{
			Project:        "prod",
			SessionID:      "runaway",
			ToolName:       "expensive_search",
			Args:           map[string]any{"query": "same"},
			Result:         map[string]any{"error": "timeout"},
			ResultClass:    "timeout",
			PromptTokens:   1000 + i*500,
			OutputTokens:   30,
			CostUSD:        0.05,
			UnixMillis:     int64(i * 10_000),
			Label:          "true_runaway",
			ExpectedAction: "block",
		})
	}
	return events
}

func legitEvents() []Event {
	var events []Event
	for i := 0; i < 8; i++ {
		events = append(events, Event{
			Project:        "prod",
			SessionID:      "legit",
			ToolName:       "upsert_customer",
			Args:           map[string]any{"customer_id": i},
			Result:         map[string]any{"ok": true},
			ResultClass:    "success",
			StateDeltaHash: "customer-state-" + string(rune('a'+i)),
			PromptTokens:   800,
			OutputTokens:   80,
			CostUSD:        0.003,
			UnixMillis:     int64(i * 1000),
			Label:          "legit_batch",
			ExpectedAction: "allow",
		})
	}
	return events
}

// A block mid-stream must stick as the trace verdict even if the tail of the
// stream cools back down to allow — max action across the stream, not final turn.
func TestEvaluateScoresMaxActionAcrossStream(t *testing.T) {
	var events []Event
	for i := 0; i < 8; i++ {
		events = append(events, Event{
			Project: "p", SessionID: "max-action", ToolName: "update_record",
			Args: map[string]any{"id": 42}, Result: map[string]any{"error": "server_error"},
			ResultClass: "unknown_error", CostUSD: 0.01, UnixMillis: int64(i+1) * 1000,
			Label: "true_runaway", ExpectedAction: "block",
		})
	}
	tools := []string{"search_docs", "read_file", "get_ticket"}
	for i := 0; i < 18; i++ {
		events = append(events, Event{
			Project: "p", SessionID: "max-action", ToolName: tools[i%3],
			Args: map[string]any{"q": i, "step": i * 7}, Result: map[string]any{"ok": true, "hit": i, "data": i * 13},
			ResultClass: "success", CostUSD: 0.001, UnixMillis: int64(60_000 + i*60_000),
			Label: "true_runaway", ExpectedAction: "block",
		})
	}
	report := Evaluate(events, loop.DefaultConfig(), DefaultGateConfig())
	if report.MissedRunaways != 0 {
		t.Fatalf("missed runaways=%d want 0 — block mid-stream must count (final-turn bug)", report.MissedRunaways)
	}
	if report.TruePositiveBlocks != 1 {
		t.Fatalf("true positive blocks=%d want 1", report.TruePositiveBlocks)
	}
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}
