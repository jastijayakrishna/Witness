package loop

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type corpusObservation struct {
	Project        string  `json:"project"`
	SessionID      string  `json:"session_id"`
	StepID         string  `json:"step_id"`
	DecisionStage  string  `json:"decision_stage"`
	ToolName       string  `json:"tool_name"`
	Args           any     `json:"args"`
	Result         any     `json:"result"`
	ResultClass    string  `json:"result_class"`
	StateDeltaHash string  `json:"state_delta_hash"`
	PromptTokens   int     `json:"prompt_tokens"`
	OutputTokens   int     `json:"output_tokens"`
	CostUSD        float64 `json:"cost_usd"`
	UnixMillis     int64   `json:"unix_millis"`
	Label          string  `json:"label"`
	ExpectedAction string  `json:"expected_action"`
}

func TestLoopCorpusJSONL(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "loop_corpus", "*.jsonl"))
	if err != nil {
		t.Fatalf("glob corpus: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no corpus files found")
	}

	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			obs := readCorpusFile(t, file)
			var expected string
			var label string
			state := NewState()
			var decision Decision
			for _, item := range obs {
				if item.ExpectedAction != "" {
					expected = item.ExpectedAction
				}
				if item.Label != "" {
					label = item.Label
				}
				state, decision = Observe(state, Observation{
					Project:        item.Project,
					SessionID:      item.SessionID,
					StepID:         item.StepID,
					DecisionStage:  item.DecisionStage,
					ToolName:       item.ToolName,
					Args:           item.Args,
					Result:         item.Result,
					ResultClass:    item.ResultClass,
					StateDeltaHash: item.StateDeltaHash,
					PromptTokens:   item.PromptTokens,
					OutputTokens:   item.OutputTokens,
					CostUSD:        item.CostUSD,
					UnixMillis:     item.UnixMillis,
				}, DefaultConfig())
			}

			if got := corpusAction(decision.ActionCeiling); got != expected {
				t.Fatalf("action=%s want %s label=%s confidence=%.2f signals=%v",
					got, expected, label, decision.Confidence, decision.SignalsFired)
			}
			if label == "legit_batch" && decision.Confidence > 0.30 {
				t.Fatalf("legit batch confidence %.2f > 0.30 signals=%v", decision.Confidence, decision.SignalsFired)
			}
			if label == "true_runaway" && decision.Confidence < 0.70 {
				t.Fatalf("runaway confidence %.2f < 0.70 signals=%v", decision.Confidence, decision.SignalsFired)
			}
		})
	}
}

func TestGeneratedLegitBatch500Allowed(t *testing.T) {
	state := NewState()
	var decision Decision
	for i := 0; i < 500; i++ {
		state, decision = Observe(state, Observation{
			Project:      "corpus",
			SessionID:    "generated-500-batch",
			ToolName:     "classify_ticket",
			Args:         map[string]any{"ticket_id": i},
			Result:       map[string]any{"ticket_id": i, "label": fmt.Sprintf("label_%d", i%7)},
			PromptTokens: 1000,
			OutputTokens: 200,
			CostUSD:      0.01,
			UnixMillis:   int64(i * 1000),
		}, DefaultConfig())
	}
	if decision.ActionCeiling == ActionBlock {
		t.Fatalf("500-call legitimate batch blocked: confidence=%.2f signals=%v", decision.Confidence, decision.SignalsFired)
	}
	if decision.Confidence > 0.30 {
		t.Fatalf("500-call legitimate batch confidence %.2f > 0.30 signals=%v", decision.Confidence, decision.SignalsFired)
	}
}

func readCorpusFile(t *testing.T, path string) []corpusObservation {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	var out []corpusObservation
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		var obs corpusObservation
		if err := json.Unmarshal([]byte(line), &obs); err != nil {
			t.Fatalf("parse corpus line: %v", err)
		}
		out = append(out, obs)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	if len(out) == 0 {
		t.Fatalf("empty corpus file %s", path)
	}
	return out
}

func corpusAction(a Action) string {
	switch a {
	case ActionBlock:
		return "block"
	case ActionWarn:
		return "warn"
	default:
		return "allow"
	}
}
