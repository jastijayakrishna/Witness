package loop

import (
	"fmt"
	"testing"
)

type productionTrace struct {
	name          string
	label         string
	observations  []Observation
	expectedFinal Action
	minConfidence float64
	maxConfidence float64
	maxBlockStep  int
}

func TestProductionLikeTraceSuite(t *testing.T) {
	traces := []productionTrace{
		prodExactRepeatRunaway(),
		prodCostCamouflageRunaway(),
		prodSameFailureArgDriftRunaway(),
		prodAlternatingRunaway(),
		prodNoStateDeltaRunaway(),
		prodLegitBatch(500),
		prodPollingUntilSuccess(),
		prodValidExploration(),
		prodOccasionalRetryClusters(),
		prodUniformResultBatch(),
		prodRetryThenRecovery(),
	}

	for _, trace := range traces {
		t.Run(trace.name, func(t *testing.T) {
			result := replayProductionTrace(trace.observations)

			if result.final.ActionCeiling != trace.expectedFinal {
				t.Fatalf("final action=%s want %s confidence=%.2f signals=%v first_block_step=%d",
					result.final.ActionCeiling, trace.expectedFinal, result.final.Confidence, result.final.SignalsFired, result.firstBlockStep)
			}
			if trace.minConfidence > 0 && result.final.Confidence < trace.minConfidence {
				t.Fatalf("confidence %.2f below minimum %.2f signals=%v", result.final.Confidence, trace.minConfidence, result.final.SignalsFired)
			}
			if trace.maxConfidence > 0 && result.final.Confidence > trace.maxConfidence {
				t.Fatalf("confidence %.2f above maximum %.2f signals=%v", result.final.Confidence, trace.maxConfidence, result.final.SignalsFired)
			}
			if trace.maxBlockStep > 0 {
				if result.firstBlockStep == 0 {
					t.Fatalf("expected block by step %d, but no block occurred", trace.maxBlockStep)
				}
				if result.firstBlockStep > trace.maxBlockStep {
					t.Fatalf("first block at step %d, want <= %d", result.firstBlockStep, trace.maxBlockStep)
				}
			}
		})
	}
}

func TestProductionShadowCorpusSummary(t *testing.T) {
	var traces []productionTrace
	for i := 0; i < 40; i++ {
		traces = append(traces,
			prodExactRepeatRunawayWithID(i),
			prodCostCamouflageRunawayWithID(i),
			prodSameFailureArgDriftRunawayWithID(i),
			prodLegitBatchWithID(i, 80+i),
			prodPollingUntilSuccessWithID(i),
			prodValidExplorationWithID(i),
			prodOccasionalRetryClustersWithID(i),
			prodRetryThenRecoveryWithID(i),
		)
	}

	var falsePositiveBlocks, missedRunaways int
	var runawayCount, legitCount int
	for _, trace := range traces {
		result := replayProductionTrace(trace.observations)
		isRunaway := trace.label == "true_runaway"
		if isRunaway {
			runawayCount++
			if result.final.ActionCeiling != ActionBlock {
				missedRunaways++
				t.Logf("MISS %s: final=%s confidence=%.2f signals=%v", trace.name, result.final.ActionCeiling, result.final.Confidence, result.final.SignalsFired)
			}
			continue
		}

		legitCount++
		if result.final.ActionCeiling == ActionBlock {
			falsePositiveBlocks++
			t.Logf("FP %s: confidence=%.2f signals=%v", trace.name, result.final.Confidence, result.final.SignalsFired)
		}
	}

	if missedRunaways != 0 || falsePositiveBlocks != 0 {
		t.Fatalf("shadow corpus failed: missed_runaways=%d/%d false_positive_blocks=%d/%d",
			missedRunaways, runawayCount, falsePositiveBlocks, legitCount)
	}
	t.Logf("shadow corpus OK: runaways=%d legit=%d missed=0 false_positive_blocks=0", runawayCount, legitCount)
}

type traceReplayResult struct {
	final          Decision
	firstBlockStep int
}

func replayProductionTrace(observations []Observation) traceReplayResult {
	cfg := DefaultConfig()
	state := NewState()
	var out traceReplayResult
	for i, obs := range observations {
		state, out.final = Observe(state, obs, cfg)
		if out.firstBlockStep == 0 && out.final.ActionCeiling == ActionBlock {
			out.firstBlockStep = i + 1
		}
	}
	return out
}

func prodExactRepeatRunaway() productionTrace { return prodExactRepeatRunawayWithID(0) }
func prodExactRepeatRunawayWithID(id int) productionTrace {
	obs := make([]Observation, 10)
	cost := 0.01
	for i := range obs {
		obs[i] = Observation{
			Project:      "prod",
			SessionID:    fmt.Sprintf("runaway-exact-%d", id),
			ToolName:     "repo_patch",
			Args:         map[string]any{"file": "auth.go", "patch": "same"},
			Result:       map[string]any{"error": "server_error"},
			PromptTokens: 1000 + i*500,
			OutputTokens: 40,
			CostUSD:      cost,
			UnixMillis:   int64(i * 90_000),
		}
		cost *= 1.35
	}
	return productionTrace{name: fmt.Sprintf("exact_repeat_runaway_%d", id), label: "true_runaway", observations: obs, expectedFinal: ActionBlock, minConfidence: 0.70, maxBlockStep: 8}
}

func prodCostCamouflageRunaway() productionTrace { return prodCostCamouflageRunawayWithID(0) }
func prodCostCamouflageRunawayWithID(id int) productionTrace {
	var obs []Observation
	ts := int64(0)
	for i := 0; i < 8; i++ {
		obs = append(obs, Observation{
			Project:      "prod",
			SessionID:    fmt.Sprintf("runaway-camouflage-%d", id),
			ToolName:     "expensive_planner",
			Args:         map[string]any{"task": "same"},
			Result:       map[string]any{"error": "timeout"},
			PromptTokens: 5000,
			OutputTokens: 10,
			CostUSD:      0.10,
			UnixMillis:   ts,
		})
		ts += 5000
		for j := 0; j < 2; j++ {
			obs = append(obs, Observation{
				Project:      "prod",
				SessionID:    fmt.Sprintf("runaway-camouflage-%d", id),
				ToolName:     "debug_log",
				Args:         map[string]any{"line": fmt.Sprintf("%d-%d", i, j)},
				Result:       map[string]any{"ok": true},
				PromptTokens: 100,
				OutputTokens: 10,
				CostUSD:      0.001,
				UnixMillis:   ts,
			})
			ts += 1000
		}
	}
	return productionTrace{name: fmt.Sprintf("cost_camouflage_runaway_%d", id), label: "true_runaway", observations: obs, expectedFinal: ActionBlock, minConfidence: 0.70, maxBlockStep: 18}
}

func prodSameFailureArgDriftRunaway() productionTrace { return prodSameFailureArgDriftRunawayWithID(0) }
func prodSameFailureArgDriftRunawayWithID(id int) productionTrace {
	obs := make([]Observation, 12)
	for i := range obs {
		obs[i] = Observation{
			Project:      "prod",
			SessionID:    fmt.Sprintf("runaway-drift-%d", id),
			ToolName:     "open_ticket",
			Args:         map[string]any{"ticket_id": fmt.Sprintf("fake-%d-%d", id, i)},
			Result:       map[string]any{"error": "file_not_found"},
			PromptTokens: 1000 + i*120,
			OutputTokens: 20,
			CostUSD:      0.01 + float64(i)*0.001,
			UnixMillis:   int64(i * 30_000),
		}
	}
	return productionTrace{name: fmt.Sprintf("same_failure_arg_drift_%d", id), label: "true_runaway", observations: obs, expectedFinal: ActionBlock, minConfidence: 0.70, maxBlockStep: 6}
}

func prodAlternatingRunaway() productionTrace {
	obs := make([]Observation, 12)
	for i := range obs {
		tool := "search"
		if i%2 == 1 {
			tool = "edit"
		}
		obs[i] = Observation{
			Project:      "prod",
			SessionID:    "runaway-alternating",
			ToolName:     tool,
			Args:         map[string]any{"target": tool},
			Result:       map[string]any{"error": "failed"},
			PromptTokens: 1000 + i*300,
			OutputTokens: 30,
			CostUSD:      0.01,
			UnixMillis:   int64(i * 30_000),
		}
	}
	return productionTrace{name: "alternating_runaway", label: "true_runaway", observations: obs, expectedFinal: ActionBlock, minConfidence: 0.70, maxBlockStep: 8}
}

func prodNoStateDeltaRunaway() productionTrace {
	obs := make([]Observation, 8)
	for i := range obs {
		obs[i] = Observation{
			Project:        "prod",
			SessionID:      "runaway-no-state-delta",
			ToolName:       "apply_patch",
			Args:           map[string]any{"attempt": i},
			Result:         map[string]any{"status": "success"},
			StateDeltaHash: "unchanged",
			PromptTokens:   1200 + i*250,
			OutputTokens:   30,
			CostUSD:        0.01,
			UnixMillis:     int64(i * 30_000),
		}
	}
	return productionTrace{name: "no_state_delta_runaway", label: "true_runaway", observations: obs, expectedFinal: ActionBlock, minConfidence: 0.70, maxBlockStep: 6}
}

func prodLegitBatch(n int) productionTrace { return prodLegitBatchWithID(0, n) }
func prodLegitBatchWithID(id, n int) productionTrace {
	obs := make([]Observation, n)
	for i := range obs {
		obs[i] = Observation{
			Project:      "prod",
			SessionID:    fmt.Sprintf("legit-batch-%d", id),
			ToolName:     "classify_ticket",
			Args:         map[string]any{"ticket_id": i},
			Result:       map[string]any{"ticket_id": i, "label": fmt.Sprintf("label_%d", i%9)},
			PromptTokens: 1000,
			OutputTokens: 200,
			CostUSD:      0.01,
			UnixMillis:   int64(i * 1000),
		}
	}
	return productionTrace{name: fmt.Sprintf("legit_batch_%d_%d", id, n), label: "legit_batch", observations: obs, expectedFinal: ActionNone, maxConfidence: 0.30}
}

func prodPollingUntilSuccess() productionTrace { return prodPollingUntilSuccessWithID(0) }
func prodPollingUntilSuccessWithID(id int) productionTrace {
	progress := []int{0, 10, 35, 55, 80, 100}
	obs := make([]Observation, len(progress))
	for i, p := range progress {
		obs[i] = Observation{
			Project:        "prod",
			SessionID:      fmt.Sprintf("polling-%d", id),
			ToolName:       "poll_job_status",
			Args:           map[string]any{"job_id": fmt.Sprintf("job-%d", id)},
			Result:         map[string]any{"status": "running", "progress": p},
			StateDeltaHash: fmt.Sprintf("progress-%d", p),
			PromptTokens:   500,
			OutputTokens:   40,
			CostUSD:        0.002,
			UnixMillis:     int64(i * 5000),
		}
	}
	obs[len(obs)-1].Result = map[string]any{"status": "success", "progress": 100}
	return productionTrace{name: fmt.Sprintf("polling_until_success_%d", id), label: "valid_exploration", observations: obs, expectedFinal: ActionNone, maxConfidence: 0.30}
}

func prodValidExploration() productionTrace { return prodValidExplorationWithID(0) }
func prodValidExplorationWithID(id int) productionTrace {
	tools := []string{"search", "fetch", "search", "fetch", "read_file", "edit_file", "run_tests"}
	obs := make([]Observation, len(tools))
	for i, tool := range tools {
		obs[i] = Observation{
			Project:        "prod",
			SessionID:      fmt.Sprintf("explore-%d", id),
			ToolName:       tool,
			Args:           map[string]any{"step": i, "query": fmt.Sprintf("issue-%d", id)},
			Result:         map[string]any{"ok": true, "artifact": fmt.Sprintf("%d-%d", id, i)},
			StateDeltaHash: fmt.Sprintf("state-%d-%d", id, i),
			PromptTokens:   1000 + i*200,
			OutputTokens:   200,
			CostUSD:        0.02,
			UnixMillis:     int64(i * 5000),
		}
	}
	return productionTrace{name: fmt.Sprintf("valid_exploration_%d", id), label: "valid_exploration", observations: obs, expectedFinal: ActionNone, maxConfidence: 0.30}
}

func prodOccasionalRetryClusters() productionTrace { return prodOccasionalRetryClustersWithID(0) }
func prodOccasionalRetryClustersWithID(id int) productionTrace {
	var obs []Observation
	ts := int64(0)
	for i := 0; i < 80; i++ {
		if i == 20 || i == 50 {
			for j := 0; j < 3; j++ {
				obs = append(obs, Observation{
					Project:      "prod",
					SessionID:    fmt.Sprintf("retry-clusters-%d", id),
					ToolName:     "flaky_api",
					Args:         map[string]any{"retry": true},
					Result:       map[string]any{"error": "503"},
					PromptTokens: 1000,
					OutputTokens: 20,
					CostUSD:      0.01,
					UnixMillis:   ts,
				})
				ts += 2000
			}
			continue
		}
		obs = append(obs, Observation{
			Project:      "prod",
			SessionID:    fmt.Sprintf("retry-clusters-%d", id),
			ToolName:     "real_work",
			Args:         map[string]any{"task": fmt.Sprintf("%d-%d", id, i)},
			Result:       map[string]any{"ok": true, "data": i},
			PromptTokens: 1000,
			OutputTokens: 200,
			CostUSD:      0.02,
			UnixMillis:   ts,
		})
		ts += 5000
	}
	return productionTrace{name: fmt.Sprintf("occasional_retry_clusters_%d", id), label: "valid_exploration", observations: obs, expectedFinal: ActionNone}
}

func prodUniformResultBatch() productionTrace {
	obs := make([]Observation, 120)
	for i := range obs {
		obs[i] = Observation{
			Project:      "prod",
			SessionID:    "uniform-result-batch",
			ToolName:     "classify_spam",
			Args:         map[string]any{"message_id": i},
			Result:       map[string]any{"label": "not_spam"},
			PromptTokens: 800,
			OutputTokens: 80,
			CostUSD:      0.005,
			UnixMillis:   int64(i * 1000),
		}
	}
	return productionTrace{name: "uniform_result_batch", label: "legit_batch", observations: obs, expectedFinal: ActionWarn}
}

func prodRetryThenRecovery() productionTrace { return prodRetryThenRecoveryWithID(0) }
func prodRetryThenRecoveryWithID(id int) productionTrace {
	obs := []Observation{
		{Project: "prod", SessionID: fmt.Sprintf("retry-recovery-%d", id), ToolName: "submit_job", Args: map[string]any{"job": id}, Result: map[string]any{"error": "timeout"}, PromptTokens: 500, OutputTokens: 20, CostUSD: 0.004, UnixMillis: 0},
		{Project: "prod", SessionID: fmt.Sprintf("retry-recovery-%d", id), ToolName: "submit_job", Args: map[string]any{"job": id}, Result: map[string]any{"error": "timeout"}, PromptTokens: 500, OutputTokens: 20, CostUSD: 0.004, UnixMillis: 5_000},
		{Project: "prod", SessionID: fmt.Sprintf("retry-recovery-%d", id), ToolName: "submit_job", Args: map[string]any{"job": id}, Result: map[string]any{"status": "success", "id": fmt.Sprintf("remote-%d", id)}, StateDeltaHash: fmt.Sprintf("remote-%d", id), PromptTokens: 500, OutputTokens: 20, CostUSD: 0.004, UnixMillis: 10_000},
	}
	return productionTrace{name: fmt.Sprintf("retry_then_recovery_%d", id), label: "valid_exploration", observations: obs, expectedFinal: ActionNone, maxConfidence: 0.30}
}
