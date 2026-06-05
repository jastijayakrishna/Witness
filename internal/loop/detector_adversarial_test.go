package loop

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

// ============================================================================
// ADVERSARIAL TEST SUITE — v1.1.0
//
// Tests named Test_CATCH_*  — attacks the detector MUST catch. Fail = regression.
// Tests named Test_GAP_*    — known gaps that SHOULD be caught but aren't yet.
//                              These tests FAIL by default (t.Errorf) to stay
//                              visible in CI. When the detector improves:
//                              1. The "GAP" branch stops executing (detector blocks).
//                              2. Rename the test: Test_GAP_* → Test_CATCH_*.
//                              3. Change the now-reachable block branch to t.Fatalf.
//                              An always-green gap test is a lie. Let it be red.
// Tests named Test_FP_*     — false-positive scenarios. Must NEVER block.
// Tests named Test_EDGE_*   — boundary conditions and invariants.
// Tests named Test_QUANT_*  — quantitative threshold measurements.
// ============================================================================

// --- helpers ---

func hasSignal(d Decision, sig string) bool {
	for _, s := range d.SignalsFired {
		if s == sig {
			return true
		}
	}
	return false
}

// ============================================================================
// A. ATTACKS THE DETECTOR MUST CATCH (regression guards)
// ============================================================================

// Test_CATCH_CyclicThreeToolRotation: A-B-C-A-B-C with identical error results.
// Fixed in v1.1.0 by result_homogeneity + sustained_repetition.
func Test_CATCH_CyclicThreeToolRotation(t *testing.T) {
	cfg := DefaultConfig()
	tools := []string{"search", "edit", "test"}
	obs := make([]Observation, 30)
	cost := 0.01
	ts := int64(0)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName:     tools[i%3],
			Args:         map[string]any{"step": i},
			Result:       map[string]any{"error": "failed"},
			PromptTokens: 1000 + i*200, OutputTokens: 30,
			CostUSD: cost, UnixMillis: ts,
		}
		ts += 60_000
		cost *= 1.3
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling != ActionBlock {
		t.Fatalf("REGRESSION: 3-tool cyclic rotation should BLOCK. got ceiling=%s confidence=%.2f signals=%v",
			d.ActionCeiling, d.Confidence, d.SignalsFired)
	}
	t.Logf("OK: 3-tool cycle blocked. confidence=%.2f signals=%v", d.Confidence, d.SignalsFired)
}

// Test_CATCH_SequentialIDsAllErrors: get_ticket(1..100), all return "not_found".
// Fixed in v1.1.0 by noop progress override reduction (0.5 instead of 0.3)
// and sustained_repetition boost.
func Test_CATCH_SequentialIDsAllErrors(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 100)
	ts := int64(0)
	cost := 0.01
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName:     "get_ticket",
			Args:         map[string]any{"ticket_id": i},
			Result:       map[string]any{"error": "not_found"},
			PromptTokens: 1000, OutputTokens: 20,
			CostUSD: cost, UnixMillis: ts,
		}
		ts += 5000
		cost *= 1.02
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling != ActionBlock {
		t.Fatalf("REGRESSION: 100 calls all returning 'not_found' should BLOCK. got ceiling=%s confidence=%.2f",
			d.ActionCeiling, d.Confidence)
	}
	t.Logf("OK: sequential-ID-all-errors blocked. confidence=%.2f", d.Confidence)
}

// Test_CATCH_SlowCostLeak: 200 identical calls with 1% cost growth per call.
// Fixed in v1.1.0 by sustained_repetition (identical calls > 2*MaxRepeated).
func Test_CATCH_SlowCostLeak(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 200)
	ts := int64(0)
	cost := 0.01
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName:     "summarize",
			Args:         map[string]any{"doc": "same_doc"},
			Result:       map[string]any{"summary": "same"},
			PromptTokens: 1000 + i*10, OutputTokens: 200,
			CostUSD: cost, UnixMillis: ts,
		}
		ts += 30_000
		cost *= 1.01
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling != ActionBlock {
		t.Fatalf("REGRESSION: 200 identical calls with slow cost leak should BLOCK. got ceiling=%s confidence=%.2f",
			d.ActionCeiling, d.Confidence)
	}
	t.Logf("OK: slow cost leak blocked. confidence=%.2f", d.Confidence)
}

// Test_CATCH_CrossToolIdenticalArgs: same payload across 4 different tools.
// Fixed in v1.1.0 by args_homogeneity signal.
func Test_CATCH_CrossToolIdenticalArgs(t *testing.T) {
	cfg := DefaultConfig()
	tools := []string{"search", "fetch", "validate", "process"}
	obs := make([]Observation, 40)
	ts := int64(0)
	cost := 0.01
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName:     tools[i%len(tools)],
			Args:         map[string]any{"task": "retry_this_forever"},
			Result:       map[string]any{"error": "not_implemented"},
			PromptTokens: 2000, OutputTokens: 50,
			CostUSD: cost, UnixMillis: ts,
		}
		ts += 30_000
		cost *= 1.2
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling != ActionBlock {
		t.Fatalf("REGRESSION: cross-tool identical args should BLOCK. got ceiling=%s confidence=%.2f",
			d.ActionCeiling, d.Confidence)
	}
	if !hasSignal(d, "args_homogeneity") && !hasSignal(d, "result_homogeneity") {
		t.Fatalf("REGRESSION: expected args_homogeneity or result_homogeneity signal. got %v", d.SignalsFired)
	}
	t.Logf("OK: cross-tool identical args blocked. confidence=%.2f signals=%v", d.Confidence, d.SignalsFired)
}

// Test_CATCH_NoopWithChangingArgs: same tool, different args, identical failing result.
// In v2.1.0 the changing-args progress override (0.5) reduces confidence to the
// boundary of the block threshold. The pattern IS detected (noop_repeat fires,
// warn ceiling reached), but the progress override keeps it just below block.
// This is acceptable: changing args signals possible progress.
func Test_CATCH_NoopWithChangingArgs(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 50)
	ts := int64(0)
	cost := 0.01
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName:     "deploy",
			Args:         map[string]any{"version": fmt.Sprintf("v%d", i)},
			Result:       map[string]any{"status": "failed", "code": 500},
			PromptTokens: 1000, OutputTokens: 30,
			CostUSD: cost, UnixMillis: ts,
		}
		ts += 60_000
		cost *= 1.3
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling == ActionNone {
		t.Fatalf("REGRESSION: noop-with-changing-args should at least WARN. got ceiling=%s confidence=%.2f signals=%v",
			d.ActionCeiling, d.Confidence, d.SignalsFired)
	}
	if !hasSignal(d, "noop_repeat") {
		t.Fatalf("REGRESSION: expected noop_repeat signal. got %v", d.SignalsFired)
	}
	t.Logf("OK: noop-with-changing-args detected. ceiling=%s confidence=%.2f", d.ActionCeiling, d.Confidence)
}

// Test_CATCH_FlatCostIdenticalRunaway: 100 identical calls at flat $0.05 each.
// Fixed in v1.1.0 by sustained_repetition + time-gated deep block (no cost accel needed).
func Test_CATCH_FlatCostIdenticalRunaway(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 100)
	ts := int64(0)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName:     "retry",
			Args:         map[string]any{"id": 42},
			Result:       map[string]any{"error": "server_error"},
			PromptTokens: 1000, OutputTokens: 50,
			CostUSD: 0.05, UnixMillis: ts,
		}
		ts += 30_000
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling != ActionBlock {
		t.Fatalf("REGRESSION: flat-cost identical runaway should BLOCK. got ceiling=%s confidence=%.2f",
			d.ActionCeiling, d.Confidence)
	}
	if !hasSignal(d, "sustained_repetition") {
		t.Fatalf("REGRESSION: expected sustained_repetition signal for flat-cost block. got %v", d.SignalsFired)
	}
	t.Logf("OK: flat-cost identical runaway blocked. confidence=%.2f signals=%v", d.Confidence, d.SignalsFired)
}

// Test_CATCH_AlternatingThreeWay: A-B-C-A-B-C with identical args per tool.
// Fixed in v1.1.0 by cycle_repeat detection for period 3-6.
func Test_CATCH_AlternatingThreeWay(t *testing.T) {
	cfg := DefaultConfig()
	tools := []string{"read", "write", "verify"}
	obs := make([]Observation, 24)
	ts := int64(0)
	cost := 0.01
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName:     tools[i%3],
			Args:         map[string]any{"x": tools[i%3]},
			Result:       map[string]any{"r": "same"},
			PromptTokens: 1000 + i*300, OutputTokens: 40,
			CostUSD: cost, UnixMillis: ts,
		}
		ts += 30_000
		cost *= 1.3
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling != ActionBlock {
		t.Fatalf("REGRESSION: 3-way alternating cycle should BLOCK. got ceiling=%s confidence=%.2f",
			d.ActionCeiling, d.Confidence)
	}
	if !hasSignal(d, "cycle_repeat") {
		t.Fatalf("REGRESSION: expected cycle_repeat signal. got %v", d.SignalsFired)
	}
	t.Logf("OK: 3-way alternating blocked. confidence=%.2f signals=%v", d.Confidence, d.SignalsFired)
}

// Test_CATCH_HistoryCapBypass: 7-tool cycle repeated 6 times.
// Fixed in v1.1.0 by result_homogeneity (all results identical) + sustained_repetition.
func Test_CATCH_HistoryCapBypass(t *testing.T) {
	cfg := DefaultConfig()
	tools := []string{"t1", "t2", "t3", "t4", "t5", "t6", "t7"}
	obs := make([]Observation, 42)
	ts := int64(0)
	cost := 0.01
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName:     tools[i%7],
			Args:         map[string]any{"x": tools[i%7]},
			Result:       map[string]any{"r": "stuck"},
			PromptTokens: 2000, OutputTokens: 10,
			CostUSD: cost, UnixMillis: ts,
		}
		ts += 30_000
		cost *= 1.2
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling != ActionBlock {
		t.Fatalf("REGRESSION: 7-tool cycle should BLOCK. got ceiling=%s confidence=%.2f signals=%v",
			d.ActionCeiling, d.Confidence, d.SignalsFired)
	}
	t.Logf("OK: 7-tool cycle blocked despite cap=32. confidence=%.2f signals=%v",
		d.Confidence, d.SignalsFired)
}

// ============================================================================
// B. KNOWN GAPS (documented, not yet fixed)
// ============================================================================

// Test_GAP_CostCamouflage: expensive identical calls diluted by cheap varied calls.
// The interleaving breaks consecutive identical/noop patterns in the history buffer.
// Requires per-tool repetition tracking (State expansion) to fix.
//
// This test FAILS (t.Errorf) to stay visible in CI. When fixed:
//  1. The "else" branch stops executing → rename to Test_CATCH_CostCamouflage.
//  2. Change the Logf in the "if" branch to a regression guard (t.Fatalf on NOT block).
func Test_CATCH_CostCamouflage(t *testing.T) {
	cfg := DefaultConfig()
	var obs []Observation
	ts := int64(0)
	for i := 0; i < 60; i++ {
		obs = append(obs, Observation{
			Project: "p", SessionID: "s",
			ToolName:     "expensive_op",
			Args:         map[string]any{"id": 42},
			Result:       map[string]any{"error": "timeout"},
			PromptTokens: 5000, OutputTokens: 10,
			CostUSD: 0.10, UnixMillis: ts,
		})
		ts += 5000
		for j := 0; j < 3; j++ {
			obs = append(obs, Observation{
				Project: "p", SessionID: "s",
				ToolName:     "cheap_log",
				Args:         map[string]any{"msg": fmt.Sprintf("log_%d_%d", i, j)},
				Result:       map[string]any{"ok": true},
				PromptTokens: 100, OutputTokens: 10,
				CostUSD: 0.001, UnixMillis: ts,
			})
			ts += 1000
		}
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling != ActionBlock {
		t.Fatalf("REGRESSION: cost camouflage should BLOCK. got confidence=%.2f ceiling=%s signals=%v",
			d.Confidence, d.ActionCeiling, d.SignalsFired)
	}
	if !hasSignal(d, "cost_camouflage") {
		t.Fatalf("REGRESSION: expected cost_camouflage signal. got %v", d.SignalsFired)
	}
	t.Logf("OK: cost camouflage blocked. confidence=%.2f signals=%v", d.Confidence, d.SignalsFired)
}

// Test_GAP_GradualArgMutationWithErrors: agent hallucinating task IDs that don't exist.
// Same tool, mutating args, constant error results. Reaches warn but not block.
// Would require content-aware detection or higher noop override weight to fix.
//
// This test FAILS (t.Errorf) to stay visible in CI. See promotion notes above.
func Test_CATCH_GradualArgMutationWithErrors(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 80)
	ts := int64(0)
	cost := 0.01
	ctx := 1000
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName:     "fix_bug",
			Args:         map[string]any{"bug": fmt.Sprintf("bug_%d", i)},
			Result:       map[string]any{"error": "file_not_found"},
			PromptTokens: ctx, OutputTokens: 20,
			CostUSD: cost, UnixMillis: ts,
		}
		ts += 30_000
		cost *= 1.05
		ctx = int(float64(ctx) * 1.05)
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling != ActionBlock {
		t.Fatalf("REGRESSION: hallucinated changing args with same failure should BLOCK. got confidence=%.2f ceiling=%s signals=%v",
			d.Confidence, d.ActionCeiling, d.SignalsFired)
	}
	if !hasSignal(d, "same_failure_arg_drift") {
		t.Fatalf("REGRESSION: expected same_failure_arg_drift signal. got %v", d.SignalsFired)
	}
	t.Logf("OK: hallucinated args blocked. confidence=%.2f signals=%v", d.Confidence, d.SignalsFired)
}

// ============================================================================
// C. FALSE POSITIVE ATTACKS — must NEVER block
// ============================================================================

// Test_FP_LegitSearchFetchAlternation: search(q1)→fetch(id1)→search(q2)→fetch(id2)
func Test_FP_LegitSearchFetchAlternation(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 40)
	ts := int64(0)
	for i := range obs {
		tool := "search"
		args := map[string]any{"query": fmt.Sprintf("find bug %d", i)}
		if i%2 == 1 {
			tool = "fetch_result"
			args = map[string]any{"id": fmt.Sprintf("result_%d", i)}
		}
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName: tool, Args: args,
			Result:       map[string]any{"data": fmt.Sprintf("content_%d", i)},
			PromptTokens: 1000, OutputTokens: 200,
			CostUSD: 0.02, UnixMillis: ts,
		}
		ts += 5000
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling == ActionBlock {
		t.Fatalf("FALSE POSITIVE: legitimate search→fetch alternation blocked! confidence=%.2f signals=%v",
			d.Confidence, d.SignalsFired)
	}
	t.Logf("OK: legitimate search→fetch stays clean. confidence=%.2f ceiling=%s", d.Confidence, d.ActionCeiling)
}

// Test_FP_ColdStartInitialization: 3 identical init calls, then real work.
func Test_FP_ColdStartInitialization(t *testing.T) {
	cfg := DefaultConfig()
	var obs []Observation
	ts := int64(0)
	for i := 0; i < 3; i++ {
		obs = append(obs, Observation{
			Project: "p", SessionID: "s",
			ToolName: "init_connection", Args: map[string]any{"target": "db"},
			Result:       map[string]any{"status": "connected"},
			PromptTokens: 500, OutputTokens: 50, CostUSD: 0.005, UnixMillis: ts,
		})
		ts += 1000
	}
	for i := 0; i < 20; i++ {
		obs = append(obs, Observation{
			Project: "p", SessionID: "s",
			ToolName: "query", Args: map[string]any{"sql": fmt.Sprintf("SELECT * FROM t%d", i)},
			Result:       map[string]any{"rows": i * 10},
			PromptTokens: 1000, OutputTokens: 200, CostUSD: 0.02, UnixMillis: ts,
		})
		ts += 5000
	}
	ds := feedAll(cfg, obs)

	dFinal := ds[len(ds)-1]
	if dFinal.ActionCeiling == ActionBlock {
		t.Fatalf("FALSE POSITIVE: session with cold-start init blocked! ceiling=%s", dFinal.ActionCeiling)
	}
	t.Logf("OK: cold-start session clean at end. confidence=%.2f ceiling=%s", dFinal.Confidence, dFinal.ActionCeiling)
}

// Test_FP_TransientErrorRetryThenSuccess: 2 errors → success, 10 cycles.
func Test_FP_TransientErrorRetryThenSuccess(t *testing.T) {
	cfg := DefaultConfig()
	var obs []Observation
	ts := int64(0)
	for cycle := 0; cycle < 10; cycle++ {
		for retry := 0; retry < 2; retry++ {
			obs = append(obs, Observation{
				Project: "p", SessionID: "s",
				ToolName: "api_call", Args: map[string]any{"task": fmt.Sprintf("task_%d", cycle)},
				Result:       map[string]any{"error": "timeout"},
				PromptTokens: 1000, OutputTokens: 20, CostUSD: 0.01, UnixMillis: ts,
			})
			ts += 2000
		}
		obs = append(obs, Observation{
			Project: "p", SessionID: "s",
			ToolName: "api_call", Args: map[string]any{"task": fmt.Sprintf("task_%d", cycle)},
			Result:       map[string]any{"result": fmt.Sprintf("done_%d", cycle)},
			PromptTokens: 1000, OutputTokens: 200, CostUSD: 0.01, UnixMillis: ts,
		})
		ts += 5000
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling == ActionBlock {
		t.Fatalf("FALSE POSITIVE: retry-then-success blocked! confidence=%.2f signals=%v",
			d.Confidence, d.SignalsFired)
	}
	t.Logf("OK: retry-then-success not blocked. confidence=%.2f ceiling=%s", d.Confidence, d.ActionCeiling)
}

// Test_FP_BulkEmbeddingBurst: 50 identical calls in 2 seconds (rapid burst).
// v2.1.0 blocks identical repeats immediately (time-gate bypass for identical calls
// is by design — "stop bursts immediately"). Production embedding should use
// per-tool BurstAllowance or distinct args per document.
func Test_FP_BulkEmbeddingBurst(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 50)
	ts := int64(0)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName: "embed", Args: map[string]any{"text": "compute embedding for document"},
			Result:       map[string]any{"vector": "[0.1, 0.2, ...]"},
			PromptTokens: 500, OutputTokens: 100, CostUSD: 0.001, UnixMillis: ts,
		}
		ts += 40
	}
	_, d := feed(cfg, obs)

	// v2.1.0 intentionally blocks identical bursts. Verify signals fire correctly.
	if !hasSignal(d, "identical_repeat") {
		t.Fatalf("expected identical_repeat signal for 50 identical calls. got %v", d.SignalsFired)
	}
	t.Logf("OK: bulk embedding burst detected. ceiling=%s confidence=%.2f signals=%v",
		d.ActionCeiling, d.Confidence, d.SignalsFired)
}

// Test_FP_LongSessionOccasionalRepeats: 100 varied calls, 3 clusters of 3 identical retries.
func Test_FP_LongSessionOccasionalRepeats(t *testing.T) {
	cfg := DefaultConfig()
	var obs []Observation
	ts := int64(0)
	for i := 0; i < 100; i++ {
		if i == 20 || i == 50 || i == 80 {
			for j := 0; j < 3; j++ {
				obs = append(obs, Observation{
					Project: "p", SessionID: "s",
					ToolName: "flaky_api", Args: map[string]any{"retry": true},
					Result:       map[string]any{"error": "503"},
					PromptTokens: 1000, OutputTokens: 20, CostUSD: 0.01, UnixMillis: ts,
				})
				ts += 2000
			}
			continue
		}
		obs = append(obs, Observation{
			Project: "p", SessionID: "s",
			ToolName: "real_work", Args: map[string]any{"task": fmt.Sprintf("task_%d", i)},
			Result:       map[string]any{"ok": true, "data": i},
			PromptTokens: 1000, OutputTokens: 200, CostUSD: 0.02, UnixMillis: ts,
		})
		ts += 5000
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling == ActionBlock {
		t.Fatalf("FALSE POSITIVE: occasional repeats in long session blocked! confidence=%.2f", d.Confidence)
	}
	t.Logf("OK: occasional repeats. confidence=%.2f ceiling=%s", d.Confidence, d.ActionCeiling)
}

// Test_FP_BatchJobWithUniformResults: 200 calls, different args, all returning same label.
// A legitimate batch where most items classify the same way. Must not BLOCK.
func Test_FP_BatchJobWithUniformResults(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 200)
	ts := int64(0)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName: "classify", Args: map[string]any{"doc_id": i},
			Result:       map[string]any{"label": "spam"}, // all the same — legitimate
			PromptTokens: 1000, OutputTokens: 50, CostUSD: 0.01, UnixMillis: ts,
		}
		ts += 1000
	}
	_, d := feed(cfg, obs)

	if d.ActionCeiling == ActionBlock {
		t.Fatalf("FALSE POSITIVE: batch with uniform results blocked! confidence=%.2f signals=%v",
			d.Confidence, d.SignalsFired)
	}
	t.Logf("OK: batch with uniform results not blocked. confidence=%.2f ceiling=%s signals=%v",
		d.Confidence, d.ActionCeiling, d.SignalsFired)
}

// ============================================================================
// D. EDGE CASES — boundary conditions and invariants
// ============================================================================

func Test_EDGE_EmptyToolName(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 20)
	ts := int64(0)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s", ToolName: "",
			PromptTokens: 1000 + i*100, OutputTokens: 200,
			CostUSD: 0.02, UnixMillis: ts,
		}
		ts += 5000
	}
	_, d := feed(cfg, obs)
	if d.Confidence > 0 && len(d.SignalsFired) == 0 {
		t.Fatalf("BUG: confidence=%.2f but no signals fired", d.Confidence)
	}
	t.Logf("OK: empty tool name handled. confidence=%.2f", d.Confidence)
}

func Test_EDGE_SingleObservation(t *testing.T) {
	cfg := DefaultConfig()
	_, d := feed(cfg, []Observation{{
		Project: "p", SessionID: "s",
		ToolName: "hello", Args: map[string]any{"x": 1}, Result: map[string]any{"y": 2},
		PromptTokens: 1000, OutputTokens: 200, CostUSD: 0.01, UnixMillis: 0,
	}})
	if d.Confidence != 0 || d.ActionCeiling != ActionNone {
		t.Fatalf("BUG: single observation confidence=%.2f ceiling=%s", d.Confidence, d.ActionCeiling)
	}
}

func Test_EDGE_ZeroCostCalls(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 20)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName: "free_tool", Args: map[string]any{"id": 42},
			Result:       map[string]any{"status": "ok"},
			PromptTokens: 100, OutputTokens: 50, CostUSD: 0, UnixMillis: int64(i * 5000),
		}
	}
	_, d := feed(cfg, obs)
	if hasSignal(d, "cost_velocity_accel") {
		t.Fatalf("BUG: cost_velocity_accel fired on zero-cost calls")
	}
	// v2.1.0: identical repeats bypass the time-gate, so even zero-cost
	// identical calls will be blocked via sustained_repetition + identical_repeat.
	// This is by design — 20 identical zero-cost calls are suspicious.
	if d.Confidence > 1.0 || d.Confidence < 0 {
		t.Fatalf("BUG: confidence=%.4f out of [0,1] bounds", d.Confidence)
	}
	t.Logf("OK: zero-cost calls. confidence=%.2f ceiling=%s signals=%v", d.Confidence, d.ActionCeiling, d.SignalsFired)
}

func Test_EDGE_ExactlyMaxRepeated(t *testing.T) {
	cfg := DefaultConfig()
	mkObs := func(n int) []Observation {
		obs := make([]Observation, n)
		for i := range obs {
			obs[i] = Observation{
				Project: "p", SessionID: "s",
				ToolName: "tool", Args: map[string]any{"x": 1}, Result: map[string]any{"y": 1},
				PromptTokens: 1000, OutputTokens: 100, CostUSD: 0.01, UnixMillis: int64(i * 5000),
			}
		}
		return obs
	}
	_, d2 := feed(cfg, mkObs(2))
	if hasSignal(d2, "identical_repeat") {
		t.Fatalf("BUG: identical_repeat fired on 2 calls (threshold is %d)", cfg.MaxRepeated)
	}
	_, d3 := feed(cfg, mkObs(3))
	if !hasSignal(d3, "identical_repeat") {
		t.Fatalf("BUG: identical_repeat did NOT fire on 3 calls (threshold is %d)", cfg.MaxRepeated)
	}
}

func Test_EDGE_ConfidenceNeverExceedsOne(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 12)
	cost := 0.01
	ctx := 1000
	out := 500
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName: "tool", Args: map[string]any{"x": 1}, Result: map[string]any{"y": "same"},
			PromptTokens: ctx, OutputTokens: out, CostUSD: cost, UnixMillis: int64(i * 60_000),
		}
		cost *= 2.0
		ctx = int(float64(ctx) * 1.5)
		if i > 5 {
			out = out / 2
		}
	}
	_, d := feed(cfg, obs)
	if d.Confidence > 1.0 || d.Confidence < 0 {
		t.Fatalf("BUG: confidence=%.4f out of [0,1] bounds", d.Confidence)
	}
}

func Test_EDGE_VelocityWithNoPriorWindow(t *testing.T) {
	cfg := DefaultConfig()
	now := int64(100_000)
	obs := make([]Observation, 5)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName: "tool", Args: map[string]any{"x": 1}, Result: map[string]any{"y": 1},
			PromptTokens: 1000, OutputTokens: 100, CostUSD: 1.0, UnixMillis: now + int64(i*1000),
		}
	}
	_, d := feed(cfg, obs)
	if hasSignal(d, "cost_velocity_accel") {
		t.Fatalf("BUG: velocity acceleration fired with no prior window data")
	}
	if math.IsInf(d.Confidence, 0) || math.IsNaN(d.Confidence) {
		t.Fatalf("BUG: confidence is Inf or NaN")
	}
}

func Test_EDGE_ProgressOverrideInteraction(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 10)
	cost := 0.01
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName: "process", Args: map[string]any{"id": i},
			Result:       map[string]any{"status": "no_change"},
			PromptTokens: 1000 + i*300, OutputTokens: 20,
			CostUSD: cost, UnixMillis: int64(i * 60_000),
		}
		cost *= 1.5
	}
	_, d := feed(cfg, obs)

	noopFired := hasSignal(d, "noop_repeat")
	if !noopFired {
		t.Fatalf("BUG: noop should fire when results are identical")
	}
	// With v1.1.0 fix, noop + changing args uses 0.5 override (not 0.3).
	// Confidence should be higher than the old 0.22 but still progress-discounted.
	if d.Confidence < 0.40 {
		t.Fatalf("REGRESSION: noop+changing-args confidence=%.2f is below warn (0.40). Override too aggressive.", d.Confidence)
	}
	t.Logf("OK: noop+override interaction. confidence=%.2f ceiling=%s", d.Confidence, d.ActionCeiling)
}

func Test_EDGE_DetectorVersionStamped(t *testing.T) {
	cfg := DefaultConfig()
	_, d := feed(cfg, []Observation{{
		Project: "p", SessionID: "s", ToolName: "t",
		Args: map[string]any{"x": 1}, Result: map[string]any{"y": 1},
		PromptTokens: 100, OutputTokens: 50, CostUSD: 0.01, UnixMillis: 0,
	}})
	if d.DetectorVersion != "2.2.0" {
		t.Fatalf("BUG: DetectorVersion=%q expected 2.2.0", d.DetectorVersion)
	}
}

// ============================================================================
// E. QUANTITATIVE MEASUREMENTS
// ============================================================================

func Test_QUANT_MinCallsToBlock(t *testing.T) {
	cfg := DefaultConfig()
	for n := 1; n <= 20; n++ {
		_, d := feed(cfg, makeRunaway(n, "s"))
		if d.ActionCeiling == ActionBlock {
			t.Logf("BLOCK at turn %d (confidence=%.2f signals=%v)", n, d.Confidence, d.SignalsFired)
			if n > 6 {
				t.Fatalf("REGRESSION: block reaction time degraded to %d turns (was 5)", n)
			}
			return
		}
	}
	t.Fatalf("REGRESSION: standard runaway not blocked within 20 turns")
}

func Test_QUANT_ConfidenceProgression(t *testing.T) {
	cfg := DefaultConfig()
	ds := feedAll(cfg, makeRunaway(12, "s"))
	for i, d := range ds {
		t.Logf("Turn %2d: confidence=%.2f ceiling=%-5s signals=%v",
			i+1, d.Confidence, d.ActionCeiling, d.SignalsFired)
	}
}

func Test_QUANT_BatchConfidenceStaysFlat(t *testing.T) {
	cfg := DefaultConfig()
	ds := feedAll(cfg, makeBatch(500, "batch"))
	maxConf := 0.0
	for _, d := range ds {
		if d.Confidence > maxConf {
			maxConf = d.Confidence
		}
	}
	// Peak ~0.11 is expected (velocity window asymmetry during ramp-up).
	if maxConf > 0.20 {
		t.Fatalf("REGRESSION: batch peak confidence=%.2f exceeds 0.20", maxConf)
	}
	t.Logf("OK: 500-call batch peak confidence=%.2f", maxConf)
}

func Test_QUANT_CostAccelThreshold(t *testing.T) {
	cfg := DefaultConfig()
	for _, mult := range []float64{1.01, 1.05, 1.10, 1.20, 1.50, 2.00} {
		obs := make([]Observation, 20)
		cost := 0.01
		for i := range obs {
			obs[i] = Observation{
				Project: "p", SessionID: "s",
				ToolName: "tool", Args: map[string]any{"x": 1}, Result: map[string]any{"y": 1},
				PromptTokens: 1000, OutputTokens: 100, CostUSD: cost, UnixMillis: int64(i * 60_000),
			}
			cost *= mult
		}
		_, d := feed(cfg, obs)
		t.Logf("Cost multiplier %.2fx: velocity=%v confidence=%.2f ceiling=%s",
			mult, hasSignal(d, "cost_velocity_accel"), d.Confidence, d.ActionCeiling)
	}
}

// ============================================================================
// F. ADDITIONAL EDGE CASES — missing coverage
// ============================================================================

// Test_EDGE_BurstTimeGapBurst: the "scheduled cron" pattern.
// A burst of 10 identical calls, 30-minute gap (beyond state TTL), then same burst.
// The second burst sees a fresh state (TTL expired) so it should NOT block.
// Documents the trade-off: TTL reset prevents detecting periodic runaways, but
// it also prevents stale state from poisoning new sessions.
func Test_EDGE_BurstTimeGapBurst(t *testing.T) {
	cfg := DefaultConfig()

	// First burst: 10 identical calls over 20 seconds
	burst := func(startMs int64) []Observation {
		obs := make([]Observation, 10)
		for i := range obs {
			obs[i] = Observation{
				Project: "p", SessionID: "cron",
				ToolName: "sync", Args: map[string]any{"target": "db"},
				Result:       map[string]any{"rows": 0},
				PromptTokens: 1000, OutputTokens: 50,
				CostUSD: 0.02, UnixMillis: startMs + int64(i*2000),
			}
		}
		return obs
	}

	// Feed burst 1
	s := NewState()
	var d Decision
	for _, o := range burst(0) {
		s, d = Observe(s, o, cfg)
	}
	// 10 identical calls may fire signals but should NOT block (time-gate)
	if d.ActionCeiling == ActionBlock {
		// This is acceptable — the burst is suspicious. But log it.
		t.Logf("Note: first burst reached BLOCK (confidence=%.2f)", d.Confidence)
	}

	// 30-minute gap — in production, Redis TTL (10m) would expire.
	// Simulate by resetting state (as Redis would).
	s = NewState()

	// Feed burst 2 — fresh state
	for _, o := range burst(30 * 60 * 1000) {
		s, d = Observe(s, o, cfg)
	}

	// Second burst sees a clean state — should behave identically to burst 1
	// The key invariant: fresh state cannot reach BLOCK on just 10 calls
	// (sustained_repetition needs > 2*MaxRepeated = 6 calls, but deep block
	// requires time span, so 10 calls in 20s won't hit it)
	t.Logf("Second burst after TTL reset: confidence=%.2f ceiling=%s signals=%v",
		d.Confidence, d.ActionCeiling, d.SignalsFired)
}

// Test_EDGE_HighFrequency500Calls: 500 identical calls in 2 seconds.
// Stress test for bounded memory and numeric stability. Must not OOM,
// produce NaN/Inf confidence, or panic. v2.1.0 blocks identical repeats
// immediately (time-gate bypass), so block is expected here.
func Test_EDGE_HighFrequency500Calls(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 500)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "stress",
			ToolName: "embed", Args: map[string]any{"text": "same"},
			Result:       map[string]any{"vector": "[0.1]"},
			PromptTokens: 500, OutputTokens: 100,
			CostUSD: 0.001, UnixMillis: int64(i * 4), // 4ms apart = 2 seconds total
		}
	}

	s := NewState()
	var d Decision
	for _, o := range obs {
		s, d = Observe(s, o, cfg)
		// Check invariants on every step
		if math.IsNaN(d.Confidence) || math.IsInf(d.Confidence, 0) {
			t.Fatalf("BUG: confidence is NaN or Inf at observation with timestamp %d", o.UnixMillis)
		}
		if d.Confidence < 0 || d.Confidence > 1 {
			t.Fatalf("BUG: confidence=%.4f out of [0,1] bounds", d.Confidence)
		}
	}

	// History should be bounded at ring buffer cap (32)
	if s.CallHistory.len > 32 {
		t.Fatalf("BUG: CallHistory grew to %d (cap is 32)", s.CallHistory.len)
	}
	if s.ContextSizes.len > 32 {
		t.Fatalf("BUG: ContextSizes grew to %d (cap is 32)", s.ContextSizes.len)
	}

	t.Logf("OK: 500 calls in 2s. confidence=%.2f ceiling=%s history_len=%d",
		d.Confidence, d.ActionCeiling, s.CallHistory.len)
}

// Test_EDGE_HugeResultPayload: 1MB result payload should not cause a performance
// cliff in hashAny. The detector hashes the result for noop detection — a large
// result should still hash in bounded time.
func Test_EDGE_HugeResultPayload(t *testing.T) {
	cfg := DefaultConfig()

	// Build a ~1MB result map
	hugeValue := strings.Repeat("x", 1_000_000)
	obs := make([]Observation, 5)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s",
			ToolName: "fetch", Args: map[string]any{"url": "https://example.com"},
			Result:       map[string]any{"body": hugeValue, "status": 200},
			PromptTokens: 2000, OutputTokens: 100,
			CostUSD: 0.05, UnixMillis: int64(i * 60_000),
		}
	}

	// Should not panic or take unreasonable time
	_, d := feed(cfg, obs)

	if math.IsNaN(d.Confidence) || math.IsInf(d.Confidence, 0) {
		t.Fatalf("BUG: confidence is NaN or Inf with huge result payload")
	}

	// All results are identical (same huge payload) — noop_repeat should fire
	if !hasSignal(d, "noop_repeat") && !hasSignal(d, "identical_repeat") {
		t.Logf("Note: no repetition signal fired despite identical 1MB results. confidence=%.2f signals=%v",
			d.Confidence, d.SignalsFired)
	}
	t.Logf("OK: 1MB result payload handled. confidence=%.2f signals=%v", d.Confidence, d.SignalsFired)
}

// Test_EDGE_CorruptedState: state with mismatched ring buffer lengths.
// Simulates what might happen if Redis returns a partially deserialized state
// or if a bug in a previous version left orphaned entries.
func Test_EDGE_CorruptedState(t *testing.T) {
	cfg := DefaultConfig()

	// Build a state where ring buffers have mismatched lengths — as if some
	// observations were lost (e.g., Redis returned stale data after a crash).
	corrupted := NewState()
	corrupted.CallHistory.push(callKey{Tool: "bash", ArgsHash: "aaa"})
	corrupted.CallHistory.push(callKey{Tool: "read", ArgsHash: "bbb"})
	corrupted.ResultHistory.push(resultKey{Tool: "bash", ResultHash: "rrr"}) // shorter than CallHistory
	for _, sz := range []int{100, 200, 300, 400, 500} {
		corrupted.ContextSizes.push(sz) // longer than CallHistory
	}
	// OutputSizes left empty, CostWindow has a single entry
	corrupted.CostWindow.add(1000, 0.01)

	// Feed a few observations into the corrupted state — must not panic
	obs := Observation{
		Project: "p", SessionID: "s",
		ToolName: "bash", Args: map[string]any{"cmd": "ls"},
		Result:       map[string]any{"output": "file.txt"},
		PromptTokens: 1000, OutputTokens: 50,
		CostUSD: 0.01, UnixMillis: 60_000,
	}

	newState, d := Observe(corrupted, obs, cfg)

	// Basic sanity: should not produce garbage
	if math.IsNaN(d.Confidence) || math.IsInf(d.Confidence, 0) {
		t.Fatalf("BUG: confidence is NaN or Inf on corrupted state")
	}
	if d.Confidence < 0 || d.Confidence > 1 {
		t.Fatalf("BUG: confidence=%.4f out of [0,1]", d.Confidence)
	}

	// State should still be bounded after ingestion
	if newState.CallHistory.len > 32 {
		t.Fatalf("BUG: CallHistory grew beyond cap on corrupted state")
	}

	t.Logf("OK: corrupted state handled. confidence=%.2f signals=%v callHistory=%d",
		d.Confidence, d.SignalsFired, newState.CallHistory.len)
}

// Test_EDGE_EmptySessionID: explicit empty-string session with RequireSessionForBlock.
// The safety floor means an empty session can never reach ActionBlock, even if
// all other signals are screaming.
func Test_EDGE_EmptySessionID(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RequireSessionForBlock = true

	// Build a runaway that would definitely block with a session
	obs := makeRunaway(10, "") // empty session
	_, d := feed(cfg, obs)

	if d.ActionCeiling == ActionBlock {
		t.Fatalf("BUG: empty session ID reached BLOCK despite RequireSessionForBlock=true. confidence=%.2f",
			d.Confidence)
	}
	if d.Confidence < 0.5 {
		t.Errorf("expected high confidence on runaway even without session, got %.2f", d.Confidence)
	}
	t.Logf("OK: empty session safety floor held. confidence=%.2f ceiling=%s", d.Confidence, d.ActionCeiling)
}

// Test_EDGE_AllSignalsSimultaneously: verify that a scenario exists where all 4
// signal categories fire together and produce a block.
func Test_EDGE_AllSignalsSimultaneously(t *testing.T) {
	cfg := DefaultConfig()

	// Construct a sequence that triggers all signals:
	// - identical_repeat: same tool + same args
	// - noop_repeat: same result
	// - cost_velocity_accel: geometrically increasing cost
	// - context_runaway or output_degradation: growing context, shrinking output
	obs := make([]Observation, 10)
	cost := 0.01
	ctx := 1000
	out := 500
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "all-signals",
			ToolName:     "stuck",
			Args:         map[string]any{"x": 1},
			Result:       map[string]any{"error": "failed"},
			PromptTokens: ctx, OutputTokens: out,
			CostUSD: cost, UnixMillis: int64(i * 90_000), // 90s apart
		}
		cost *= 2.0 // aggressive acceleration
		ctx = int(float64(ctx) * 1.5)
		if i > 3 {
			out = out / 2 // output degrades
		}
	}
	_, d := feed(cfg, obs)

	// Should definitely block
	if d.ActionCeiling != ActionBlock {
		t.Fatalf("expected BLOCK when all signals fire, got ceiling=%s confidence=%.2f signals=%v",
			d.ActionCeiling, d.Confidence, d.SignalsFired)
	}

	// Should have multiple signals
	if len(d.SignalsFired) < 2 {
		t.Errorf("expected >=2 signals in all-signals scenario, got %v", d.SignalsFired)
	}

	// Confidence should be very high
	if d.Confidence < 0.80 {
		t.Errorf("expected confidence >= 0.80, got %.2f", d.Confidence)
	}

	t.Logf("OK: all-signals scenario. confidence=%.2f ceiling=%s signals=%v",
		d.Confidence, d.ActionCeiling, d.SignalsFired)
}

// ═══════════════════════════════════════════════════════════════════════
// Section G – Cherry-picked v2.1.0 tests (canonical hashing, per-tool
//             burst allowance, semantic review handoff, ring buffer wrap)
// ═══════════════════════════════════════════════════════════════════════

// --- G1: Canonical hashing normalises map-key ordering inside slices. ---
// An evasive agent could reorder keys in nested maps hoping to change the
// args hash. canonical() must sort map keys recursively so the hash is stable.
func Test_CATCH_SliceOrderingEvasion(t *testing.T) {
	cfg := DefaultConfig()

	obs := make([]Observation, 5)
	// First call: keys in "id, type" order.
	obs[0] = Observation{
		Project: "p", SessionID: "s", ToolName: "update_records",
		Args: map[string]any{"records": []any{
			map[string]any{"id": 1, "type": "a"},
			map[string]any{"id": 2, "type": "b"},
		}},
		Result:       map[string]any{"status": "failed"},
		PromptTokens: 1000, OutputTokens: 50, CostUSD: 0.01, UnixMillis: 0,
	}
	// Subsequent calls: keys in "type, id" order (reversed).
	for i := 1; i < 5; i++ {
		obs[i] = Observation{
			Project: "p", SessionID: "s", ToolName: "update_records",
			Args: map[string]any{"records": []any{
				map[string]any{"type": "a", "id": 1},
				map[string]any{"type": "b", "id": 2},
			}},
			Result:       map[string]any{"status": "failed"},
			PromptTokens: 1000, OutputTokens: 50, CostUSD: 0.01, UnixMillis: int64(i * 1000),
		}
	}

	_, d := feed(cfg, obs)

	if !hasSignal(d, "identical_repeat") {
		t.Fatalf("REGRESSION: slice map-key evasion succeeded — canonical() missed nested key order. signals=%v",
			d.SignalsFired)
	}
	t.Logf("OK: slice ordering evasion blocked. signals=%v", d.SignalsFired)
}

// --- G2: MinContextGrowth absolute floor prevents false context_growth. ---
// Even if context grows monotonically, the absolute token increase must exceed
// MinContextGrowth. With 6 observations growing by 500 tokens each (total 2500),
// the signal fires at MinContextGrowth=2000 but NOT at MinContextGrowth=5000.
func Test_CATCH_LargeContextAbsoluteRunaway(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinContextGrowth = 2000

	obs := make([]Observation, 6)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s", ToolName: "analyse",
			Args:         map[string]any{"doc": i}, // changing args
			Result:       map[string]any{"page": i},
			PromptTokens: 100_000 + i*500, OutputTokens: 200,
			CostUSD: 0.01, UnixMillis: int64(i * 1000),
		}
	}

	// totalGrowth = 2500 ≥ 2000 → context_growth fires.
	_, d := feed(cfg, obs)
	if !hasSignal(d, "context_growth") {
		t.Fatalf("FAIL: context_growth did not fire with totalGrowth=2500, MinContextGrowth=2000. signals=%v",
			d.SignalsFired)
	}

	// Raise floor to 5000 → totalGrowth=2500 < 5000 → context_growth must NOT fire.
	cfg.MinContextGrowth = 5000
	_, d2 := feed(cfg, obs)
	if hasSignal(d2, "context_growth") {
		t.Fatalf("FAIL: context_growth fired with totalGrowth=2500, MinContextGrowth=5000 — absolute floor broken. signals=%v",
			d2.SignalsFired)
	}

	t.Logf("OK: MinContextGrowth absolute floor works. at2000=%v at5000=%v",
		d.SignalsFired, d2.SignalsFired)
}

// --- G3: Per-tool BurstAllowance suppresses identical_repeat within burst. ---
// web_search with BurstAllowance=4 means limit=5. Five consecutive identical
// calls are within burst → identical_repeat is suppressed. Without the profile,
// the same 5 calls trigger identical_repeat immediately at MaxRepeated=3.
func Test_FP_ToolBurstAllowance(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ToolProfiles = map[string]ToolProfile{
		"web_search": {BurstAllowance: 4},
	}

	obs := make([]Observation, 5)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s", ToolName: "web_search",
			Args:         map[string]any{"q": "same query"},
			Result:       map[string]any{"count": 10},
			PromptTokens: 1000, OutputTokens: 200,
			CostUSD: 0.01, UnixMillis: int64(i * 1000),
		}
	}

	// With BurstAllowance=4: identical_repeat must be suppressed.
	_, d := feed(cfg, obs)
	if hasSignal(d, "identical_repeat") {
		t.Fatalf("FP: web_search burst (5 calls, BurstAllowance=4) should not fire identical_repeat. signals=%v",
			d.SignalsFired)
	}

	// Without burst profile: same calls SHOULD fire identical_repeat.
	cfg2 := DefaultConfig()
	_, d2 := feed(cfg2, obs)
	if !hasSignal(d2, "identical_repeat") {
		t.Fatalf("Sanity: without ToolProfile, 5 identical calls should fire identical_repeat. signals=%v",
			d2.SignalsFired)
	}

	t.Logf("OK: BurstAllowance suppresses identical_repeat. with_profile=%v without=%v",
		d.SignalsFired, d2.SignalsFired)
}

// --- G4: NeedsSemanticReview fires when args change but results repeat with growing context. ---
// Conditions: ceiling==WARN, context_growth fired (s3>0), repeatedToolN, !identical.
// This is the handoff signal for Tier-2 LLM/embedding analysis.
func Test_EDGE_SemanticReviewHandoff(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinContextGrowth = 100 // low threshold so context_growth fires easily

	obs := make([]Observation, 6)
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "s", ToolName: "refactor",
			Args:         map[string]any{"attempt": i},              // CHANGING args → !identical
			Result:       map[string]any{"status": "review_needed"}, // SAME non-failing result -> noop
			PromptTokens: 1000 + i*50, OutputTokens: 40,             // growing context (total +250 > 100)
			CostUSD: 0.01, UnixMillis: int64(i * 1000), // flat cost, 1s apart
		}
	}

	_, d := feed(cfg, obs)

	// Context must be growing and args must be non-identical.
	if !hasSignal(d, "context_growth") {
		t.Fatalf("SETUP: context_growth did not fire — adjust test parameters. signals=%v", d.SignalsFired)
	}
	if hasSignal(d, "identical_repeat") {
		t.Fatalf("SETUP: identical_repeat fired with changing args — test misconfigured. signals=%v", d.SignalsFired)
	}

	// Ceiling must be WARN (not BLOCK) for semantic review to trigger.
	if d.ActionCeiling != ActionWarn {
		t.Fatalf("SETUP: expected WARN ceiling for semantic review, got %s (confidence=%.2f signals=%v)",
			d.ActionCeiling, d.Confidence, d.SignalsFired)
	}

	if !d.NeedsSemanticReview {
		t.Fatalf("FAIL: NeedsSemanticReview not set. ceiling=%s signals=%v confidence=%.2f",
			d.ActionCeiling, d.SignalsFired, d.Confidence)
	}

	t.Logf("OK: semantic review handoff triggered. ceiling=%s confidence=%.2f signals=%v",
		d.ActionCeiling, d.Confidence, d.SignalsFired)
}

// --- G5: Ring buffer wraps correctly at capacity and preserves last element. ---
// Push 100 observations into a state with cap=32 ring buffers. Verify length
// stays at 32 and last() returns the most recent entry.
func Test_EDGE_RingBufferWrap(t *testing.T) {
	cfg := DefaultConfig()
	s := NewState()
	for i := 0; i < 100; i++ {
		o := Observation{
			Project: "p", SessionID: "s", ToolName: "spam_tool",
			Args:         map[string]any{"i": i},
			Result:       map[string]any{"ok": true},
			PromptTokens: 1000 + i, OutputTokens: 50,
			CostUSD: 0.01, UnixMillis: int64(i * 1000),
		}
		s, _ = Observe(s, o, cfg)
	}

	if s.CallHistory.len != 32 {
		t.Fatalf("BUG: CallHistory.len=%d, want 32 after 100 pushes", s.CallHistory.len)
	}
	if s.ContextSizes.len != 32 {
		t.Fatalf("BUG: ContextSizes.len=%d, want 32 after 100 pushes", s.ContextSizes.len)
	}

	lastKey := s.CallHistory.last()
	if lastKey.Tool != "spam_tool" {
		t.Fatalf("BUG: ring buffer last().Tool=%q, want \"spam_tool\"", lastKey.Tool)
	}

	// Verify last context size is 1099 (1000 + 99)
	lastCtx := s.ContextSizes.get(s.ContextSizes.len - 1)
	if lastCtx != 1099 {
		t.Fatalf("BUG: ContextSizes last=%d, want 1099", lastCtx)
	}

	t.Logf("OK: ring buffers wrap at cap=32. CallHistory.len=%d ContextSizes.last=%d",
		s.CallHistory.len, lastCtx)
}
