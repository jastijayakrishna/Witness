package loop

import "testing"

// feed runs a sequence of observations through a fresh state and returns the final decision.
func feed(cfg Config, obs []Observation) (State, Decision) {
	s := State{}
	var d Decision
	for _, o := range obs {
		s, d = Observe(s, o, cfg)
	}
	return s, d
}

// feedAll runs a sequence and returns ALL decisions (one per observation).
func feedAll(cfg Config, obs []Observation) []Decision {
	s := State{}
	var ds []Decision
	for _, o := range obs {
		var d Decision
		s, d = Observe(s, o, cfg)
		ds = append(ds, d)
	}
	return ds
}

// makeBatch builds a legitimate high-volume job: same tool, CHANGING args, FLAT cost.
func makeBatch(n int, sessionID string) []Observation {
	out := make([]Observation, n)
	t := int64(0)
	for i := 0; i < n; i++ {
		out[i] = Observation{
			Project:      "p", SessionID: sessionID,
			ToolName:     "classify_ticket",
			Args:         map[string]any{"ticket_id": i}, // CHANGES every call -> progress
			Result:       map[string]any{"label": i % 5},
			PromptTokens: 1000, OutputTokens: 200, // steady
			CostUSD:      0.01, UnixMillis: t, // flat cost
		}
		t += 1000
	}
	return out
}

// makeRunaway builds a true runaway: same tool, IDENTICAL args, ACCELERATING cost.
func makeRunaway(n int, sessionID string) []Observation {
	out := make([]Observation, n)
	// Space turns ~90s apart so early turns land in the "prior" 5-min window and
	// later turns in the "recent" window — that's how velocity is measured in reality.
	t := int64(0)
	ctx := 1000
	cost := 0.01
	for i := 0; i < n; i++ {
		out[i] = Observation{
			Project:      "p", SessionID: sessionID,
			ToolName:     "update_record",
			Args:         map[string]any{"id": 42, "payload": "same"}, // IDENTICAL
			Result:       map[string]any{"error": "failed"},           // same failure
			PromptTokens: ctx, OutputTokens: 50, // output stays small
			CostUSD:      cost, UnixMillis: t,
		}
		t += 90_000 // 90 seconds between turns
		ctx = int(float64(ctx) * 1.3) // context compounds
		cost = cost * 1.4              // cost accelerates (geometric)
	}
	return out
}

// makeAlternating builds an A-B-A-B flip-flop loop.
func makeAlternating(n int, sessionID string) []Observation {
	out := make([]Observation, n)
	t := int64(0)
	cost := 0.01
	for i := 0; i < n; i++ {
		tool := "search"
		if i%2 == 1 {
			tool = "edit"
		}
		out[i] = Observation{
			Project:      "p", SessionID: sessionID,
			ToolName:     tool,
			Args:         map[string]any{"x": tool}, // identical per side
			Result:       map[string]any{"r": i},
			PromptTokens: 1000 + i*400, OutputTokens: 60,
			CostUSD:      cost, UnixMillis: t,
		}
		t += 1000
		cost = cost * 1.4
	}
	return out
}

// --- The test that SELLS the product: legitimate batch is NEVER blocked, even with action:block. ---
func TestBatchJobNeverBlocked(t *testing.T) {
	cfg := DefaultConfig()
	_, d := feed(cfg, makeBatch(200, "nightly-batch"))
	if d.ActionCeiling == ActionBlock {
		t.Fatalf("FAIL: legitimate 200-turn batch hit BLOCK ceiling. confidence=%.2f signals=%v",
			d.Confidence, d.SignalsFired)
	}
	if EffectiveAction(ActionBlock, d.ActionCeiling) == ActionBlock {
		t.Fatalf("FAIL: configured block escalated on batch job")
	}
	if d.Confidence > 0.3 {
		t.Fatalf("FAIL: batch confidence %.2f exceeded 0.3 (should stay low)", d.Confidence)
	}
	t.Logf("OK: batch job confidence=%.2f ceiling=%s reason=%q", d.Confidence, d.ActionCeiling, d.Reason)
}

// --- True runaway WITH a session reaches BLOCK. ---
func TestRunawayWithSessionBlocks(t *testing.T) {
	cfg := DefaultConfig()
	_, d := feed(cfg, makeRunaway(8, "2am-fix"))
	if d.ActionCeiling != ActionBlock {
		t.Fatalf("FAIL: runaway did not reach BLOCK. ceiling=%s confidence=%.2f signals=%v reason=%q",
			d.ActionCeiling, d.Confidence, d.SignalsFired, d.Reason)
	}
	if d.Confidence < 0.7 {
		t.Fatalf("FAIL: runaway confidence %.2f below 0.70", d.Confidence)
	}
	t.Logf("OK: runaway confidence=%.2f signals=%v reason=%q", d.Confidence, d.SignalsFired, d.Reason)
}

// --- Same runaway WITHOUT a session can only WARN (safety floor). ---
func TestRunawayNoSessionWarnOnly(t *testing.T) {
	cfg := DefaultConfig()
	_, d := feed(cfg, makeRunaway(8, "")) // no session id
	if d.ActionCeiling == ActionBlock {
		t.Fatalf("FAIL: blocked a sessionless runaway (safety floor breached)")
	}
	if d.ActionCeiling != ActionWarn {
		t.Fatalf("expected WARN ceiling without session, got %s", d.ActionCeiling)
	}
	t.Logf("OK: sessionless runaway capped at WARN. confidence=%.2f", d.Confidence)
}

// --- Alternating loop is detected. ---
func TestAlternatingDetected(t *testing.T) {
	cfg := DefaultConfig()
	_, d := feed(cfg, makeAlternating(10, "flip"))
	found := false
	for _, s := range d.SignalsFired {
		if s == "alternating_repeat" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: alternating loop not detected. signals=%v", d.SignalsFired)
	}
	t.Logf("OK: alternating detected. signals=%v ceiling=%s", d.SignalsFired, d.ActionCeiling)
}

// --- No-op loop (identical results, args drift slightly) is detected. ---
func TestNoopDetected(t *testing.T) {
	cfg := DefaultConfig()
	obs := make([]Observation, 5)
	t0 := int64(0)
	cost := 0.01
	for i := range obs {
		obs[i] = Observation{
			Project: "p", SessionID: "noop",
			ToolName: "save", Args: map[string]any{"attempt": i}, // args drift
			Result:       map[string]any{"status": "noop"}, // IDENTICAL result
			PromptTokens: 1000 + i*500, OutputTokens: 40,
			CostUSD: cost, UnixMillis: t0,
		}
		t0 += 1000
		cost *= 1.4
	}
	_, d := feed(cfg, obs)
	found := false
	for _, s := range d.SignalsFired {
		if s == "noop_repeat" {
			found = true
		}
	}
	if !found {
		t.Fatalf("FAIL: no-op loop not detected. signals=%v", d.SignalsFired)
	}
	t.Logf("OK: no-op detected. signals=%v", d.SignalsFired)
}

// --- Determinism: same trace, same verdict, every time. ---
func TestDeterministic(t *testing.T) {
	cfg := DefaultConfig()
	in := makeRunaway(8, "x")
	_, d1 := feed(cfg, in)
	_, d2 := feed(cfg, in)
	if d1.Confidence != d2.Confidence || d1.ActionCeiling != d2.ActionCeiling {
		t.Fatalf("FAIL: non-deterministic. %v vs %v", d1, d2)
	}
	t.Logf("OK: deterministic. confidence=%.2f", d1.Confidence)
}

// --- A bursty-but-legitimate job (changing args, one cost bump, then flat) stays sub-block. ---
func TestBurstyLegitNotBlocked(t *testing.T) {
	cfg := DefaultConfig()
	obs := makeBatch(30, "bursty")
	// inject a single transient cost bump (a couple of big-but-legit calls), then back to flat
	obs[10].CostUSD = 0.05
	obs[11].CostUSD = 0.05
	_, d := feed(cfg, obs)
	if d.ActionCeiling == ActionBlock {
		t.Fatalf("FAIL: bursty-legit job blocked. confidence=%.2f signals=%v", d.Confidence, d.SignalsFired)
	}
	t.Logf("OK: bursty-legit not blocked. confidence=%.2f ceiling=%s", d.Confidence, d.ActionCeiling)
}