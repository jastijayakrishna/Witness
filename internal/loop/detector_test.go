package loop

import "testing"

// feed runs a sequence of observations through a fresh state and returns the final decision.
func feed(cfg Config, obs []Observation) (State, Decision) {
	s := NewState()
	var d Decision
	for _, o := range obs {
		s, d = Observe(s, o, cfg)
	}
	return s, d
}

// feedAll runs a sequence and returns ALL decisions (one per observation).
func feedAll(cfg Config, obs []Observation) []Decision {
	s := NewState()
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

// --- Decide returns the same verdict as Observe without mutating state. ---
func TestDecideMatchesObserve(t *testing.T) {
	cfg := DefaultConfig()
	obs := makeRunaway(8, "decide-test")

	// Build up state with 7 observations
	s := NewState()
	for _, o := range obs[:7] {
		s, _ = Observe(s, o, cfg)
	}

	// 8th observation: compare Decide (read-only) vs Observe
	last := obs[7]
	decideResult := Decide(s, last, cfg)
	_, observeResult := Observe(s, last, cfg)

	if decideResult.Confidence != observeResult.Confidence {
		t.Fatalf("Decide confidence=%.4f != Observe confidence=%.4f", decideResult.Confidence, observeResult.Confidence)
	}
	if decideResult.ActionCeiling != observeResult.ActionCeiling {
		t.Fatalf("Decide ceiling=%s != Observe ceiling=%s", decideResult.ActionCeiling, observeResult.ActionCeiling)
	}
	if len(decideResult.SignalsFired) != len(observeResult.SignalsFired) {
		t.Fatalf("Decide signals=%v != Observe signals=%v", decideResult.SignalsFired, observeResult.SignalsFired)
	}
	t.Logf("OK: Decide matches Observe. confidence=%.2f ceiling=%s", decideResult.Confidence, decideResult.ActionCeiling)
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

// --- Flat-cost runaway blocked via pre-request empty-observation gate. ---
// This is the proof that checkLoop (pre-request, empty obs) correctly blocks
// turn N+1 of a flat-cost runaway via sustained_repetition + deepQualifies.
func TestFlatCostRunaway_EmptyObsGateBlocks(t *testing.T) {
	cfg := Config{
		Action:                 "block",
		MaxRepeated:            3,
		VelocityAccelRatio:     1.5,
		VelocityWindowMs:       1_000, // 1s → minSpan = 100ms
		WarnConfidence:         0.40,
		BlockConfidence:        0.70,
		RequireSessionForBlock: true,
	}

	// Build 8 identical flat-cost calls spanning 200ms each (total 1600ms > minSpan=100ms).
	// This simulates 8 observeLoop post-request updates.
	s := NewState()
	t0 := int64(1_000_000) // arbitrary start time
	for i := 0; i < 8; i++ {
		obs := Observation{
			Project:      "p",
			SessionID:    "stuck-session",
			ToolName:     "search",
			Args:         map[string]any{"query": "fix"},       // identical every time
			Result:       map[string]any{"error": "not found"}, // identical result
			PromptTokens: 100, OutputTokens: 10,                // flat
			CostUSD:      0.01,              // flat cost — NO acceleration
			UnixMillis:   t0 + int64(i)*200, // 200ms apart
		}
		s, _ = Observe(s, obs, cfg)
	}

	// Now simulate the pre-request check: empty observation (no tool, no cost).
	// This is exactly what handler.checkLoop does before forwarding the request.
	emptyObs := Observation{
		Project:    "p",
		SessionID:  "stuck-session",
		UnixMillis: t0 + 8*200, // time of the would-be 9th request
	}
	_, decision := Observe(s, emptyObs, cfg)

	// Assert: the empty-obs check reaches BLOCK ceiling
	if decision.ActionCeiling != ActionBlock {
		t.Fatalf("FAIL: flat-cost runaway with empty-obs gate did not reach BLOCK.\n"+
			"  ceiling=%s confidence=%.2f signals=%v reason=%q",
			decision.ActionCeiling, decision.Confidence, decision.SignalsFired, decision.Reason)
	}
	if decision.Confidence < 0.70 {
		t.Fatalf("FAIL: confidence %.2f below block threshold 0.70", decision.Confidence)
	}

	// Verify sustained_repetition fired (this is what makes flat-cost blocking possible)
	hasSustained := false
	for _, sig := range decision.SignalsFired {
		if sig == "sustained_repetition" {
			hasSustained = true
		}
	}
	if !hasSustained {
		t.Fatalf("FAIL: sustained_repetition did not fire. signals=%v", decision.SignalsFired)
	}

	t.Logf("OK: flat-cost runaway blocked by empty-obs gate. confidence=%.2f signals=%v",
		decision.Confidence, decision.SignalsFired)
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