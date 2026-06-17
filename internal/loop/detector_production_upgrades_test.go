package loop

// Tests pinning the three production upgrades beyond the synthetic-corpus gate:
//  A. long-period macro-cycles (the documented period-20 blindspot)
//  B. near-identical argument repetition (paraphrase loops with success results)
//  C. cross-session runaway storms (per-session state evasion)

import (
	"fmt"
	"testing"
)

// --- A: long-period cycles -------------------------------------------------

// A 20-tool macro-loop repeated 3 times was the documented architectural
// blindspot (cycle ceiling 16). It must now block.
func TestLongPeriodCycleBlocked(t *testing.T) {
	var turns []Observation
	ts := int64(0)
	for rep := 0; rep < 3; rep++ {
		for i := 0; i < 20; i++ {
			ts += 3000
			turns = append(turns, Observation{
				Project: "p", SessionID: "cyc20", ToolName: fmt.Sprintf("t%d", i),
				Args:   map[string]any{"x": i},
				Result: map[string]any{"error": "stuck"}, ResultClass: "unknown_error",
				CostUSD: 0.02, UnixMillis: ts,
			})
		}
	}
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst != ActionBlock {
		t.Fatalf("period-20 macro-cycle not blocked; worst=%v signals=%v", worst, keys(signals))
	}
}

// --- B: near-identical argument repetition ----------------------------------

// Paraphrased args (case / whitespace variants of the same call) with varying
// SUCCESSFUL results evade exact-hash repeats. They must at least warn.
func TestNearIdenticalArgsLoopWarns(t *testing.T) {
	base := "find user signup errors last 24h"
	variants := []string{base, "FIND USER SIGNUP ERRORS LAST 24H", base + " ", "  " + base, "Find User Signup Errors Last 24h"}
	var turns []Observation
	ts := int64(0)
	for i := 0; i < 12; i++ {
		ts += 2500
		turns = append(turns, Observation{
			Project: "p", SessionID: "paraphrase", ToolName: "search_docs",
			Args:   map[string]any{"q": variants[i%len(variants)]},
			Result: map[string]any{"hits": i, "ok": true}, ResultClass: "success",
			CostUSD: 0.01, UnixMillis: ts,
		})
	}
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst == ActionNone {
		t.Fatalf("near-identical paraphrase loop fully silent; signals=%v", keys(signals))
	}
	if !signals["near_identical_repeat"] {
		t.Fatalf("expected near_identical_repeat; got %v", keys(signals))
	}
	if worst == ActionBlock {
		t.Fatalf("near-identical repetition alone is soft evidence — must warn, not block; signals=%v", keys(signals))
	}
}

// Genuinely distinct queries must not trip the canonical-args signal.
func TestDistinctQueriesStaySilent(t *testing.T) {
	var turns []Observation
	ts := int64(0)
	for i := 0; i < 12; i++ {
		ts += 2500
		turns = append(turns, Observation{
			Project: "p", SessionID: "research", ToolName: "search_docs",
			Args:   map[string]any{"q": fmt.Sprintf("subtopic %d details", i)},
			Result: map[string]any{"hits": i, "ok": true}, ResultClass: "success",
			CostUSD: 0.01, UnixMillis: ts,
		})
	}
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst != ActionNone {
		t.Fatalf("distinct research queries flagged: worst=%v signals=%v", worst, keys(signals))
	}
}

// --- C: cross-session runaway guard -----------------------------------------

func projectObs(session string, i int, ts int64) Observation {
	return Observation{
		Project: "p", SessionID: session, ToolName: "enqueue_task",
		Args:   map[string]any{"task": "analyze repo"},
		Result: map[string]any{"status": "queued"},
		CostUSD: 0.02, UnixMillis: ts,
	}
}

// The same unkeyed side-effect call hammered across many sessions is invisible
// to per-session state. The project guard must block it.
func TestCrossSessionStormBlocked(t *testing.T) {
	ps := NewProjectState()
	var decision Decision
	ts := int64(0)
	for i := 0; i < 12; i++ {
		ts += 2000
		session := fmt.Sprintf("s-%d", i%4) // 4 distinct sessions
		ps, decision = ObserveProject(ps, projectObs(session, i, ts), ActionRiskWrite)
	}
	if decision.ActionCeiling != ActionBlock {
		t.Fatalf("cross-session storm not blocked: %+v", decision)
	}
	if len(decision.SignalsFired) == 0 || decision.SignalsFired[0] != SignalCrossSessionRepeat {
		t.Fatalf("expected %s, got %v", SignalCrossSessionRepeat, decision.SignalsFired)
	}
}

// Two sessions calling the same tool+args a couple of times each is normal
// concurrent work, not a storm.
func TestCrossSessionFewSessionsAllowed(t *testing.T) {
	ps := NewProjectState()
	var decision Decision
	ts := int64(0)
	for i := 0; i < 4; i++ {
		ts += 2000
		session := fmt.Sprintf("s-%d", i%2)
		ps, decision = ObserveProject(ps, projectObs(session, i, ts), ActionRiskWrite)
		if decision.ActionCeiling == ActionBlock {
			t.Fatalf("two concurrent sessions blocked at call %d: %+v", i+1, decision)
		}
	}
}

// Calls carrying idempotency keys are deliberate keyed work — the firewall
// ledger owns dedup there; the guard must stay out of it.
func TestCrossSessionKeyedWorkExempt(t *testing.T) {
	ps := NewProjectState()
	var decision Decision
	ts := int64(0)
	for i := 0; i < 15; i++ {
		ts += 2000
		obs := projectObs(fmt.Sprintf("s-%d", i%5), i, ts)
		obs.IdempotencyKey = fmt.Sprintf("task-%d", i)
		ps, decision = ObserveProject(ps, obs, ActionRiskWrite)
		if decision.ActionCeiling == ActionBlock {
			t.Fatalf("keyed cross-session batch blocked at call %d: %+v", i+1, decision)
		}
	}
}

// Read calls never engage the guard: hot-key reads across sessions are normal.
func TestCrossSessionReadsExempt(t *testing.T) {
	ps := NewProjectState()
	var decision Decision
	ts := int64(0)
	for i := 0; i < 20; i++ {
		ts += 1000
		ps, decision = ObserveProject(ps, projectObs(fmt.Sprintf("s-%d", i%6), i, ts), ActionRiskRead)
		if decision.ActionCeiling != ActionNone {
			t.Fatalf("read traffic engaged the project guard: %+v", decision)
		}
	}
}

// Old activity outside the window must not accumulate into a storm verdict.
func TestCrossSessionWindowPrunes(t *testing.T) {
	ps := NewProjectState()
	var decision Decision
	ts := int64(0)
	for i := 0; i < 8; i++ {
		ts += 15 * 60 * 1000 // 15 minutes apart — every call falls out of the window
		ps, decision = ObserveProject(ps, projectObs(fmt.Sprintf("s-%d", i), i, ts), ActionRiskWrite)
		if decision.ActionCeiling == ActionBlock {
			t.Fatalf("slow spread-out calls blocked at %d: %+v", i+1, decision)
		}
	}
}
