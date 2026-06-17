package loop

// detector_hardreal_test.go — an adversarial, real-world stress harness.
//
// WHY THIS EXISTS
//   The existing detector tests verify patterns the detector was built to catch
//   (you grading your own homework). This file does the opposite: it encodes
//   traffic shapes that occur in the wild and are *designed to be ambiguous* —
//   the legitimate-but-loopy patterns that produce false positives, and the
//   runaways that are deliberately shaped to slip past mechanical detection.
//
//   It is a SCORECARD, not a pass/fail gate. Every scenario declares the
//   *correct* verdict (`want`). The runner replays it through the real Observe()
//   path with a synthetic clock, compares, and prints a confusion matrix with
//   precision / recall / false-positive-rate. Only the handful of
//   non-negotiable scenarios (mustHold=true) hard-fail the build; everything
//   else is reported so you can see — and then close — each gap.
//
// HOW TO USE IT
//   go test ./internal/loop/ -run TestHardRealWorld -v
//   Read the SCORECARD block at the end of the output. FP rows are the ones
//   that get you ripped out in week one. FN rows are missed runaways.
//
// TUNING KNOBS THESE SCENARIOS PRESSURE (all in Config / detector.go):
//   MaxRepeated (3), BlockConfidence (0.70), WarnConfidence (0.40),
//   VelocityAccelRatio (1.5), MinContextGrowth (2000), the S1..S4 weights
//   (0.40/0.35/0.15/0.10), HistoryCap (32 → cycle period ceiling 16),
//   perToolStreakGapMs (30s staleness reset), per-tool BurstAllowance,
//   and the cost_camouflage TotalCost floor (0.05).

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
)

// ---------- scenario model ----------

type hrtKind int

const (
	hrtLegit     hrtKind = iota // must NOT block. block == false positive (the kill metric).
	hrtRunaway                  // SHOULD block by the end. none == missed runaway.
	hrtBlindspot                // a known architectural limit; reported, never fails the build.
)

func (k hrtKind) String() string {
	switch k {
	case hrtLegit:
		return "legit"
	case hrtRunaway:
		return "runaway"
	default:
		return "blindspot"
	}
}

type hrtTurn struct {
	tool   string
	args   any
	result any
	class  string // explicit ResultClass; "" lets the classifier decide
	state  string // StateDeltaHash; "" means the agent reported no progress
	pin    int    // prompt tokens
	out    int    // output tokens
	cost   float64
	gapMs  int64 // wall-clock gap since previous turn; 0 → default 250ms
}

type hrtScenario struct {
	name      string
	kind      hrtKind
	session   string // "" → no X-Session-ID (cannot be blocked under default policy)
	cfg       *Config
	turns     []hrtTurn
	want      Action // the CORRECT verdict
	mustHold  bool   // if true, a wrong verdict fails the build (regression gate)
	rationale string
}

// ---------- turn generators (keep the table compact) ----------

func hrtConst(n int, t hrtTurn) []hrtTurn {
	out := make([]hrtTurn, n)
	for i := range out {
		out[i] = t
	}
	return out
}

// hrtArgDriftFail: same tool, drifting args, SAME failure class, but DISTINCT
// result text each turn (so it is NOT a noop — only same_failure_arg_drift can fire).
func hrtArgDriftFail(n int, tool, class string, cost float64, gapMs int64) []hrtTurn {
	out := make([]hrtTurn, n)
	for i := range out {
		out[i] = hrtTurn{
			tool:   tool,
			args:   map[string]any{"attempt": i, "q": fmt.Sprintf("variant-%d", i)},
			result: fmt.Sprintf("%s for variant-%d (request id %d)", class, i, 9000+i),
			class:  class,
			cost:   cost,
			gapMs:  gapMs,
		}
	}
	return out
}

// hrtBatch: legitimate batch work — same tool, unique args, unique successful results.
func hrtBatch(n int, tool string) []hrtTurn {
	out := make([]hrtTurn, n)
	for i := range out {
		out[i] = hrtTurn{
			tool:   tool,
			args:   map[string]any{"row_id": i},
			result: map[string]any{"row_id": i, "written": true, "etag": fmt.Sprintf("e%d", i*7+3)},
			class:  ResultSuccess,
			state:  fmt.Sprintf("rows-written-%d", i+1), // real progress: state advances every turn
			cost:   0.002,
			gapMs:  120,
		}
	}
	return out
}

// hrtCycle: repeat a fixed sequence of tools `reps` times.
func hrtCycle(tools []string, reps int, class string, progress bool, cost float64) []hrtTurn {
	var out []hrtTurn
	step := 0
	for r := 0; r < reps; r++ {
		for _, tool := range tools {
			t := hrtTurn{
				tool:   tool,
				args:   map[string]any{"k": tool},
				result: fmt.Sprintf("%s:%s", tool, class),
				class:  class,
				cost:   cost,
				gapMs:  300,
			}
			if progress {
				t.state = fmt.Sprintf("s-%d", step)
			}
			out = append(out, t)
			step++
		}
	}
	return out
}

// ---------- scenarios ----------

func hrtScenarios() []hrtScenario {
	burst := DefaultConfig()
	burst.Action = "block"
	burst.ToolProfiles = map[string]ToolProfile{
		"poll_job": {BurstAllowance: 12},
	}

	return []hrtScenario{
		// =========================================================
		// LEGIT — the false-positive killers. Blocking any of these is the
		// thing that gets HubbleOps torn out of a customer in week one.
		// =========================================================
		{
			name:      "legit_batch_500_unique",
			kind:      hrtLegit,
			session:   "s-batch",
			turns:     hrtBatch(500, "crm_upsert"),
			want:      ActionNone,
			mustHold:  true,
			rationale: "Bulk upsert: same tool, unique rows, state advances each turn. Classic batch.",
		},
		{
			name:    "legit_batch_uniform_ok_result",
			kind:    hrtLegit,
			session: "s-batch2",
			// Bulk job where every call legitimately returns the SAME {"ok":true}
			// body, but args differ and state advances. Trips result_homogeneity bait.
			turns: func() []hrtTurn {
				out := make([]hrtTurn, 40)
				for i := range out {
					out[i] = hrtTurn{
						tool: "send_invoice", args: map[string]any{"invoice": i},
						result: map[string]any{"ok": true}, class: ResultSuccess,
						state: fmt.Sprintf("sent-%d", i+1), cost: 0.003, gapMs: 150,
					}
				}
				return out
			}(),
			want:      ActionNone,
			mustHold:  true,
			rationale: "Uniform success body with distinct args + real progress must not read as homogeneity.",
		},
		{
			name:    "legit_retry_then_success",
			kind:    hrtLegit,
			session: "s-retry",
			turns: []hrtTurn{
				{tool: "charge_card", args: map[string]any{"id": "c1"}, result: "timeout talking to gateway", class: ResultTimeout, cost: 0.01, gapMs: 800},
				{tool: "charge_card", args: map[string]any{"id": "c1"}, result: "timeout talking to gateway", class: ResultTimeout, cost: 0.01, gapMs: 1600},
				{tool: "charge_card", args: map[string]any{"id": "c1"}, result: map[string]any{"status": "ok", "charge": "ch_1"}, class: ResultSuccess, state: "charged-c1", cost: 0.01, gapMs: 1200},
			},
			want:      ActionNone,
			mustHold:  true,
			rationale: "Two transient timeouts then success is healthy retry-with-backoff, not a runaway.",
		},
		{
			name:    "legit_react_research_20step",
			kind:    hrtLegit,
			session: "s-react",
			turns: func() []hrtTurn {
				tools := []string{"web_search", "fetch_page", "summarize"}
				out := make([]hrtTurn, 0, 21)
				ctx := 1200
				for i := 0; i < 21; i++ {
					tool := tools[i%len(tools)]
					ctx += 150 // context grows as research accumulates — legitimately
					out = append(out, hrtTurn{
						tool: tool,
						args: map[string]any{"q": fmt.Sprintf("subtopic-%d", i)},
						result: map[string]any{"doc": fmt.Sprintf("finding-%d", i)},
						class: ResultSuccess, state: fmt.Sprintf("notes-%d", i+1),
						pin: ctx, out: 400, cost: 0.012, gapMs: 600,
					})
				}
				return out
			}(),
			want:      ActionNone,
			mustHold:  true,
			rationale: "Long multi-tool ReAct trajectory with growing context but genuine progress.",
		},
		{
			name:    "legit_pagination_cursor",
			kind:    hrtLegit,
			session: "s-page",
			turns: func() []hrtTurn {
				out := make([]hrtTurn, 30)
				for i := range out {
					out[i] = hrtTurn{tool: "list_tickets", args: map[string]any{"cursor": fmt.Sprintf("p%d", i)},
						result: map[string]any{"page": i, "items": 50}, class: ResultSuccess,
						state: fmt.Sprintf("seen-%d", (i+1)*50), cost: 0.004, gapMs: 200}
				}
				return out
			}(),
			want:      ActionNone,
			mustHold:  true,
			rationale: "Cursor pagination: same tool, drifting cursor, advancing state.",
		},
		{
			name:    "legit_search_fetch_alternation",
			kind:    hrtLegit,
			session: "s-alt",
			turns: func() []hrtTurn {
				out := make([]hrtTurn, 0, 16)
				for i := 0; i < 8; i++ {
					out = append(out,
						hrtTurn{tool: "search", args: map[string]any{"q": fmt.Sprintf("q%d", i)}, result: fmt.Sprintf("hits-%d", i), class: ResultSuccess, state: fmt.Sprintf("a-%d", i), cost: 0.005, gapMs: 300},
						hrtTurn{tool: "fetch", args: map[string]any{"url": fmt.Sprintf("u%d", i)}, result: fmt.Sprintf("body-%d", i), class: ResultSuccess, state: fmt.Sprintf("b-%d", i), cost: 0.006, gapMs: 300},
					)
				}
				return out
			}(),
			want:      ActionNone,
			mustHold:  true,
			rationale: "search→fetch alternation with distinct args is the canonical false-positive trap.",
		},
		{
			name:    "legit_high_cost_but_progressing",
			kind:    hrtLegit,
			session: "s-expensive",
			// Cost is high AND rising (bigger context each step), but state advances
			// every turn. The cost-velocity signal must not override real progress.
			turns: func() []hrtTurn {
				out := make([]hrtTurn, 18)
				ctx := 4000
				for i := range out {
					ctx += 1500
					out[i] = hrtTurn{tool: "analyze_doc", args: map[string]any{"chunk": i},
						result: map[string]any{"insight": i}, class: ResultSuccess, state: fmt.Sprintf("analyzed-%d", i+1),
						pin: ctx, out: 900, cost: 0.04 + float64(i)*0.01, gapMs: 40000}
				}
				return out
			}(),
			want:      ActionNone,
			mustHold:  false,
			rationale: "Expensive, accelerating-cost, growing-context work that is genuinely progressing.",
		},
		{
			name:    "legit_polling_pending_then_done",
			kind:    hrtLegit,
			session: "s-poll",
			// THE common one: poll an external job. Same tool, same args, identical
			// "pending" body 9×, then "done". The agent makes no *internal* progress
			// while waiting — which is exactly what a stuck loop looks like.
			turns: append(
				hrtConst(9, hrtTurn{tool: "poll_deploy", args: map[string]any{"id": "d1"},
					result: map[string]any{"status": "pending"}, class: ResultPending, cost: 0.001, gapMs: 5000}),
				hrtTurn{tool: "poll_deploy", args: map[string]any{"id": "d1"},
					result: map[string]any{"status": "ok"}, class: ResultSuccess, state: "deployed", cost: 0.001, gapMs: 5000},
			),
			want:      ActionNone,
			mustHold:  false,
			rationale: "Patient polling of a slow job. Out-of-the-box this likely BLOCKS — a real FP. Mitigation: per-tool BurstAllowance or special-casing 'pending'.",
		},
		{
			name:      "legit_polling_with_burst_allowance",
			kind:      hrtLegit,
			session:   "s-poll2",
			cfg:       &burst,
			turns:     hrtConst(11, hrtTurn{tool: "poll_job", args: map[string]any{"id": "j1"}, result: map[string]any{"status": "pending"}, class: ResultPending, cost: 0.001, gapMs: 4000}),
			want:      ActionNone,
			mustHold:  false,
			rationale: "Same polling with BurstAllowance=12. PROVES the mitigation is broken: isWithinBurstAllowance only engages once there are allowance+1 (13) identical calls in the ring, so an 11-poll burst under a 12 allowance still blocks. Burst allowance does not protect the short legit bursts it exists for.",
		},

		// =========================================================
		// RUNAWAY — recall baseline. These should reach block.
		// =========================================================
		{
			name:      "runaway_exact_repeat",
			kind:      hrtRunaway,
			session:   "s-exact",
			turns:     hrtConst(10, hrtTurn{tool: "get_order", args: map[string]any{"id": "o1"}, result: "not found", class: ResultNotFound, cost: 0.01, gapMs: 200}),
			want:      ActionBlock,
			mustHold:  true,
			rationale: "Identical failing call 10×. The floor case — if this is missed, nothing works.",
		},
		{
			name:      "runaway_same_failure_arg_drift",
			kind:      hrtRunaway,
			session:   "s-drift",
			turns:     hrtArgDriftFail(8, "refund", ResultPermissionError, 0.02, 300),
			want:      ActionBlock,
			mustHold:  true,
			rationale: "Same permission_error while the model keeps rewording args. Your named pattern.",
		},
		{
			name:      "runaway_alternating_stuck",
			kind:      hrtRunaway,
			session:   "s-altstuck",
			turns:     hrtCycle([]string{"plan", "act"}, 6, ResultUnknownError, false, 0.02),
			want:      ActionBlock,
			mustHold:  false,
			rationale: "plan↔act ping-pong, no progress, same error.",
		},
		{
			name:      "runaway_short_cycle_p3",
			kind:      hrtRunaway,
			session:   "s-cyc3",
			turns:     hrtCycle([]string{"a", "b", "c"}, 6, ResultUnknownError, false, 0.02),
			want:      ActionBlock,
			mustHold:  false,
			rationale: "Period-3 cycle within ring/cycle detection range.",
		},

		// =========================================================
		// HARD / EVASION — where 'very hard' lives. These probe the seams I
		// found reading detector.go. Several are expected to currently MISS.
		// =========================================================
		{
			name:    "evasion_fake_progress_state_churn",
			kind:    hrtRunaway,
			session: "s-fake",
			// Genuine runaway: identical failing call. BUT the agent reports a NEW,
			// unique StateDeltaHash every turn (a churning retry counter / log append).
			// stateProgress=true then suppresses noop + homogeneity. This is the most
			// dangerous evasion: trust StateDeltaHash and a loop hides behind fake state.
			turns: func() []hrtTurn {
				out := make([]hrtTurn, 12)
				for i := range out {
					out[i] = hrtTurn{tool: "process", args: map[string]any{"id": "x"},
						result: "permission denied", class: ResultPermissionError,
						state: fmt.Sprintf("retry-counter-%d", i), // unique every turn → fake progress
						cost: 0.03, gapMs: 250}
				}
				return out
			}(),
			want:      ActionBlock,
			mustHold:  false,
			rationale: "Identical failing call hidden behind a state hash that changes every turn. CAUGHT today, but only via cost_camouflage (which ignores state). See evasion_cheap_fake_progress_churn for the variant that defeats it.",
		},
		{
			name:    "evasion_cheap_fake_progress_churn",
			kind:    hrtRunaway,
			session: "s-cheapfake",
			// The combination that actually defeats the detector: identical failing
			// call + a NOVEL state hash every turn (suppresses every state-aware
			// signal) + cost kept under the cost_camouflage floor (0.05). The only
			// signal that ignores state is cost_camouflage, and it needs >$0.05 —
			// so a cheap state-churning loop slips through.
			turns: func() []hrtTurn {
				out := make([]hrtTurn, 16)
				for i := range out {
					out[i] = hrtTurn{tool: "process", args: map[string]any{"id": "x"},
						result: "permission denied", class: ResultPermissionError,
						state: fmt.Sprintf("counter-%d", i), cost: 0.0001, gapMs: 200}
				}
				return out
			}(),
			want:      ActionBlock,
			mustHold:  false,
			rationale: "Cheap + novel-state-every-turn. Expected MISS — the seam: every no-progress signal respects stateProgress, and the one that doesn't (cost_camouflage) needs >$0.05. Fix candidates: cap how many turns unique state can vouch for progress, or add a state-agnostic cheap-repetition signal.",
		},
		{
			name:      "evasion_slow_drip_past_30s_reset",
			kind:      hrtRunaway,
			session:   "s-drip",
			turns:     hrtConst(10, hrtTurn{tool: "ping", args: map[string]any{"id": "p"}, result: "deadline exceeded", class: ResultTimeout, cost: 0.005, gapMs: 31000}),
			want:      ActionBlock,
			mustHold:  false,
			rationale: "Identical failing call every 31s resets per-tool stats (perToolStreakGapMs=30s). Tests whether ring-based signals survive deliberate pacing.",
		},
		{
			name:      "blindspot_long_period_cycle_p20",
			kind:      hrtBlindspot,
			session:   "s-cyc20",
			turns:     hrtCycle([]string{"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "t9", "t10", "t11", "t12", "t13", "t14", "t15", "t16", "t17", "t18", "t19"}, 3, ResultUnknownError, false, 0.02),
			want:      ActionBlock,
			mustHold:  false,
			rationale: "Period-20 macro-loop exceeds cycle ceiling (HistoryCap/2 = 16). Architectural blind spot — fix is a larger ring, not a threshold tweak.",
		},
		{
			name:      "evasion_cheap_infinite_loop",
			kind:      hrtRunaway,
			session:   "s-cheap",
			turns:     hrtConst(40, hrtTurn{tool: "noop_tool", args: map[string]any{"id": "z"}, result: "empty", class: ResultEmpty, cost: 0.0000005, gapMs: 100}),
			want:      ActionBlock,
			mustHold:  false,
			rationale: "Thousands-of-calls-cheap loop stays under the cost_camouflage floor (0.05) and never accelerates. Must be caught by mechanical signals alone.",
		},
		{
			name:    "evasion_sawtooth_context_compaction",
			kind:    hrtRunaway,
			session: "s-saw",
			// Stuck loop whose context is periodically compacted (grow, drop, grow),
			// defeating the monotonic context_growth signal. Calls repeat → must still
			// be caught mechanically.
			turns: func() []hrtTurn {
				out := make([]hrtTurn, 12)
				ctxs := []int{2000, 6000, 2200, 6200, 2400, 6400, 2600, 6600, 2800, 6800, 3000, 7000}
				for i := range out {
					out[i] = hrtTurn{tool: "rethink", args: map[string]any{"id": "r"},
						result: "no such file", class: ResultNotFound, pin: ctxs[i], out: 300, cost: 0.02, gapMs: 400}
				}
				return out
			}(),
			want:      ActionBlock,
			mustHold:  false,
			rationale: "Context compaction creates a sawtooth that defeats context_growth; repetition must still trip the block.",
		},
		{
			name:      "evasion_no_session_runaway",
			kind:      hrtBlindspot,
			session:   "", // no X-Session-ID
			turns:     hrtConst(12, hrtTurn{tool: "delete_thing", args: map[string]any{"id": "d"}, result: "permission denied", class: ResultPermissionError, cost: 0.03, gapMs: 200}),
			want:      ActionWarn, // by design: RequireSessionForBlock=true caps at warn
			mustHold:  false,
			rationale: "Clear runaway, but omitting the session header makes it immune to block by design. Document: an agent that drops X-Session-ID cannot be hard-stopped.",
		},
		{
			name:      "boundary_arg_drift_at_warn_window",
			kind:      hrtRunaway,
			session:   "s-bound",
			turns:     hrtArgDriftFail(4, "lookup", ResultNotFound, 0.01, 300),
			want:      ActionWarn, // between MaxRepeated(3) and deep(6): single-signal → should warn, not block
			mustHold:  false,
			rationale: "Boundary probe: 4 same-failure-arg-drift calls. Reveals the warn→block escalation point so you can decide if 4 retries deserves a block.",
		},
		{
			name:    "evasion_burst_allowance_abuse",
			kind:    hrtRunaway,
			session: "s-burstabuse",
			cfg: func() *Config {
				c := DefaultConfig()
				c.Action = "block"
				c.ToolProfiles = map[string]ToolProfile{"flaky_tool": {BurstAllowance: 3}}
				return &c
			}(),
			turns:     hrtConst(20, hrtTurn{tool: "flaky_tool", args: map[string]any{"id": "f"}, result: "permission denied", class: ResultPermissionError, cost: 0.03, gapMs: 200}),
			want:      ActionBlock,
			mustHold:  false,
			rationale: "isWithinBurstAllowance suppresses identical whenever the LAST (allowance+1) calls match — which never stops in a long run. Verifies a tool with a burst allowance can still be blocked (via other signals) and surfaces the latent suppression logic.",
		},
		{
			name:    "evasion_two_keys_round_robin",
			kind:    hrtRunaway,
			session: "s-rr",
			// Two failing variants alternated to dodge "identical" while making no
			// progress. Args toggle A,B,A,B; both return the same failure class.
			turns: func() []hrtTurn {
				out := make([]hrtTurn, 12)
				for i := range out {
					key := "A"
					if i%2 == 1 {
						key = "B"
					}
					out[i] = hrtTurn{tool: "fetch", args: map[string]any{"key": key},
						result: "deadline exceeded " + key, class: ResultTimeout, cost: 0.02, gapMs: 300}
				}
				return out
			}(),
			want:      ActionBlock,
			mustHold:  false,
			rationale: "Two-value round-robin of the same failure dodges identical-repeat; alternating + same-failure should still catch it.",
		},
	}
}

// ---------- runner ----------
//
// Production semantics: a proxy enforces the STRONGEST action reached across the
// stream, because the first block halts the agent — later turns never execute.
// So we score on max-action-across-the-stream, not the final turn. (An earlier
// version of this harness scored only the final turn and that HID the polling
// false positive, because the trailing "success" turn relaxed the verdict.)

func hrtRank(a Action) int {
	switch a {
	case ActionWarn:
		return 1
	case ActionBlock:
		return 2
	default:
		return 0
	}
}

type hrtRun struct {
	maxAction Action
	atMax     Decision // decision at the turn that produced maxAction
	final     Decision
	atTurn    int
}

func hrtReplay(scn hrtScenario) hrtRun {
	cfg := DefaultConfig()
	cfg.Action = "block"
	if scn.cfg != nil {
		cfg = *scn.cfg
	}
	st := NewState()
	run := hrtRun{maxAction: ActionNone}
	var clock int64 = 1_700_000_000_000
	for i, tn := range scn.turns {
		gap := tn.gapMs
		if gap == 0 {
			gap = 250
		}
		clock += gap
		obs := Observation{
			Project: "hrt", SessionID: scn.session, ToolName: tn.tool,
			Args: tn.args, Result: tn.result, ResultClass: tn.class,
			StateDeltaHash: tn.state, PromptTokens: tn.pin, OutputTokens: tn.out,
			CostUSD: tn.cost, UnixMillis: clock,
		}
		var dec Decision
		st, dec = Observe(st, obs, cfg)
		run.final = dec
		if hrtRank(dec.ActionCeiling) > hrtRank(run.maxAction) {
			run.maxAction = dec.ActionCeiling
			run.atMax = dec
			run.atTurn = i + 1
		}
	}
	return run
}

type hrtResult struct {
	scn     hrtScenario
	got     Action
	atTurn  int
	verdict string // OK | FALSE_POSITIVE | MISSED_RUNAWAY | NOISE | BLINDSPOT_OK | BLINDSPOT_GAP
	signals []string
	conf    float64
}

func hrtClassify(scn hrtScenario, run hrtRun) hrtResult {
	got := run.maxAction
	r := hrtResult{scn: scn, got: got, atTurn: run.atTurn, signals: run.atMax.SignalsFired, conf: run.atMax.Confidence}
	switch scn.kind {
	case hrtLegit:
		switch got {
		case ActionBlock:
			r.verdict = "FALSE_POSITIVE"
		case ActionWarn:
			r.verdict = "NOISE"
		default:
			r.verdict = "OK"
		}
	case hrtRunaway:
		switch {
		case got == ActionBlock:
			r.verdict = "OK"
		case got == ActionWarn && scn.want == ActionWarn:
			r.verdict = "OK"
		default:
			r.verdict = "MISSED_RUNAWAY"
		}
	case hrtBlindspot:
		if got == scn.want {
			r.verdict = "BLINDSPOT_OK"
		} else {
			r.verdict = "BLINDSPOT_GAP"
		}
	}
	return r
}

func TestHardRealWorld(t *testing.T) {
	scns := hrtScenarios()
	results := make([]hrtResult, 0, len(scns))
	var tp, fp, tn, fn, noise int

	for _, scn := range scns {
		run := hrtReplay(scn)
		r := hrtClassify(scn, run)
		results = append(results, r)

		switch scn.kind {
		case hrtLegit:
			if r.verdict == "FALSE_POSITIVE" {
				fp++
			} else {
				tn++
				if r.verdict == "NOISE" {
					noise++
				}
			}
		case hrtRunaway:
			if r.verdict == "OK" && r.got == ActionBlock {
				tp++
			} else if r.verdict == "OK" && scn.want == ActionWarn {
				// boundary case scored correct; not a runaway block, don't count in TP/FN
			} else {
				fn++
			}
		}

		if scn.mustHold && (r.verdict == "FALSE_POSITIVE" || r.verdict == "MISSED_RUNAWAY") {
			t.Errorf("MUST-HOLD VIOLATED [%s]: want %s, got %s@turn%d (signals=%v) — %s",
				scn.name, scn.want, r.got, r.atTurn, r.signals, scn.rationale)
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		order := map[string]int{"FALSE_POSITIVE": 0, "MISSED_RUNAWAY": 1, "BLINDSPOT_GAP": 2, "NOISE": 3, "BLINDSPOT_OK": 4, "OK": 5}
		return order[results[i].verdict] < order[results[j].verdict]
	})

	var b strings.Builder
	fmt.Fprintf(&b, "\n================ HARD REAL-WORLD SCORECARD (max-action across stream) ================\n")
	fmt.Fprintf(&b, "%-38s %-9s %-6s %-6s %-7s %-16s\n", "scenario", "kind", "want", "got", "@turn", "verdict")
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 100))
	for _, r := range results {
		flag := ""
		if r.scn.mustHold {
			flag = " *"
		}
		at := "-"
		if r.got != ActionNone {
			at = fmt.Sprintf("%d", r.atTurn)
		}
		fmt.Fprintf(&b, "%-38s %-9s %-6s %-6s %-7s %-16s%s\n", r.scn.name, r.scn.kind, r.scn.want, r.got, at, r.verdict, flag)
	}
	fmt.Fprintf(&b, "%s\n", strings.Repeat("-", 100))
	fmt.Fprintf(&b, "runaways:  caught %d / missed %d   (recall %s)\n", tp, fn, pct(tp, tp+fn))
	fmt.Fprintf(&b, "legit:     clean %d / BLOCKED(FP) %d / noisy-warned %d   (FP-rate %s, precision %s)\n", tn, fp, noise, pct(fp, fp+tn), pct(tp, tp+fp))
	fmt.Fprintf(&b, "* = must-hold regression gate.  @turn = first turn that reached the verdict (production halts there).\n")
	fmt.Fprintf(&b, "======================================================================================\n")

	var d strings.Builder
	gaps := 0
	for _, r := range results {
		if r.verdict == "OK" || r.verdict == "BLINDSPOT_OK" {
			continue
		}
		gaps++
		fmt.Fprintf(&d, "  [%s] %s  (got %s @turn %d, conf=%.2f, signals=%s)\n      %s\n",
			r.verdict, r.scn.name, r.got, r.atTurn, r.conf, joinOrDash(r.signals), r.scn.rationale)
	}

	t.Log(b.String())
	if gaps > 0 {
		t.Logf("\n---- GAPS TO IMPROVE (%d) ----\n%s", gaps, d.String())
	}
}

func pct(num, den int) string {
	if den == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", 100*float64(num)/float64(den))
}

func joinOrDash(s []string) string {
	if len(s) == 0 {
		return "-"
	}
	return strings.Join(s, ",")
}

var _ = json.Marshal
