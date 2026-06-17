package loop

// Tests pinning the detector gaps surfaced by the synthetic corpus scoreboard.
// Each test encodes a behavior PATTERN (not a corpus family) so the fix
// generalizes: backoff retries, scheduled/cron repeats, default polling
// tolerance, uniform-ack batches, and self-triggering call storms.

import (
	"fmt"
	"testing"
)

// replayTurns drives pre_tool Decide + post_tool Observe for each turn, the way
// the proxy does, and returns the worst action seen plus the union of signals.
func replayTurns(t *testing.T, turns []Observation, cfg Config) (Action, map[string]bool) {
	t.Helper()
	state := NewState()
	worst := ActionNone
	signals := map[string]bool{}
	bump := func(d Decision) {
		for _, s := range d.SignalsFired {
			signals[s] = true
		}
		if actionWorse(d.ActionCeiling, worst) {
			worst = d.ActionCeiling
		}
	}
	for _, obs := range turns {
		pre := obs
		pre.DecisionStage = "pre_tool"
		pre.Result = nil
		pre.ResultClass = ""
		pre.StateDeltaHash = ""
		pre.PromptTokens, pre.OutputTokens, pre.CostUSD = 0, 0, 0
		bump(Decide(state, pre, cfg))
		post := obs
		post.DecisionStage = "post_tool"
		var d Decision
		state, d = Observe(state, post, cfg)
		bump(d)
	}
	return worst, signals
}

func actionWorse(a, b Action) bool {
	rank := map[Action]int{ActionNone: 0, ActionWarn: 1, ActionBlock: 2}
	return rank[a] > rank[b]
}

// Exponential-backoff retries (growing gaps, retryable failure, small count,
// then success) are the canonical legitimate retry. Must never block.
func TestBackoffRetryThenSuccessNotBlocked(t *testing.T) {
	var turns []Observation
	ts := int64(10_000)
	gap := int64(1000)
	for i := 0; i < 4; i++ {
		turns = append(turns, Observation{
			Project: "p", SessionID: "backoff", ToolName: "update_record",
			Args:   map[string]any{"id": 9},
			Result: map[string]any{"status_code": 429}, ResultClass: "rate_limited",
			CostUSD: 0.01, UnixMillis: ts,
		})
		ts += gap
		gap *= 2
	}
	turns = append(turns, Observation{
		Project: "p", SessionID: "backoff", ToolName: "update_record",
		Args:   map[string]any{"id": 9},
		Result: map[string]any{"status": "success"}, ResultClass: "success",
		CostUSD: 0.01, UnixMillis: ts,
	})
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst == ActionBlock {
		t.Fatalf("backoff retry blocked; signals=%v", keys(signals))
	}
}

// A runaway that merely *shapes* its gaps like backoff must still be caught
// once it goes deep: growth-shaped suppression is capped, never unbounded.
func TestBackoffShapedRunawayStillBlocked(t *testing.T) {
	var turns []Observation
	ts := int64(10_000)
	gap := int64(500)
	for i := 0; i < 12; i++ {
		turns = append(turns, Observation{
			Project: "p", SessionID: "backoff-evasion", ToolName: "update_record",
			Args:   map[string]any{"id": 9},
			Result: map[string]any{"status_code": 429}, ResultClass: "rate_limited",
			CostUSD: 0.01, UnixMillis: ts,
		})
		ts += gap
		gap = gap * 3 / 2
	}
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst != ActionBlock {
		t.Fatalf("backoff-shaped 12-deep runaway not blocked; worst=%v signals=%v", worst, keys(signals))
	}
}

// An identical successful call repeated on a long-period schedule (cron/health
// check) is scheduled work, not a loop iteration. Must stay fully silent.
func TestScheduledSuccessRepeatStaysSilent(t *testing.T) {
	var turns []Observation
	ts := int64(0)
	for i := 0; i < 12; i++ {
		ts += 1_800_000 // 30 minutes
		turns = append(turns, Observation{
			Project: "p", SessionID: "cron", ToolName: "fetch_url",
			Args:   map[string]any{"endpoint": "/health"},
			Result: map[string]any{"status_code": 200}, ResultClass: "success",
			CostUSD: 0.001, UnixMillis: ts,
		})
	}
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst != ActionNone {
		t.Fatalf("scheduled success repeat flagged: worst=%v signals=%v", worst, keys(signals))
	}
}

// A slow IDENTICAL FAILING call (every 4 minutes) is still a runaway — the
// scheduled-repeat exemption applies only to successful outcomes.
func TestSlowFailingLoopStillBlocked(t *testing.T) {
	var turns []Observation
	ts := int64(0)
	for i := 0; i < 12; i++ {
		ts += 240_000
		turns = append(turns, Observation{
			Project: "p", SessionID: "slow-fail", ToolName: "fetch_url",
			Args:   map[string]any{"endpoint": "/sync", "retry": true},
			Result: map[string]any{"status_code": 500}, ResultClass: "unknown_error",
			CostUSD: 0.01, UnixMillis: ts,
		})
	}
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst != ActionBlock {
		t.Fatalf("slow failing loop not blocked; worst=%v signals=%v", worst, keys(signals))
	}
}

// Unprofiled polling tools get the default polling tolerance: a handful of
// pending results then completion must not block.
func TestUnprofiledPollingWithinDefaultBoundsAllowed(t *testing.T) {
	var turns []Observation
	ts := int64(0)
	for i := 0; i < 7; i++ {
		ts += 8000
		turns = append(turns, Observation{
			Project: "p", SessionID: "poll", ToolName: "poll_job_status",
			Args:   map[string]any{"job_id": "j1"},
			Result: map[string]any{"status": "pending"}, ResultClass: "pending",
			CostUSD: 0.01, UnixMillis: ts,
		})
	}
	ts += 8000
	turns = append(turns, Observation{
		Project: "p", SessionID: "poll", ToolName: "poll_job_status",
		Args:   map[string]any{"job_id": "j1"},
		Result: map[string]any{"status": "succeeded"}, ResultClass: "success",
		CostUSD: 0.01, UnixMillis: ts,
	})
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst == ActionBlock {
		t.Fatalf("bounded opaque polling blocked; signals=%v", keys(signals))
	}
}

// Pending forever is still never a bypass: an unprofiled tool that keeps
// returning pending far past the default bounds must block.
func TestUnboundedPendingStillBlocked(t *testing.T) {
	var turns []Observation
	ts := int64(0)
	for i := 0; i < 30; i++ {
		ts += 4000
		turns = append(turns, Observation{
			Project: "p", SessionID: "pending-abuse", ToolName: "poll_job_status",
			Args:   map[string]any{"job_id": "j2"},
			Result: map[string]any{"status": "pending", "progress": 0}, ResultClass: "pending",
			CostUSD: 0.004, UnixMillis: ts,
		})
	}
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst != ActionBlock {
		t.Fatalf("unbounded pending not blocked; worst=%v signals=%v", worst, keys(signals))
	}
}

// A well-behaved batch writer: distinct args every call, a FRESH idempotency
// key per call (proof of distinct intent), uniform tiny success ack, no state
// hash. Weak evidence — must not even warn.
func TestUniformAckKeyedBatchWriterStaysSilent(t *testing.T) {
	var turns []Observation
	ts := int64(0)
	for i := 0; i < 15; i++ {
		ts += 3000
		turns = append(turns, Observation{
			Project: "p", SessionID: "batch-writer", ToolName: "update_crm",
			Args:   map[string]any{"contact": i, "field": "stage"},
			Result: map[string]any{"status": "success"}, ResultClass: "success",
			IdempotencyKey: fmt.Sprintf("crm-%d", i),
			CostUSD:        0.01, UnixMillis: ts,
		})
	}
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst != ActionNone {
		t.Fatalf("keyed uniform-ack batch flagged: worst=%v signals=%v", worst, keys(signals))
	}
}

// The same uniform-ack batch WITHOUT idempotency keys keeps its warning: there
// is no proof of distinct intent and the agent may be ignoring tool output.
func TestUniformAckUnkeyedBatchStillWarns(t *testing.T) {
	var turns []Observation
	ts := int64(0)
	for i := 0; i < 15; i++ {
		ts += 3000
		turns = append(turns, Observation{
			Project: "p", SessionID: "batch-writer-unkeyed", ToolName: "update_crm",
			Args:   map[string]any{"contact": i, "field": "stage"},
			Result: map[string]any{"status": "success"}, ResultClass: "success",
			CostUSD: 0.01, UnixMillis: ts,
		})
	}
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst != ActionWarn {
		t.Fatalf("unkeyed uniform-ack batch: worst=%v want warn; signals=%v", worst, keys(signals))
	}
}

// The Cloudflare A20 shape: the same exact call fired every second, each
// "succeeding" with a different id, no state hash, no idempotency key on the
// firewall side. Result variance must not hide a deep same-args storm.
func TestSelfTriggerCallStormBlocked(t *testing.T) {
	var turns []Observation
	ts := int64(0)
	for i := 0; i < 20; i++ {
		ts += 1100
		turns = append(turns, Observation{
			Project: "p", SessionID: "alarm-loop", ToolName: "schedule_alarm",
			Args:   map[string]any{"handler": "onStart", "delay_ms": 1000},
			Result: map[string]any{"status": "success", "alarm_id": fmt.Sprintf("a%d", i)},
			ResultClass: "success", CostUSD: 0.0008, UnixMillis: ts,
		})
	}
	worst, signals := replayTurns(t, turns, DefaultConfig())
	if worst != ActionBlock {
		t.Fatalf("self-trigger call storm not blocked; worst=%v signals=%v", worst, keys(signals))
	}
	if !signals["deep_call_repeat"] {
		t.Fatalf("expected deep_call_repeat signal; got %v", keys(signals))
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
