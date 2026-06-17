package loop

import "testing"

func TestFloorRisk(t *testing.T) {
	cases := []struct {
		name           string
		client, floor  string
		want           string
	}{
		{"client downgrades below floor", "read", "write", ActionRiskWrite},
		{"floor below client keeps client", "write", "read", ActionRiskWrite},
		{"no floor keeps client", "read", "", ActionRiskRead},
		{"client above floor kept", "dangerous", "write", ActionRiskDangerous},
		{"empty client floored", "", "dangerous", ActionRiskDangerous},
		{"money_movement client normalizes to write", "money_movement", "", ActionRiskWrite},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := FloorRisk(c.client, c.floor); got != c.want {
				t.Fatalf("FloorRisk(%q,%q)=%q want %q", c.client, c.floor, got, c.want)
			}
		})
	}
}

func TestFailClosedRisk(t *testing.T) {
	for _, r := range []string{"dangerous", "danger", "money_movement", "critical", "destructive", "DANGEROUS"} {
		if !FailClosedRisk(r) {
			t.Fatalf("FailClosedRisk(%q)=false want true", r)
		}
	}
	for _, r := range []string{"read", "write", "customer_visible", "", "low"} {
		if FailClosedRisk(r) {
			t.Fatalf("FailClosedRisk(%q)=true want false", r)
		}
	}
}

// TestPreToolBlocksRepeatedCallBeforeExecution verifies the preventive half of the
// loop detector: at pre_tool the proposed call joins the clone's history so a
// call-based repeat (identical_repeat) can block BEFORE the side effect, while
// result-based signals stay suppressed (there is no result yet).
func TestPreToolBlocksRepeatedCallBeforeExecution(t *testing.T) {
	cfg := DefaultConfig()
	st := NewState()
	args := map[string]any{"invoice": "inv_9"}

	// Two prior identical calls that returned empty (no-progress) results, recorded
	// at /result. After these, one more identical call is the third repeat.
	for i := 0; i < 2; i++ {
		var d Decision
		st, d = Observe(st, Observation{
			Project: "p", SessionID: "s",
			ToolName: "refund_customer", Args: args,
			Result: nil, ResultClass: "",
			DecisionStage: "post_tool",
			UnixMillis:    int64(i+1) * 1000,
		}, cfg)
		_ = d
	}

	// pre_tool decision for the same call (no result yet): the proposed call makes it
	// the third identical call, which a call-based signal should catch preemptively.
	pre := Decide(st, Observation{
		Project: "p", SessionID: "s",
		ToolName: "refund_customer", Args: args,
		DecisionStage: "pre_tool",
		UnixMillis:    3000,
	}, cfg)

	if !hasSignal(pre, "identical_repeat") {
		t.Fatalf("pre_tool should fire identical_repeat (preventive): signals=%v", pre.SignalsFired)
	}
	if hasSignal(pre, "noop_repeat") {
		t.Fatalf("pre_tool must NOT fire result-based noop_repeat on an empty pre-execution result: signals=%v", pre.SignalsFired)
	}
	if hasSignal(pre, "no_state_delta") {
		t.Fatalf("pre_tool must NOT fire result-based no_state_delta: signals=%v", pre.SignalsFired)
	}

	// At post_tool (result known) the same empty-result repeat DOES fire the
	// result-based signal — proving the gate is stage-specific, not a blanket disable.
	post := Decide(st, Observation{
		Project: "p", SessionID: "s",
		ToolName: "refund_customer", Args: args,
		Result: nil, ResultClass: "",
		DecisionStage: "post_tool",
		UnixMillis:    3000,
	}, cfg)
	if !hasSignal(post, "noop_repeat") {
		t.Fatalf("post_tool should fire noop_repeat when results repeat: signals=%v", post.SignalsFired)
	}
}
