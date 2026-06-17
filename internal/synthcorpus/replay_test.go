package synthcorpus

import (
	"context"
	"testing"

	"github.com/hubbleops/hubbleops/internal/loop"
)

func replayEvents(t *testing.T, events []Event) SessionResult {
	t.Helper()
	res, err := ReplaySession(context.Background(), events, loop.DefaultConfig(), loop.NewMemoryActionStore())
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	return res
}

// Max-action scoring: a block mid-stream must stick as the session verdict even
// if later events cool down to allow. This is the final-turn-scoring bug guard.
func TestReplayVerdictIsMaxAcrossStream(t *testing.T) {
	var events []Event
	for i := 0; i < 8; i++ {
		events = append(events, Event{
			Project: "p", SessionID: "s", ToolName: "update_record",
			Args:    map[string]any{"id": 42},
			Result:  map[string]any{"error": "server_error"},
			CostUSD: 0.02, PromptTokens: 1000, OutputTokens: 40,
			UnixMillis: int64(i+1) * 1000,
		})
	}
	for i := 0; i < 12; i++ {
		events = append(events, Event{
			Project: "p", SessionID: "s", ToolName: "search_docs",
			Args:    map[string]any{"q": i},
			Result:  map[string]any{"ok": true, "hit": i},
			CostUSD: 0.01, PromptTokens: 1000, OutputTokens: 80,
			UnixMillis: int64(20+i) * 1000,
		})
	}
	res := replayEvents(t, events)
	if res.Verdict != "block" {
		t.Fatalf("verdict=%s want block (max across stream); signals=%v", res.Verdict, res.Signals)
	}
	if res.FirstBlock == 0 || res.FirstBlock > 8 {
		t.Fatalf("first block at %d, want within the runaway prefix", res.FirstBlock)
	}
	if res.SavedCostUSD <= 0 {
		t.Fatalf("saved cost = %.4f, want > 0 (cost after first block)", res.SavedCostUSD)
	}
}

// The firewall path must fire: amount over policy blocks via ActionStore.Decide.
func TestReplayFirewallAmountPolicy(t *testing.T) {
	events := []Event{{
		Project: "p", SessionID: "s", ToolName: "refund_payment",
		Args: map[string]any{"order": 1}, Result: map[string]any{"status": "ok"},
		ActionRisk: "dangerous", IdempotencyKey: "rf-1", BackupID: "bk-1",
		AmountCents: 9999, MaxAmountCents: 100, UnixMillis: 1000,
	}}
	res := replayEvents(t, events)
	if res.Verdict != "block" {
		t.Fatalf("verdict=%s want block", res.Verdict)
	}
	if !hasString(res.Signals, "policy_amount_exceeded") {
		t.Fatalf("signals=%v want policy_amount_exceeded", res.Signals)
	}
}

// Committed duplicate: success result commits the key; a second identical call
// must block with duplicate_side_effect — proving the post_tool reconcile runs.
func TestReplayDuplicateAfterCommit(t *testing.T) {
	call := Event{
		Project: "p", SessionID: "s", ToolName: "refund_payment",
		Args: map[string]any{"order": 7}, Result: map[string]any{"status": "success"},
		ResultClass: "success", ActionRisk: "dangerous", IdempotencyKey: "rf-7",
		BackupID: "bk-7", AmountCents: 50, MaxAmountCents: 100, UnixMillis: 1000,
	}
	second := call
	second.UnixMillis = 5000
	res := replayEvents(t, []Event{call, second})
	if res.Verdict != "block" {
		t.Fatalf("verdict=%s want block", res.Verdict)
	}
	if !hasString(res.Signals, "duplicate_side_effect") {
		t.Fatalf("signals=%v want duplicate_side_effect", res.Signals)
	}
	if res.FirstBlock != 2 {
		t.Fatalf("first block=%d want 2", res.FirstBlock)
	}
}

// A clean read-only session must stay allow with no signals recorded.
func TestReplayCleanSessionAllows(t *testing.T) {
	var events []Event
	for i := 0; i < 5; i++ {
		events = append(events, Event{
			Project: "p", SessionID: "s", ToolName: "read_file",
			Args:    map[string]any{"path": i},
			Result:  map[string]any{"content": i},
			CostUSD: 0.01, UnixMillis: int64(i+1) * 1000,
		})
	}
	res := replayEvents(t, events)
	if res.Verdict != "allow" {
		t.Fatalf("verdict=%s want allow; signals=%v", res.Verdict, res.Signals)
	}
}
