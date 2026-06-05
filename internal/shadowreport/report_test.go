package shadowreport

import (
	"strings"
	"testing"

	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

func TestBuildShadowReport(t *testing.T) {
	records := []wal.Record{
		{
			Provider:         "_tool",
			Project:          "p",
			SessionID:        "s",
			ToolSignature:    "send_email",
			ResultClass:      loop.ResultDuplicateAction,
			LoopSignalsFired: loop.SignalDuplicateSideEffect,
			LoopAction:       "shadow_would_block",
			ImmediateOutcome: "blocked",
			Cost:             1.25,
			DecisionID:       "dec_1",
			ActionRisk:       "write",
			IdempotencyKey:   "email:1",
			DecisionReason:   "duplicate side-effect blocked",
		},
		{
			Provider:      "_tool",
			Project:       "p",
			SessionID:     "s",
			ToolSignature: "search_docs",
			ResultClass:   loop.ResultNotFound,
			LoopAction:    "allow",
			Cost:          0.10,
		},
	}
	report := Build(records)
	if report.TotalRecords != 2 || report.ToolEvents != 2 {
		t.Fatalf("counts = %+v", report)
	}
	if report.DuplicateSideEffects != 1 {
		t.Fatalf("duplicates=%d want 1", report.DuplicateSideEffects)
	}
	if report.NoProgressEvents != 2 {
		t.Fatalf("no_progress=%d want 2", report.NoProgressEvents)
	}
	if report.WouldBlock != 1 {
		t.Fatalf("would_block=%d want 1", report.WouldBlock)
	}
	if report.Blocked != 0 {
		t.Fatalf("blocked=%d want 0", report.Blocked)
	}
	if report.EstimatedWastedCostUSD != 1.25 {
		t.Fatalf("estimated_wasted_cost_usd=%f want 1.25", report.EstimatedWastedCostUSD)
	}
	if len(report.FalsePositiveReviewSet) != 1 || report.FalsePositiveReviewSet[0].DecisionID != "dec_1" {
		t.Fatalf("review set = %+v", report.FalsePositiveReviewSet)
	}
	if report.RecommendedFirstPolicy == "" {
		t.Fatalf("missing recommendation")
	}
}

func TestReadJSONL(t *testing.T) {
	records, err := ReadJSONL(strings.NewReader(`{"project":"p","provider":"_tool"}` + "\n"))
	if err != nil {
		t.Fatalf("read jsonl: %v", err)
	}
	if len(records) != 1 || records[0].Project != "p" {
		t.Fatalf("records=%+v", records)
	}
}
