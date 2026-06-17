package shadowreport

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/wal"
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
			DecisionEvidence: "duplicate_window=24h0m0s; idempotency_key=repeated",
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
			DecisionID:    "dec_2",
			ActionRisk:    "read",
		},
		{
			Provider:       "_proxy",
			Project:        "p",
			SessionID:      "s",
			DecisionStage:  "pre_budget",
			LoopAction:     "block",
			StatusCode:     429,
			Cost:           5.00,
			DecisionID:     "dec_budget",
			DecisionReason: "daily budget hard limit exceeded",
		},
	}
	report := Build(records)
	if report.TotalRecords != 3 || report.ToolEvents != 2 {
		t.Fatalf("counts = %+v", report)
	}
	if report.TotalActionDecisions != 3 {
		t.Fatalf("total_action_decisions=%d want 3", report.TotalActionDecisions)
	}
	if report.DuplicateSideEffectDecisions != 1 {
		t.Fatalf("duplicates=%d want 1", report.DuplicateSideEffectDecisions)
	}
	if report.NoProgressDecisions != 1 {
		t.Fatalf("no_progress=%d want 1", report.NoProgressDecisions)
	}
	if report.BudgetDecisions != 1 {
		t.Fatalf("budget_decisions=%d want 1", report.BudgetDecisions)
	}
	if report.WouldBlockDecisions != 1 {
		t.Fatalf("would_block=%d want 1", report.WouldBlockDecisions)
	}
	if report.Blocked != 1 {
		t.Fatalf("blocked=%d want 1", report.Blocked)
	}
	if report.EstimatedCostSavedUSD != 6.25 {
		t.Fatalf("estimated_cost_saved_usd=%f want 6.25", report.EstimatedCostSavedUSD)
	}
	if report.UnreviewedDecisionsCount != 3 {
		t.Fatalf("unreviewed_decisions_count=%d want 3", report.UnreviewedDecisionsCount)
	}
	if len(report.RecommendedReviewSample) != 3 {
		t.Fatalf("review sample = %+v", report.RecommendedReviewSample)
	}
	if report.RecommendedReviewSample[0].DecisionID != "dec_budget" {
		t.Fatalf("first review item=%+v want budget block first", report.RecommendedReviewSample[0])
	}
	if report.RecommendedReviewSample[0].ReviewCommand == "" || !strings.Contains(report.RecommendedReviewSample[0].ReviewCommand, "hubbleops review-decision -decision dec_budget") {
		t.Fatalf("missing review command: %+v", report.RecommendedReviewSample[0])
	}
	if report.RecommendedFirstPolicy == "" {
		t.Fatalf("missing recommendation")
	}
}

func TestShadowReportExcludesRawArgs(t *testing.T) {
	records := []wal.Record{
		{
			Project:          "p",
			Provider:         "_tool",
			SessionID:        "s",
			ToolSignature:    "send_email",
			ArgsFingerprint:  `{"email":"customer@example.com","body":"hello"}`,
			ResultClass:      loop.ResultDuplicateAction,
			LoopSignalsFired: loop.SignalDuplicateSideEffect,
			LoopAction:       "shadow_would_block",
			DecisionID:       "dec_raw",
			DecisionReason:   "raw_args contained customer@example.com",
			DecisionEvidence: `raw_args={"email":"customer@example.com","body":"hello"}`,
		},
	}

	report := Build(records)
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	output := string(encoded) + "\n" + Markdown(report)
	for _, forbidden := range []string{"customer@example.com", `"email"`, `"body"`, "raw_args={"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("report leaked raw args marker %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "raw-sensitive evidence redacted") {
		t.Fatalf("report did not explain evidence redaction: %s", output)
	}
}

func TestShadowReportMarkdownIncludesReviewCommands(t *testing.T) {
	report := Build([]wal.Record{{
		Project:          "p",
		Provider:         "_tool",
		SessionID:        "s",
		ToolSignature:    "refund_customer",
		ResultClass:      loop.ResultDuplicateAction,
		LoopSignalsFired: loop.SignalDuplicateSideEffect,
		LoopAction:       "shadow_would_block",
		DecisionID:       "dec_123",
		ActionRisk:       "money_movement",
		DecisionReason:   "duplicate side-effect blocked",
	}})

	markdown := Markdown(report)
	if !strings.Contains(markdown, "# HubbleOps Shadow Review Report") {
		t.Fatalf("missing markdown header: %s", markdown)
	}
	if !strings.Contains(markdown, "hubbleops review-decision -decision dec_123 -label true_positive -role developer") {
		t.Fatalf("missing review command: %s", markdown)
	}
}

func TestShadowReportJSONIsValid(t *testing.T) {
	report := Build([]wal.Record{{
		Project:        "p",
		Provider:       "_tool",
		SessionID:      "s",
		ToolSignature:  "refund_customer",
		LoopAction:     "warn",
		DecisionID:     "dec_json",
		DecisionReason: "risky write action",
	}})

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json should be valid: %v", err)
	}
	if decoded.RecommendedReviewSample[0].DecisionID != "dec_json" {
		t.Fatalf("decoded report=%+v", decoded)
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
