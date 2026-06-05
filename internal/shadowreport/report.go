package shadowreport

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

type Report struct {
	TotalRecords           int          `json:"total_records"`
	ToolEvents             int          `json:"tool_events"`
	ActionReceipts         int          `json:"action_receipts"`
	WouldBlock             int          `json:"would_block"`
	Blocked                int          `json:"blocked"`
	DuplicateSideEffects   int          `json:"duplicate_side_effects"`
	NoProgressEvents       int          `json:"no_progress_events"`
	EstimatedWastedCostUSD float64      `json:"estimated_wasted_cost_usd"`
	TopTools               []Count      `json:"top_tools"`
	TopResultClasses       []Count      `json:"top_result_classes"`
	RecommendedFirstPolicy string       `json:"recommended_first_policy,omitempty"`
	FalsePositiveReviewSet []ReviewItem `json:"false_positive_review_set,omitempty"`
}

type WALRecord = wal.Record

type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ReviewItem struct {
	DecisionID     string  `json:"decision_id,omitempty"`
	Project        string  `json:"project"`
	SessionID      string  `json:"session_id,omitempty"`
	ToolName       string  `json:"tool_name,omitempty"`
	ActionRisk     string  `json:"action_risk,omitempty"`
	ResultClass    string  `json:"result_class,omitempty"`
	LoopAction     string  `json:"loop_action,omitempty"`
	Reason         string  `json:"reason,omitempty"`
	CostUSD        float64 `json:"cost_usd,omitempty"`
	IdempotencyKey string  `json:"idempotency_key,omitempty"`
}

func ReadJSONL(r io.Reader) ([]wal.Record, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 256*1024), 10*1024*1024)
	var records []wal.Record
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var rec wal.Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return records, nil
}

func Build(records []wal.Record) Report {
	report := Report{TotalRecords: len(records)}
	tools := map[string]int{}
	classes := map[string]int{}

	for _, rec := range records {
		if rec.Provider == "_tool" {
			report.ToolEvents++
		}
		if rec.DecisionID != "" {
			report.ActionReceipts++
		}
		if rec.ToolSignature != "" {
			tools[rec.ToolSignature]++
		}
		if rec.ResultClass != "" {
			classes[rec.ResultClass]++
		}
		shadowWouldBlock := rec.LoopAction == "shadow_would_block"
		if shadowWouldBlock {
			report.WouldBlock++
			report.EstimatedWastedCostUSD += rec.Cost
			report.FalsePositiveReviewSet = appendReview(report.FalsePositiveReviewSet, rec)
		}
		if !shadowWouldBlock && (rec.LoopAction == "block" || rec.ImmediateOutcome == "blocked") {
			report.Blocked++
			report.EstimatedWastedCostUSD += rec.Cost
			report.FalsePositiveReviewSet = appendReview(report.FalsePositiveReviewSet, rec)
		}
		if rec.ResultClass == loop.ResultDuplicateAction || strings.Contains(rec.LoopSignalsFired, loop.SignalDuplicateSideEffect) {
			report.DuplicateSideEffects++
		}
		if isNoProgressClass(rec.ResultClass) {
			report.NoProgressEvents++
		}
	}

	report.TopTools = topCounts(toCounts(tools), 10)
	report.TopResultClasses = topCounts(toCounts(classes), 10)
	report.RecommendedFirstPolicy = recommend(report)
	return report
}

func appendReview(items []ReviewItem, rec wal.Record) []ReviewItem {
	if len(items) >= 20 {
		return items
	}
	reason := rec.DecisionReason
	if reason == "" {
		reason = rec.LoopEvidence
	}
	return append(items, ReviewItem{
		DecisionID:     rec.DecisionID,
		Project:        rec.Project,
		SessionID:      rec.SessionID,
		ToolName:       rec.ToolSignature,
		ActionRisk:     rec.ActionRisk,
		ResultClass:    rec.ResultClass,
		LoopAction:     rec.LoopAction,
		Reason:         reason,
		CostUSD:        rec.Cost,
		IdempotencyKey: rec.IdempotencyKey,
	})
}

func isNoProgressClass(class string) bool {
	switch class {
	case loop.ResultEmpty, loop.ResultNotFound, loop.ResultTimeout, loop.ResultPermissionError,
		loop.ResultSchemaError, loop.ResultSameOutput, loop.ResultRateLimited,
		loop.ResultUnknownError, loop.ResultDuplicateAction:
		return true
	default:
		return false
	}
}

func toCounts(values map[string]int) []Count {
	out := make([]Count, 0, len(values))
	for name, count := range values {
		out = append(out, Count{Name: name, Count: count})
	}
	return out
}

func topCounts(values []Count, limit int) []Count {
	sort.Slice(values, func(i, j int) bool {
		if values[i].Count == values[j].Count {
			return values[i].Name < values[j].Name
		}
		return values[i].Count > values[j].Count
	})
	if len(values) > limit {
		return values[:limit]
	}
	return values
}

func recommend(report Report) string {
	switch {
	case report.DuplicateSideEffects > 0:
		return "block duplicate side-effect actions with stable idempotency keys"
	case report.NoProgressEvents > 0:
		return "start with warn mode for repeated no-progress tool results"
	case report.WouldBlock > 0:
		return "review would-block traces, then enable warn mode for the highest-volume tool"
	default:
		return "keep shadow mode running until real no-progress or duplicate-action evidence appears"
	}
}
