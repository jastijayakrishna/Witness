package shadowreport

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/outcomes"
	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/wal"
)

type Report struct {
	TotalRecords                 int          `json:"total_records"`
	ToolEvents                   int          `json:"tool_events"`
	ActionReceipts               int          `json:"action_receipts"` // legacy alias for total_action_decisions
	TotalActionDecisions         int          `json:"total_action_decisions"`
	WouldBlock                   int          `json:"would_block"` // legacy alias for would_block_decisions
	WouldBlockDecisions          int          `json:"would_block_decisions"`
	Blocked                      int          `json:"blocked"`
	DuplicateSideEffects         int          `json:"duplicate_side_effects"` // legacy alias
	DuplicateSideEffectDecisions int          `json:"duplicate_side_effect_decisions"`
	NoProgressEvents             int          `json:"no_progress_events"` // legacy alias
	NoProgressDecisions          int          `json:"no_progress_decisions"`
	BudgetDecisions              int          `json:"budget_decisions"`
	EstimatedWastedCostUSD       float64      `json:"estimated_wasted_cost_usd"` // legacy alias
	EstimatedCostSavedUSD        float64      `json:"estimated_cost_saved_usd"`
	TopTools                     []Count      `json:"top_tools"`
	TopToolsByRiskyDecisions     []Count      `json:"top_tools_by_risky_decisions"`
	TopResultClasses             []Count      `json:"top_result_classes"`
	UnreviewedDecisionsCount     int          `json:"unreviewed_decisions_count"`
	RecommendedReviewSample      []ReviewItem `json:"recommended_review_sample,omitempty"`
	RecommendedFirstPolicy       string       `json:"recommended_first_policy,omitempty"`
	FalsePositiveReviewSet       []ReviewItem `json:"false_positive_review_set,omitempty"` // legacy alias for recommended_review_sample
}

type WALRecord = wal.Record

type Count struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ReviewItem struct {
	DecisionID       string  `json:"decision_id,omitempty"`
	Project          string  `json:"project"`
	SessionID        string  `json:"session_id,omitempty"`
	ActionName       string  `json:"action_name,omitempty"`
	ToolName         string  `json:"tool_name,omitempty"` // legacy alias for action_name
	HubbleOpsAction    string  `json:"hubbleops_action,omitempty"`
	ActionRisk       string  `json:"action_risk,omitempty"` // legacy alias for risk_class
	RiskClass        string  `json:"risk_class,omitempty"`
	ResultClass      string  `json:"result_class,omitempty"`
	LoopAction       string  `json:"loop_action,omitempty"`
	Reason           string  `json:"reason,omitempty"`
	EvidenceSummary  string  `json:"evidence_summary,omitempty"`
	CostUSD          float64 `json:"cost_usd,omitempty"` // legacy alias for estimated_cost_usd
	EstimatedCostUSD float64 `json:"estimated_cost_usd,omitempty"`
	EstimatedRisk    string  `json:"estimated_risk,omitempty"`
	ReviewCommand    string  `json:"review_command,omitempty"`
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
	riskyTools := map[string]int{}
	classes := map[string]int{}
	actionDecisions := map[string]struct{}{}
	wouldBlockDecisions := map[string]struct{}{}
	duplicateDecisions := map[string]struct{}{}
	noProgressDecisions := map[string]struct{}{}
	budgetDecisions := map[string]struct{}{}
	savedCostDecisions := map[string]struct{}{}
	reviewCandidates := map[string]ReviewItem{}

	for _, rec := range records {
		if rec.Provider == "_tool" {
			report.ToolEvents++
		}
		if rec.DecisionID != "" {
			actionDecisions[rec.DecisionID] = struct{}{}
		}
		if rec.ToolSignature != "" {
			tools[rec.ToolSignature]++
		}
		if rec.ResultClass != "" {
			classes[string(outcomes.NormalizeResultClass(rec.ResultClass))]++
		}
		decisionKey := decisionKey(rec)
		shadowWouldBlock := isWouldBlockDecision(rec)
		duplicateDecision := isDuplicateSideEffectDecision(rec)
		noProgressDecision := isNoProgressDecision(rec)
		budgetDecision := isBudgetDecision(rec)
		riskyDecision := isRiskyDecision(rec)
		if riskyDecision && rec.ToolSignature != "" {
			riskyTools[rec.ToolSignature]++
		}
		if shadowWouldBlock {
			wouldBlockDecisions[decisionKey] = struct{}{}
			if _, seen := savedCostDecisions[decisionKey]; !seen {
				report.EstimatedCostSavedUSD += rec.Cost
				savedCostDecisions[decisionKey] = struct{}{}
			}
		}
		if !shadowWouldBlock && (rec.LoopAction == "block" || rec.ImmediateOutcome == "blocked") {
			report.Blocked++
			if _, seen := savedCostDecisions[decisionKey]; !seen {
				report.EstimatedCostSavedUSD += rec.Cost
				savedCostDecisions[decisionKey] = struct{}{}
			}
		}
		if duplicateDecision {
			duplicateDecisions[decisionKey] = struct{}{}
		}
		if noProgressDecision {
			noProgressDecisions[decisionKey] = struct{}{}
		}
		if budgetDecision {
			budgetDecisions[decisionKey] = struct{}{}
		}
		if rec.DecisionID != "" && riskyDecision {
			if _, exists := reviewCandidates[rec.DecisionID]; !exists {
				reviewCandidates[rec.DecisionID] = reviewItem(rec)
			}
		}
	}

	report.TotalActionDecisions = len(actionDecisions)
	report.ActionReceipts = report.TotalActionDecisions
	report.WouldBlockDecisions = len(wouldBlockDecisions)
	report.WouldBlock = report.WouldBlockDecisions
	report.DuplicateSideEffectDecisions = len(duplicateDecisions)
	report.DuplicateSideEffects = report.DuplicateSideEffectDecisions
	report.NoProgressDecisions = len(noProgressDecisions)
	report.NoProgressEvents = report.NoProgressDecisions
	report.BudgetDecisions = len(budgetDecisions)
	report.EstimatedWastedCostUSD = report.EstimatedCostSavedUSD
	report.TopTools = topCounts(toCounts(tools), 10)
	report.TopToolsByRiskyDecisions = topCounts(toCounts(riskyTools), 10)
	report.TopResultClasses = topCounts(toCounts(classes), 10)
	report.UnreviewedDecisionsCount = len(reviewCandidates)
	report.RecommendedReviewSample = topReviewItems(reviewCandidates, 10)
	report.FalsePositiveReviewSet = report.RecommendedReviewSample
	report.RecommendedFirstPolicy = recommend(report)
	return report
}

func reviewItem(rec wal.Record) ReviewItem {
	reason := rec.DecisionReason
	if reason == "" {
		reason = rec.LoopEvidence
	}
	reason = safeSummary(reason, rec.ResultClass, rec.LoopSignalsFired)
	evidence := safeSummary(rec.DecisionEvidence, rec.LoopSignalsFired, rec.ResultClass)
	riskClass := firstNonEmpty(rec.ActionRisk, inferredRiskClass(rec))
	resultClass := ""
	if rec.ResultClass != "" {
		resultClass = string(outcomes.NormalizeResultClass(rec.ResultClass))
	}
	return ReviewItem{
		DecisionID:       rec.DecisionID,
		Project:          rec.Project,
		SessionID:        rec.SessionID,
		ActionName:       firstNonEmpty(rec.ToolSignature, rec.Model, rec.DecisionStage),
		ToolName:         firstNonEmpty(rec.ToolSignature, rec.Model, rec.DecisionStage),
		HubbleOpsAction:    hubbleopsAction(rec),
		ActionRisk:       riskClass,
		RiskClass:        riskClass,
		ResultClass:      resultClass,
		LoopAction:       rec.LoopAction,
		Reason:           reason,
		EvidenceSummary:  evidence,
		CostUSD:          rec.Cost,
		EstimatedCostUSD: rec.Cost,
		EstimatedRisk:    estimatedRisk(rec),
		ReviewCommand:    reviewCommand(rec.DecisionID),
	}
}

func isDuplicateSideEffectDecision(rec wal.Record) bool {
	return outcomes.NormalizeResultClass(rec.ResultClass) == outcomes.ResultClassDuplicate ||
		strings.Contains(rec.LoopSignalsFired, loop.SignalDuplicateSideEffect)
}

func isNoProgressDecision(rec wal.Record) bool {
	return !isDuplicateSideEffectDecision(rec) && isNoProgressClass(rec.ResultClass)
}

func isNoProgressClass(class string) bool {
	switch outcomes.NormalizeResultClass(class) {
	case outcomes.ResultClassEmptyResult, outcomes.ResultClassNoStateDelta, outcomes.ResultClassNotFound,
		outcomes.ResultClassTimeout, outcomes.ResultClassPermissionError, outcomes.ResultClassSchemaError,
		outcomes.ResultClassRateLimited:
		return true
	default:
		return legacyResultToken(class) == loop.ResultUnknownError
	}
}

func isBudgetDecision(rec wal.Record) bool {
	return rec.DecisionStage == "pre_budget" || rec.StatusCode == 429 || containsAnyLower(
		"budget",
		rec.DecisionReason,
		rec.DecisionEvidence,
		rec.LoopEvidence,
		rec.LoopSignalsFired,
		rec.ResultClass,
	)
}

func isWouldBlockDecision(rec wal.Record) bool {
	return rec.LoopAction == "shadow_would_block"
}

func isRiskyDecision(rec wal.Record) bool {
	return isWouldBlockDecision(rec) ||
		rec.LoopAction == "block" ||
		rec.LoopAction == "warn" ||
		rec.ImmediateOutcome == "blocked" ||
		isDuplicateSideEffectDecision(rec) ||
		isNoProgressDecision(rec) ||
		isBudgetDecision(rec)
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

func topReviewItems(items map[string]ReviewItem, limit int) []ReviewItem {
	out := make([]ReviewItem, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		left := reviewPriority(out[i])
		right := reviewPriority(out[j])
		if left == right {
			if out[i].EstimatedCostUSD == out[j].EstimatedCostUSD {
				return out[i].DecisionID < out[j].DecisionID
			}
			return out[i].EstimatedCostUSD > out[j].EstimatedCostUSD
		}
		return left > right
	})
	if len(out) > limit {
		return out[:limit]
	}
	return out
}

func reviewPriority(item ReviewItem) int {
	score := 0
	switch item.HubbleOpsAction {
	case "block":
		score += 100
	case "shadow":
		score += 80
	case "warn":
		score += 60
	}
	switch {
	case strings.Contains(item.Reason, "budget") || strings.Contains(item.EvidenceSummary, "budget"):
		score += 30
	case outcomes.NormalizeResultClass(item.ResultClass) == outcomes.ResultClassDuplicate:
		score += 25
	case item.ResultClass != "":
		score += 10
	}
	switch item.EstimatedRisk {
	case "high":
		score += 20
	case "medium":
		score += 10
	}
	return score
}

func decisionKey(rec wal.Record) string {
	if rec.DecisionID != "" {
		return rec.DecisionID
	}
	if rec.RecordHash != "" {
		return rec.RecordHash
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s", rec.Project, rec.SessionID, rec.ToolSignature, rec.DecisionStage, rec.ResultClass)
}

func hubbleopsAction(rec wal.Record) string {
	switch rec.LoopAction {
	case "shadow_would_block", "shadow":
		return "shadow"
	case "warn":
		return "warn"
	case "block":
		return "block"
	default:
		if rec.ImmediateOutcome == "blocked" {
			return "block"
		}
		return "allow"
	}
}

func inferredRiskClass(rec wal.Record) string {
	switch {
	case isBudgetDecision(rec):
		return "budget"
	case isDuplicateSideEffectDecision(rec):
		return "duplicate_side_effect"
	case isNoProgressDecision(rec):
		return "no_progress"
	default:
		return "unknown"
	}
}

func estimatedRisk(rec wal.Record) string {
	switch {
	case rec.LoopAction == "block" || rec.ImmediateOutcome == "blocked" || isBudgetDecision(rec) || isDuplicateSideEffectDecision(rec):
		return "high"
	case isWouldBlockDecision(rec) || rec.LoopAction == "warn" || isNoProgressDecision(rec):
		return "medium"
	default:
		return "low"
	}
}

func reviewCommand(decisionID string) string {
	if decisionID == "" {
		return ""
	}
	return "hubbleops review-decision -decision " + shellToken(decisionID) + " -label true_positive -role developer"
}

func shellToken(value string) string {
	if value == "" {
		return "''"
	}
	if strings.ContainsAny(value, " \t\r\n\"'`$&|;<>()") {
		return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
	}
	return value
}

func safeSummary(values ...string) string {
	for _, value := range values {
		summary := strings.TrimSpace(value)
		if summary == "" {
			continue
		}
		summary = strings.Join(strings.Fields(summary), " ")
		if containsRawSensitiveEvidence(summary) {
			return "raw-sensitive evidence redacted"
		}
		if len(summary) > 220 {
			return summary[:217] + "..."
		}
		return summary
	}
	return ""
}

func containsRawSensitiveEvidence(value string) bool {
	return privacy.ContainsSensitiveText(value)
}

func containsAnyLower(needle string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), needle) {
			return true
		}
	}
	return false
}

func legacyResultToken(value string) string {
	token := strings.ToLower(strings.TrimSpace(value))
	token = strings.NewReplacer(" ", "_", "-", "_", "/", "_").Replace(token)
	return strings.Trim(token, "_")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func Markdown(report Report) string {
	var b strings.Builder
	b.WriteString("# HubbleOps Shadow Review Report\n\n")
	fmt.Fprintf(&b, "- Total records: %d\n", report.TotalRecords)
	fmt.Fprintf(&b, "- Total action decisions: %d\n", report.TotalActionDecisions)
	fmt.Fprintf(&b, "- Duplicate side-effect decisions: %d\n", report.DuplicateSideEffectDecisions)
	fmt.Fprintf(&b, "- No-progress decisions: %d\n", report.NoProgressDecisions)
	fmt.Fprintf(&b, "- Budget decisions: %d\n", report.BudgetDecisions)
	fmt.Fprintf(&b, "- Would-block decisions: %d\n", report.WouldBlockDecisions)
	fmt.Fprintf(&b, "- Estimated cost saved: $%.6f\n", report.EstimatedCostSavedUSD)
	fmt.Fprintf(&b, "- Unreviewed decisions: %d\n", report.UnreviewedDecisionsCount)
	if report.RecommendedFirstPolicy != "" {
		fmt.Fprintf(&b, "- Recommended first policy: %s\n", report.RecommendedFirstPolicy)
	}
	b.WriteString("\n## Top Tools By Risky Decisions\n\n")
	writeMarkdownCounts(&b, report.TopToolsByRiskyDecisions)
	b.WriteString("\n## Top Result Classes\n\n")
	writeMarkdownCounts(&b, report.TopResultClasses)
	b.WriteString("\n## Recommended Review Sample\n\n")
	if len(report.RecommendedReviewSample) == 0 {
		b.WriteString("No risky unreviewed decisions found in this report input.\n")
		return b.String()
	}
	for i, item := range report.RecommendedReviewSample {
		fmt.Fprintf(&b, "### %d. %s\n\n", i+1, item.DecisionID)
		fmt.Fprintf(&b, "- Action: `%s`\n", item.ActionName)
		fmt.Fprintf(&b, "- HubbleOps action: `%s`\n", item.HubbleOpsAction)
		fmt.Fprintf(&b, "- Risk class: `%s`\n", item.RiskClass)
		if item.ResultClass != "" {
			fmt.Fprintf(&b, "- Result class: `%s`\n", item.ResultClass)
		}
		if item.Reason != "" {
			fmt.Fprintf(&b, "- Reason: %s\n", item.Reason)
		}
		if item.EvidenceSummary != "" {
			fmt.Fprintf(&b, "- Evidence: %s\n", item.EvidenceSummary)
		}
		fmt.Fprintf(&b, "- Estimated cost/risk: $%.6f / %s\n", item.EstimatedCostUSD, item.EstimatedRisk)
		fmt.Fprintf(&b, "- Label command: `%s`\n\n", item.ReviewCommand)
	}
	return b.String()
}

func writeMarkdownCounts(b *strings.Builder, counts []Count) {
	if len(counts) == 0 {
		b.WriteString("No data.\n")
		return
	}
	b.WriteString("| Name | Count |\n")
	b.WriteString("| --- | ---: |\n")
	for _, count := range counts {
		fmt.Fprintf(b, "| `%s` | %d |\n", count.Name, count.Count)
	}
}

func recommend(report Report) string {
	switch {
	case report.DuplicateSideEffectDecisions > 0:
		return "block duplicate side-effect actions with stable idempotency keys"
	case report.NoProgressDecisions > 0:
		return "start with warn mode for repeated no-progress tool results"
	case report.WouldBlockDecisions > 0:
		return "review would-block traces, then enable warn mode for the highest-volume tool"
	default:
		return "keep shadow mode running until real no-progress or duplicate-action evidence appears"
	}
}
