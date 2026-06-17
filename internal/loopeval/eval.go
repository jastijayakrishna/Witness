package loopeval

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/hubbleops/hubbleops/internal/loop"
)

type Event struct {
	Project        string  `json:"project"`
	SessionID      string  `json:"session_id"`
	StepID         string  `json:"step_id,omitempty"`
	DecisionStage  string  `json:"decision_stage,omitempty"`
	ToolName       string  `json:"tool_name"`
	Args           any     `json:"args,omitempty"`
	Result         any     `json:"result,omitempty"`
	ResultClass    string  `json:"result_class,omitempty"`
	StateDeltaHash string  `json:"state_delta_hash,omitempty"`
	PromptTokens   int     `json:"prompt_tokens,omitempty"`
	OutputTokens   int     `json:"output_tokens,omitempty"`
	CostUSD        float64 `json:"cost_usd,omitempty"`
	UnixMillis     int64   `json:"unix_millis,omitempty"`
	Label          string  `json:"label,omitempty"`
	ExpectedAction string  `json:"expected_action,omitempty"`
	Source         string  `json:"source,omitempty"`
}

type GateConfig struct {
	MaxFalsePositiveBlockRate float64
	MaxMissedRunawayRate      float64
	MaxP95DecisionMs          float64
	MinRunawayRecall          float64
	MinBlockPrecision         float64
}

type TraceResult struct {
	Project       string   `json:"project"`
	SessionID     string   `json:"session_id"`
	Label         string   `json:"label,omitempty"`
	Expected      string   `json:"expected_action,omitempty"`
	FinalAction   string   `json:"final_action"`
	Confidence    float64  `json:"confidence"`
	Signals       []string `json:"signals,omitempty"`
	Events        int      `json:"events"`
	FirstBlock    int      `json:"first_block_step,omitempty"`
	TotalCostUSD  float64  `json:"total_cost_usd"`
	SavedCostUSD  float64  `json:"saved_cost_usd,omitempty"`
	MissedRunaway bool     `json:"missed_runaway,omitempty"`
	FalseBlock    bool     `json:"false_block,omitempty"`
}

type Report struct {
	TotalEvents                int           `json:"total_events"`
	TotalTraces                int           `json:"total_traces"`
	RunawayTraces              int           `json:"runaway_traces"`
	LegitTraces                int           `json:"legit_traces"`
	TruePositiveBlocks         int           `json:"true_positive_blocks"`
	FalsePositiveBlocks        int           `json:"false_positive_blocks"`
	MissedRunaways             int           `json:"missed_runaways"`
	WarningTraces              int           `json:"warning_traces"`
	TotalCostUSD               float64       `json:"total_cost_usd"`
	SavedCostUSD               float64       `json:"saved_cost_usd"`
	RunawayRecall              float64       `json:"runaway_recall"`
	BlockPrecision             float64       `json:"block_precision"`
	FalsePositiveBlockRate     float64       `json:"false_positive_block_rate"`
	MissedRunawayRate          float64       `json:"missed_runaway_rate"`
	ReplayP95DecisionLatencyMs float64       `json:"replay_p95_decision_latency_ms"`
	GateFailures               []string      `json:"gate_failures,omitempty"`
	Traces                     []TraceResult `json:"traces,omitempty"`
}

type traceKey struct {
	project string
	session string
}

func DefaultGateConfig() GateConfig {
	return GateConfig{
		MaxFalsePositiveBlockRate: 0,
		MaxMissedRunawayRate:      0,
		MaxP95DecisionMs:          25,
		MinRunawayRecall:          1,
		MinBlockPrecision:         1,
	}
}

func Evaluate(events []Event, cfg loop.Config, gates GateConfig) Report {
	groups := make(map[traceKey][]Event)
	var order []traceKey
	for _, event := range events {
		project := firstNonEmpty(event.Project, "unknown")
		session := firstNonEmpty(event.SessionID, "unknown")
		key := traceKey{project: project, session: session}
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], event)
	}

	var report Report
	var decisionDurations []float64
	for _, key := range order {
		trace := groups[key]
		result, durations := evaluateTrace(key, trace, cfg)
		decisionDurations = append(decisionDurations, durations...)
		report.TotalEvents += result.Events
		report.TotalTraces++
		report.TotalCostUSD += result.TotalCostUSD
		report.SavedCostUSD += result.SavedCostUSD
		if result.FinalAction == "warn" {
			report.WarningTraces++
		}
		if isRunawayLabel(result.Label) {
			report.RunawayTraces++
			if result.FinalAction == "block" {
				report.TruePositiveBlocks++
			} else {
				report.MissedRunaways++
				result.MissedRunaway = true
			}
		} else {
			report.LegitTraces++
			if result.FinalAction == "block" {
				report.FalsePositiveBlocks++
				result.FalseBlock = true
			}
		}
		report.Traces = append(report.Traces, result)
	}

	report.TotalCostUSD = round4(report.TotalCostUSD)
	report.SavedCostUSD = round4(report.SavedCostUSD)
	report.RunawayRecall = ratio(report.TruePositiveBlocks, report.RunawayTraces)
	report.BlockPrecision = ratio(report.TruePositiveBlocks, report.TruePositiveBlocks+report.FalsePositiveBlocks)
	report.FalsePositiveBlockRate = ratio(report.FalsePositiveBlocks, report.LegitTraces)
	report.MissedRunawayRate = ratio(report.MissedRunaways, report.RunawayTraces)
	report.ReplayP95DecisionLatencyMs = percentile(decisionDurations, 0.95)
	report.GateFailures = gateFailures(report, gates)
	return report
}

func evaluateTrace(key traceKey, events []Event, cfg loop.Config) (TraceResult, []float64) {
	state := loop.NewState()
	var decision loop.Decision
	// maxDecision carries the highest-severity decision seen across the stream;
	// a trace is judged by its worst moment, not its final turn.
	var maxDecision loop.Decision
	var durations []float64
	var firstBlock int
	var totalCost float64
	label := ""
	expected := ""

	for i, event := range events {
		if event.Label != "" {
			label = event.Label
		}
		if event.ExpectedAction != "" {
			expected = event.ExpectedAction
		}
		obs := loop.Observation{
			Project:        firstNonEmpty(event.Project, key.project),
			SessionID:      firstNonEmpty(event.SessionID, key.session),
			StepID:         event.StepID,
			DecisionStage:  event.DecisionStage,
			ToolName:       event.ToolName,
			Args:           event.Args,
			Result:         event.Result,
			ResultClass:    event.ResultClass,
			StateDeltaHash: event.StateDeltaHash,
			PromptTokens:   event.PromptTokens,
			OutputTokens:   event.OutputTokens,
			CostUSD:        event.CostUSD,
			UnixMillis:     event.UnixMillis,
		}
		start := time.Now()
		state, decision = loop.Observe(state, obs, cfg)
		durations = append(durations, float64(time.Since(start).Microseconds())/1000)
		totalCost += event.CostUSD
		if decisionRank(decision.ActionCeiling) > decisionRank(maxDecision.ActionCeiling) {
			maxDecision = decision
		}
		if firstBlock == 0 && decision.ActionCeiling == loop.ActionBlock {
			firstBlock = i + 1
		}
	}

	final := actionName(maxDecision.ActionCeiling)
	if expected == "" {
		expected = expectedFromLabel(label)
	}
	return TraceResult{
		Project:      key.project,
		SessionID:    key.session,
		Label:        label,
		Expected:     expected,
		FinalAction:  final,
		Confidence:   maxDecision.Confidence,
		Signals:      maxDecision.SignalsFired,
		Events:       len(events),
		FirstBlock:   firstBlock,
		TotalCostUSD: round4(totalCost),
		SavedCostUSD: round4(savedCost(events, firstBlock, label)),
	}, durations
}

func ReadJSONL(r io.Reader, source string) ([]Event, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	var events []Event
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", source, lineNo, err)
		}
		if event.Source == "" {
			event.Source = source
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	return events, nil
}

func WriteJSONL(w io.Writer, events []Event) error {
	enc := json.NewEncoder(w)
	for _, event := range events {
		if err := enc.Encode(event); err != nil {
			return err
		}
	}
	return nil
}

func Anonymize(events []Event, salt string) []Event {
	out := make([]Event, len(events))
	for i, event := range events {
		event.Project = hashIdentifier("project", event.Project, salt)
		event.SessionID = hashIdentifier("session", event.SessionID, salt)
		if event.StepID != "" {
			event.StepID = hashIdentifier("step", event.StepID, salt)
		}
		if event.StateDeltaHash != "" {
			event.StateDeltaHash = hashIdentifier("state", event.StateDeltaHash, salt)
		}
		if event.Args != nil {
			event.Args = fingerprintValue(event.Args)
		}
		if event.Result != nil {
			event.Result = fingerprintValue(event.Result)
		}
		out[i] = event
	}
	return out
}

func decisionRank(action loop.Action) int {
	switch action {
	case loop.ActionBlock:
		return 3
	case loop.ActionWarn:
		return 2
	default:
		return 1
	}
}

func actionName(action loop.Action) string {
	switch action {
	case loop.ActionBlock:
		return "block"
	case loop.ActionWarn:
		return "warn"
	default:
		return "allow"
	}
}

func expectedFromLabel(label string) string {
	if isRunawayLabel(label) {
		return "block"
	}
	if label != "" {
		return "allow"
	}
	return ""
}

func isRunawayLabel(label string) bool {
	return strings.EqualFold(label, "true_runaway") || strings.EqualFold(label, "runaway")
}

func savedCost(events []Event, firstBlock int, label string) float64 {
	if firstBlock == 0 || !isRunawayLabel(label) {
		return 0
	}
	var saved float64
	for i := firstBlock; i < len(events); i++ {
		saved += events[i].CostUSD
	}
	return saved
}

func gateFailures(report Report, gates GateConfig) []string {
	if gates == (GateConfig{}) {
		gates = DefaultGateConfig()
	}
	var failures []string
	if report.FalsePositiveBlockRate > gates.MaxFalsePositiveBlockRate {
		failures = append(failures, fmt.Sprintf("false_positive_block_rate %.4f > %.4f", report.FalsePositiveBlockRate, gates.MaxFalsePositiveBlockRate))
	}
	if report.MissedRunawayRate > gates.MaxMissedRunawayRate {
		failures = append(failures, fmt.Sprintf("missed_runaway_rate %.4f > %.4f", report.MissedRunawayRate, gates.MaxMissedRunawayRate))
	}
	if report.RunawayTraces > 0 && report.RunawayRecall < gates.MinRunawayRecall {
		failures = append(failures, fmt.Sprintf("runaway_recall %.4f < %.4f", report.RunawayRecall, gates.MinRunawayRecall))
	}
	if report.TruePositiveBlocks+report.FalsePositiveBlocks > 0 && report.BlockPrecision < gates.MinBlockPrecision {
		failures = append(failures, fmt.Sprintf("block_precision %.4f < %.4f", report.BlockPrecision, gates.MinBlockPrecision))
	}
	if gates.MaxP95DecisionMs > 0 && report.ReplayP95DecisionLatencyMs > gates.MaxP95DecisionMs {
		failures = append(failures, fmt.Sprintf("replay_p95_decision_latency_ms %.4f > %.4f", report.ReplayP95DecisionLatencyMs, gates.MaxP95DecisionMs))
	}
	return failures
}

func ratio(num, denom int) float64 {
	if denom == 0 {
		return 0
	}
	return round4(float64(num) / float64(denom))
}

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Float64s(values)
	idx := int(math.Ceil(float64(len(values))*p)) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return round4(values[idx])
}

func round4(v float64) float64 {
	return math.Round(v*10_000) / 10_000
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func hashIdentifier(prefix, value, salt string) string {
	sum := sha256.Sum256([]byte(salt + ":" + value))
	return prefix + "_" + hex.EncodeToString(sum[:])[:16]
}

func fingerprintValue(value any) map[string]any {
	data, err := json.Marshal(value)
	if err != nil {
		data = []byte(fmt.Sprintf("%v", value))
	}
	sum := sha256.Sum256(data)
	return map[string]any{
		"hubbleops_capture": "fingerprint",
		"sha256":          hex.EncodeToString(sum[:]),
		"type":            fmt.Sprintf("%T", value),
	}
}
