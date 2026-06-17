// Package loop is HubbleOps's runaway-loop detector.
//
// This detector is intentionally deterministic, dependency-free, and bounded-memory.
// It is designed for production safety, not cleverness.
//
// Core safety rules:
//   - False positives are customer-trust killers.
//   - A block requires hard no-progress evidence, not just a weighted score.
//   - Changing StateDeltaHash is only reported progress unless a trusted tool profile vouches for it.
//   - Pending/polling is bounded by count, time, and cost. Pending forever is never a bypass.
//   - Cheap loops still matter. Cost amplifies urgency; it is not required for no-progress detection.
//   - Confidence is a heuristic risk score, not a calibrated probability.
package loop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// ---------- Configuration ----------

type Config struct {
	Action                 string                 // "shadow", "warn", "block" – operator maximum
	MaxRepeated            int                    // default 3
	VelocityAccelRatio     float64                // default 1.5
	VelocityWindowMs       int64                  // half-window for velocity, default 5 min
	WarnConfidence         float64                // default 0.40; heuristic risk score
	BlockConfidence        float64                // default 0.70; heuristic risk score
	RequireSessionForBlock bool                   // default true – no block without session id
	MinContextGrowth       int                    // absolute token increase to flag context runaway (default 2000)
	ToolProfiles           map[string]ToolProfile // per-tool overrides
	ToolRiskFloor          map[string]string      // per-tool minimum action risk the client cannot downgrade (e.g. refund_customer→write)
}

type ToolProfile struct {
	MaxRepeated    int // override global MaxRepeated; 0 = use global
	BurstAllowance int // consecutive identical (tool,args) calls still considered normal

	// Polling controls. A polling tool can legitimately return repeated pending
	// results while waiting for an external job, but only within explicit bounds.
	Polling              bool
	MaxPendingCount      int
	MaxPendingDurationMs int64
	MaxPendingCostUSD    float64

	// TrustedStateDelta means the tool wrapper computes StateDeltaHash from trusted
	// external state. Without this, a changing StateDeltaHash is only reported
	// progress and must not suppress hard no-progress repeats.
	TrustedStateDelta bool
}

func DefaultConfig() Config {
	return Config{
		Action:                 "shadow",
		MaxRepeated:            3,
		VelocityAccelRatio:     1.5,
		VelocityWindowMs:       300_000,
		WarnConfidence:         0.40,
		BlockConfidence:        0.70,
		RequireSessionForBlock: true,
		MinContextGrowth:       2000,
	}
}

// ---------- Observation ----------

type Observation struct {
	Project        string
	SessionID      string
	StepID         string
	DecisionStage  string
	ToolName       string
	Args           any
	Result         any
	ResultClass    string
	StateDeltaHash string
	PromptTokens   int
	OutputTokens   int
	CostUSD        float64
	UnixMillis     int64
	// IdempotencyKey (when the caller supplies one) is evidence of intent: a
	// run of DISTINCT keys on the same tool marks deliberate batch writes, not
	// a stuck loop. Only its hash is retained in state.
	IdempotencyKey string
}

// ---------- State – constant memory ----------

type State struct {
	CallHistory    *ringBuf[callKey]
	ResultHistory  *ringBuf[resultKey]
	ContextSizes   *ringIntBuf
	OutputSizes    *ringIntBuf
	CostWindow     *costWindow
	ToolCallStreak map[string]int // kept for JSON/backward compatibility; detector logic uses history/stats
	ToolStats      map[string]ToolStats
	LastTool       string
	// LastEventMs / PrevEventMs are the timestamps of the session's two most
	// recent completed (post_tool) events, used to tell a quiet scheduled
	// session apart from a busy one cycling between tools.
	LastEventMs int64
	PrevEventMs int64
}

type callKey struct {
	Tool     string
	ArgsHash string
}

type resultKey struct {
	Tool        string
	ResultHash  string
	ResultClass string
}

type ToolStats struct {
	TotalCalls                   int
	SameArgsCount                int
	SameResultCount              int
	SameFailureChangingArgsCount int
	SameStateDeltaCount          int
	SameArgsAndClassCount        int
	PendingCount                 int
	PendingCostUSD               float64
	PendingStartMs               int64
	LastArgsHash                 string
	LastResultHash               string
	LastResultClass              string
	LastStateDeltaHash           string
	TotalCost                    float64
	LastSeenMs                   int64
	// LastGapMs / PrevGapMs are the two most recent inter-call gaps for this
	// tool. They let the detector recognize exponential-backoff retry shapes
	// (growing gaps) and scheduled repeats (long gaps) without storing
	// per-call timestamps in the rings.
	LastGapMs int64
	PrevGapMs int64
	// LastIdemKeyHash / DistinctKeyStreak track whether the caller is supplying
	// a fresh idempotency key per call — the signature of a deliberate batch
	// writer rather than a stuck loop.
	LastIdemKeyHash  string
	DistinctKeyStreak int
	// LastCanonArgsHash / SameCanonArgsCount track repetition under argument
	// canonicalization (case folding, whitespace collapse), catching loops that
	// paraphrase the same call textually to evade the exact-hash repeat.
	LastCanonArgsHash  string
	SameCanonArgsCount int
}

const perToolStreakGapMs = 30_000

// historyCap sizes the call/result rings. 64 entries puts the cycle-detection
// period ceiling at 32 tools, closing the documented period-20 macro-loop
// blindspot while keeping per-session state bounded (~10KB serialized).
const historyCap = 64

func NewState() State {
	return State{
		CallHistory:    newRing[callKey](historyCap),
		ResultHistory:  newRing[resultKey](historyCap),
		ContextSizes:   newIntRing(32),
		OutputSizes:    newIntRing(32),
		CostWindow:     newCostWindow(),
		ToolCallStreak: make(map[string]int),
		ToolStats:      make(map[string]ToolStats),
	}
}

// ---------- Decision ----------

type Action string

const (
	ActionNone  Action = "none"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

// 2.4.0: deep_call_repeat signal (self-trigger storms with varying results);
// backoff-retry and scheduled-repeat exemptions; default polling tolerance for
// unprofiled tools; keyed-batch suppression of uniform-ack warns; risk-aware
// ambiguous-failure lease hold (action-firewall ResultDisposition).
// 2.5.0: history rings 32→64 (cycle ceiling 16→32, closes the period-20
// macro-loop blindspot); near_identical_repeat (canonicalized-args paraphrase
// loops); cross-session project guard (cross_session_repeat).
const DetectorVersion = "2.5.0"

type Decision struct {
	SignalsFired        []string
	Confidence          float64 // heuristic risk score; not calibrated probability
	ActionCeiling       Action
	DetectorVersion     string
	Reason              string
	HadSession          bool
	PolicyVersion       string
	DecisionEvidence    []string
	NeedsSemanticReview bool
}

// Decide evaluates current state without mutating it.
func Decide(s State, obs Observation, cfg Config) Decision {
	clone := s.clone()
	_, d := Observe(clone, obs, cfg)
	return d
}

// Observe updates State with one observation and returns a Decision.
func Observe(s State, obs Observation, cfg Config) (State, Decision) {
	s.ensureInit()

	// At pre_tool the action has not run: there is no result, no tokens, no cost yet.
	// Record only the proposed call so call-pattern signals can evaluate it, but do NOT
	// push a synthetic empty result or update result/cost stats — that would corrupt the
	// progress picture (e.g. make a healthy polling tool look stuck). Result-derived
	// stats stay as the tool's real history; deriveFacts reads LastResultClass from them.
	preTool := obs.DecisionStage == "pre_tool"

	if obs.ToolName != "" {
		argsHash := hashAny(obs.Args)
		s.CallHistory.push(callKey{Tool: obs.ToolName, ArgsHash: argsHash})
		if !preTool {
			resultHash := hashAny(obs.Result)
			resultClass := normalizeResultClass(obs.ResultClass)
			if resultClass == "" {
				resultClass = ClassifyResult(obs.Result)
			}
			s.ResultHistory.push(resultKey{Tool: obs.ToolName, ResultHash: resultHash, ResultClass: resultClass})
			s.updateToolStats(obs, argsHash, resultHash, resultClass)
		}
	}

	if !preTool {
		s.ContextSizes.push(obs.PromptTokens)
		s.OutputSizes.push(obs.OutputTokens)
		s.CostWindow.add(obs.UnixMillis, obs.CostUSD)
		s.PrevEventMs = s.LastEventMs
		s.LastEventMs = obs.UnixMillis
	}

	return s, decide(s, obs, cfg)
}

func EffectiveAction(configured Action, ceiling Action) Action {
	rank := map[Action]int{ActionNone: 0, ActionWarn: 1, ActionBlock: 2}
	if rank[configured] < rank[ceiling] {
		return configured
	}
	return ceiling
}

// ---------- Decision core ----------

type progressLevel int

const (
	progressNone progressLevel = iota
	progressReported
	progressTrusted
)

func (p progressLevel) String() string {
	switch p {
	case progressTrusted:
		return "trusted"
	case progressReported:
		return "reported"
	default:
		return "none"
	}
}

type signal struct {
	Name              string
	Strength          float64
	NoProgress        bool
	HardProof         bool
	Evidence          []string
	FalsePositiveRisk string
}

type detectorFacts struct {
	Obs             Observation
	ArgsHash        string
	ResultHash      string
	ResultClass     string
	ToolProfile     ToolProfile
	MaxRepeated     int
	DeepRepeated    int
	Stats           ToolStats
	HadSession      bool
	Progress        progressLevel
	PendingExceeded bool
	ArgsChanging    bool
	CostRatio       float64
	ObservedSpanMs  int64
	// GapMs is the gap between this call and the tool's previous call
	// (-1 when unknown — first call or missing timestamps).
	GapMs int64
	// BackoffRetry: the current same-args streak has exponential-backoff shape
	// (growing gaps) with a retryable failure class and is still shallow.
	// Healthy clients retry transient failures this way; suppression is capped
	// by depth so a backoff-shaped runaway is still caught.
	BackoffRetry bool
	// ScheduledRepeat: an identical SUCCESSFUL call after a long quiet gap is
	// scheduled work (cron, health checks), not a loop iteration. Failing
	// repeats are never exempted regardless of pace.
	ScheduledRepeat bool
}

func decide(s State, obs Observation, cfg Config) Decision {
	cfg = normalizeConfig(cfg)
	facts := deriveFacts(s, obs, cfg)
	signals := evaluateSignals(s, facts, cfg)
	score := scoreSignals(signals, facts, cfg)
	ceiling := chooseAction(score, signals, facts, cfg)

	return Decision{
		SignalsFired:        signalNames(signals),
		Confidence:          round2(score),
		ActionCeiling:       ceiling,
		DetectorVersion:     DetectorVersion,
		Reason:              reasonFromEvidence(ceiling, signals),
		HadSession:          facts.HadSession,
		DecisionEvidence:    evidenceStrings(signals, facts),
		NeedsSemanticReview: needsSemanticReview(signals, facts, ceiling),
	}
}

func normalizeConfig(cfg Config) Config {
	def := DefaultConfig()
	if cfg.Action == "" {
		cfg.Action = def.Action
	}
	if cfg.MaxRepeated <= 0 {
		cfg.MaxRepeated = def.MaxRepeated
	}
	if cfg.VelocityAccelRatio <= 0 {
		cfg.VelocityAccelRatio = def.VelocityAccelRatio
	}
	if cfg.VelocityWindowMs <= 0 {
		cfg.VelocityWindowMs = def.VelocityWindowMs
	}
	if cfg.WarnConfidence <= 0 {
		cfg.WarnConfidence = def.WarnConfidence
	}
	if cfg.BlockConfidence <= 0 {
		cfg.BlockConfidence = def.BlockConfidence
	}
	if cfg.MinContextGrowth <= 0 {
		cfg.MinContextGrowth = def.MinContextGrowth
	}
	return cfg
}

func deriveFacts(s State, obs Observation, cfg Config) detectorFacts {
	argsHash, resultHash := "", ""
	resultClass := normalizeResultClass(obs.ResultClass)
	if obs.ToolName != "" {
		argsHash = hashAny(obs.Args)
		resultHash = hashAny(obs.Result)
		if resultClass == "" {
			resultClass = ClassifyResult(obs.Result)
		}
	}

	profile := ToolProfile{}
	if cfg.ToolProfiles != nil && obs.ToolName != "" {
		profile = cfg.ToolProfiles[obs.ToolName]
	}
	maxRepeated := effectiveMaxRepeated(obs.ToolName, cfg)
	stats := strongestToolStats(s, obs)
	if obs.DecisionStage == "pre_tool" {
		// No result yet — judge the proposed repeat against the tool's last real result
		// class so a stuck failure loop (no-progress) is caught while a tool that was
		// making progress (success / changing state / polling) is not blocked pre-run.
		resultClass = stats.LastResultClass
	}
	progress := assessProgress(obs, resultClass, profile, stats)

	argsChanging := false
	if obs.ToolName != "" && s.CallHistory.len >= maxRepeated {
		lastTool := s.CallHistory.last().Tool
		count := 0
		for i := 0; i < maxRepeated; i++ {
			if s.CallHistory.get(s.CallHistory.len-1-i).Tool == lastTool {
				count++
			}
		}
		argsChanging = count == maxRepeated && !checkRepeatedN(s.CallHistory, maxRepeated)
	}

	gapMs, prevGapMs := callGaps(obs, stats)
	sessionGapMs := sessionGap(s, obs)

	return detectorFacts{
		Obs:             obs,
		ArgsHash:        argsHash,
		ResultHash:      resultHash,
		ResultClass:     resultClass,
		ToolProfile:     profile,
		MaxRepeated:     maxRepeated,
		DeepRepeated:    2 * maxRepeated,
		Stats:           stats,
		HadSession:      obs.SessionID != "",
		Progress:        progress,
		PendingExceeded: pendingExceeded(stats, profile, cfg),
		ArgsChanging:    argsChanging,
		CostRatio:       s.CostWindow.velocityRatio(),
		ObservedSpanMs:  s.CostWindow.observedSpan(),
		GapMs:           gapMs,
		BackoffRetry:    isBackoffRetry(resultClass, stats, gapMs, prevGapMs),
		ScheduledRepeat: resultClass == ResultSuccess && gapMs > scheduledRepeatGapMs && sessionGapMs > scheduledRepeatGapMs,
	}
}

// scheduledRepeatGapMs is how quiet a session must be before an identical
// SUCCESSFUL repeat reads as scheduled work (cron, health checks) rather than
// a loop iteration. Minutes, not seconds: a 60-second hammer is still a loop.
const scheduledRepeatGapMs = 300_000

// sessionGap is the time since the session's previous completed event — the
// "is the session quiet?" half of the scheduled-repeat test. A tool in a busy
// multi-tool cycle has a long per-tool gap but a short session gap; a cron
// session is quiet on both. -1 when unknown.
func sessionGap(s State, obs Observation) int64 {
	prev := s.LastEventMs
	if obs.DecisionStage != "pre_tool" {
		// updateToolStats and the session timestamps were already advanced for
		// this observation, so the previous event's timestamp is PrevEventMs.
		prev = s.PrevEventMs
	}
	if prev <= 0 || obs.UnixMillis <= 0 {
		return -1
	}
	return obs.UnixMillis - prev
}

// callGaps returns this call's gap to the tool's previous call and the gap
// before that. At post_tool updateToolStats already ran, so the current gap is
// LastGapMs; at pre_tool the call has not been recorded, so it is computed from
// LastSeenMs. -1 means unknown (first call or missing timestamps).
func callGaps(obs Observation, stats ToolStats) (gapMs, prevGapMs int64) {
	if obs.DecisionStage == "pre_tool" {
		if stats.LastSeenMs <= 0 || obs.UnixMillis <= 0 {
			return -1, -1
		}
		return obs.UnixMillis - stats.LastSeenMs, stats.LastGapMs
	}
	if stats.LastGapMs <= 0 {
		return -1, -1
	}
	return stats.LastGapMs, stats.PrevGapMs
}

// isBackoffRetry recognizes the exponential-backoff retry shape: a shallow
// same-args streak on a retryable failure class whose inter-call gaps are
// growing by at least backoffGrowthRatio. The depth cap keeps this from ever
// exempting a deep loop — past it, the usual repeat signals apply in full.
const (
	backoffGrowthRatio = 1.3
	maxBackoffRetries  = 5
)

func isBackoffRetry(resultClass string, stats ToolStats, gapMs, prevGapMs int64) bool {
	switch normalizeResultClass(resultClass) {
	case ResultRateLimited, ResultTimeout, ResultUnknownError:
	default:
		return false
	}
	if stats.SameArgsCount > maxBackoffRetries {
		return false
	}
	if gapMs <= 0 || prevGapMs <= 0 {
		return false
	}
	return float64(gapMs) >= backoffGrowthRatio*float64(prevGapMs)
}

func assessProgress(obs Observation, resultClass string, profile ToolProfile, stats ToolStats) progressLevel {
	// updateToolStats already ran before this is called, so stats.LastStateDeltaHash
	// equals obs.StateDeltaHash — comparing them directly is always equal. Instead,
	// use SameStateDeltaCount: updateToolStats sets it to 1 when the hash just changed
	// and increments when it repeats. SameStateDeltaCount==1 means the hash changed.
	if obs.StateDeltaHash == "" || stats.SameStateDeltaCount != 1 {
		return progressNone
	}
	if profile.TrustedStateDelta {
		return progressTrusted
	}
	return progressReported
}

func evaluateSignals(s State, facts detectorFacts, cfg Config) []signal {
	var out []signal
	n := facts.MaxRepeated

	// At pre_tool the proposed call has no result yet. The handler injects an empty
	// result, so result-based signals (noop/result-homogeneity/state-delta/failure-drift/
	// state-agnostic-repeat) must be suppressed here — an absent result is not evidence
	// of no progress. Call-based signals (identical/alternating/cycle repeat) DO run, so
	// "this exact action already failed N times" can be blocked before it executes.
	preTool := facts.Obs.DecisionStage == "pre_tool"

	identical := checkRepeatedN(s.CallHistory, n)
	if identical && isWithinBurstAllowance(s.CallHistory, cfg) {
		identical = false
	}
	// Pending-under-bound: tool is legitimately polling; don't fire on repeated pending.
	// progressReported (changing StateDeltaHash) suppresses noop-type signals the same
	// way v2.2.0's stateProgress did — the tool reported external change, so we defer.
	if identical && facts.Progress == progressNone && sameNoProgressResult(facts, n) && !pendingUnderBound(facts) &&
		!facts.BackoffRetry && !facts.ScheduledRepeat {
		out = append(out, sig("identical_repeat", 1.0, true, true,
			fmt.Sprintf("same tool+args repeated %d times with %s", n, facts.ResultClass)))
	}

	if checkAlternatingN(s.CallHistory, n) && facts.Progress == progressNone {
		out = append(out, sig("alternating_repeat", 0.75, true, true,
			fmt.Sprintf("alternating call pattern repeated over last %d calls", 2*n)))
	}

	if !preTool && checkNoopN(s.ResultHistory, n) && facts.Progress == progressNone && !pendingUnderBound(facts) &&
		!facts.BackoffRetry && !facts.ScheduledRepeat && !batchShaped(facts) {
		// When args are changing with a non-failure result (batch normalizer: different
		// inputs, same output), treat as partial progress — don't mark as hard proof.
		noopHard := !facts.ArgsChanging || isNoProgressClass(facts.ResultClass)
		fpr := "low"
		if !noopHard {
			fpr = "medium"
		}
		out = append(out, signal{
			Name: "noop_repeat", Strength: 0.80, NoProgress: true, HardProof: noopHard,
			Evidence:          []string{fmt.Sprintf("same tool result repeated %d times", n)},
			FalsePositiveRisk: fpr,
		})
	}

	if period, cyc := detectCallCycle(s.CallHistory, s.CallHistory.cap/2); cyc &&
		facts.Progress == progressNone && !pendingUnderBound(facts) && !facts.ScheduledRepeat &&
		(repeatedNoProgressResult(s, n) || noProgressClassRun(s.ResultHistory, 2*period)) {
		out = append(out, sig("cycle_repeat", 0.85, true, true,
			fmt.Sprintf("cyclic tool pattern (period %d) repeated without trusted progress", period)))
	}

	if checkArgsHomogeneity(s.CallHistory, cfg) && facts.Progress == progressNone {
		out = append(out, sig("args_homogeneity", 0.45, true, false,
			"same args reused across different tools"))
	}

	if !preTool && checkResultHomogeneity(s.ResultHistory, cfg) && facts.Progress == progressNone && !pendingUnderBound(facts) {
		out = append(out, sig("result_homogeneity", 0.45, true, false,
			"same result reused across different tools"))
	}

	if !preTool && facts.Stats.SameFailureChangingArgsCount >= n && facts.Progress != progressTrusted {
		out = append(out, sig("same_failure_arg_drift", 0.95, true, true,
			fmt.Sprintf("same failure class %s repeated while args changed %d times", facts.ResultClass, facts.Stats.SameFailureChangingArgsCount)))
	}

	// no_state_delta: StateDeltaHash is present but hasn't changed — trusted proof that
	// the tool's reported output is frozen. Only fire when StateDeltaHash is not advancing
	// (progressReported means it IS changing, so suppress).
	if !preTool && facts.Stats.SameStateDeltaCount >= n && facts.Obs.StateDeltaHash != "" && facts.Progress == progressNone {
		out = append(out, sig("no_state_delta", 0.80, true, true,
			fmt.Sprintf("same state delta repeated %d times", facts.Stats.SameStateDeltaCount)))
	}

	if !preTool && facts.Stats.SameArgsAndClassCount >= facts.DeepRepeated && isNoProgressClass(facts.ResultClass) {
		out = append(out, sig("state_agnostic_repeat", 1.0, true, true,
			fmt.Sprintf("same args + %s repeated %d times ignoring reported state churn", facts.ResultClass, facts.Stats.SameArgsAndClassCount)))
	}

	// near_identical_repeat: the same call repeated under argument
	// canonicalization (case / whitespace paraphrases) while the exact hashes
	// differ. Soft evidence — textual variation of one query is how agents
	// disguise a stuck loop, but it can also be sloppy legitimate retries, so
	// this warns and never carries hard proof on its own.
	if facts.Stats.SameCanonArgsCount >= facts.DeepRepeated &&
		facts.Stats.SameArgsCount < facts.DeepRepeated &&
		facts.Progress != progressTrusted &&
		!pendingUnderBound(facts) &&
		!facts.ScheduledRepeat && !facts.BackoffRetry {
		out = append(out, signal{
			Name: "near_identical_repeat", Strength: 1.0, NoProgress: true,
			Evidence: []string{fmt.Sprintf(
				"canonically identical call repeated %d times with varying surface form",
				facts.Stats.SameCanonArgsCount)},
			FalsePositiveRisk: "medium",
		})
	}

	// deep_call_repeat: the same exact call fired past the deep threshold at
	// high frequency with no trusted progress — even when each response varies
	// (rotating ids, fresh handles). This is the self-triggering storm shape
	// (Cloudflare A20): result variance must not hide a call storm. Scheduled
	// repeats, bounded polling, and backoff retries are exempt by construction.
	if facts.Stats.SameArgsCount >= facts.DeepRepeated &&
		facts.Progress != progressTrusted &&
		!pendingUnderBound(facts) &&
		!facts.ScheduledRepeat && !facts.BackoffRetry {
		out = append(out, sig("deep_call_repeat", 0.95, true, true,
			fmt.Sprintf("identical call repeated %d times at high frequency without trusted progress", facts.Stats.SameArgsCount)))
	}

	if facts.PendingExceeded {
		out = append(out, sig("pending_exceeded_bound", 0.95, true, true, pendingEvidence(facts)))
	} else if facts.ResultClass == ResultPending {
		out = append(out, signal{Name: "pending_polling", Strength: 0.10, Evidence: []string{"pending result is within configured polling bounds"}, FalsePositiveRisk: "medium"})
	}

	if cheapMechanicalLoop(facts) && !pendingUnderBound(facts) {
		out = append(out, sig("cheap_mechanical_loop", 0.90, true, true,
			"deep mechanical no-progress loop detected even though cost is low"))
	}

	// cost_camouflage: cross-tool slow-burn detection. Catches loops that spread
	// repetition across tool switches to evade consecutive-streak signals.
	if hasCostCamouflage(s, facts, cfg) && !pendingUnderBound(facts) {
		out = append(out, sig("cost_camouflage", 0.90, true, true,
			"slow-burn cross-tool loop: same args+result class repeated with significant total cost"))
	}

	if facts.CostRatio > cfg.VelocityAccelRatio {
		out = append(out, signal{
			Name:              "cost_velocity_accel",
			Strength:          clamp((facts.CostRatio-1.0)/2.0, 0, 1),
			Evidence:          []string{fmt.Sprintf("recent cost velocity %.2fx exceeds %.2fx", facts.CostRatio, cfg.VelocityAccelRatio)},
			FalsePositiveRisk: "medium",
		})
	}

	if contextRunaway(s.ContextSizes, cfg.MinContextGrowth) {
		out = append(out, signal{Name: "context_growth", Strength: 0.70, Evidence: []string{fmt.Sprintf("prompt context grew by at least %d tokens", cfg.MinContextGrowth)}, FalsePositiveRisk: "high"})
	}

	if outputDegrading(s.OutputSizes, s.ContextSizes, 0.6) {
		out = append(out, signal{Name: "output_degradation", Strength: 0.55, NoProgress: true, Evidence: []string{"output size degraded while context continued growing"}, FalsePositiveRisk: "medium"})
	}

	if deepNoProgress(s, facts) {
		// Batch normalizer: same tool, changing args, uniform non-failure result.
		// Suspicious but not conclusive — raise score without triggering block floor.
		batchNoop := facts.ArgsChanging && !isNoProgressClass(facts.ResultClass)
		fpr := "low"
		if batchNoop {
			fpr = "medium"
		}
		out = append(out, signal{
			Name: "sustained_repetition", Strength: 1.0, NoProgress: true, HardProof: !batchNoop,
			Evidence:          []string{fmt.Sprintf("no-progress repetition reached deep threshold %d", facts.DeepRepeated)},
			FalsePositiveRisk: fpr,
		})
	}

	return dedupeSignals(out)
}

func sig(name string, strength float64, noProgress, hard bool, evidence string) signal {
	return signal{Name: name, Strength: strength, NoProgress: noProgress, HardProof: hard, Evidence: []string{evidence}, FalsePositiveRisk: "low"}
}

func sameNoProgressResult(facts detectorFacts, n int) bool {
	return facts.Stats.SameResultCount >= n || facts.Stats.SameFailureChangingArgsCount >= n || facts.Stats.SameStateDeltaCount >= n || isNoProgressClass(facts.ResultClass)
}

func repeatedNoProgressResult(s State, n int) bool {
	return checkNoopN(s.ResultHistory, n) || checkResultHomogeneityN(s.ResultHistory, n)
}

func pendingUnderBound(facts detectorFacts) bool {
	return facts.ResultClass == ResultPending && !facts.PendingExceeded
}

// batchShaped: changing args, a non-failure result, AND a run of distinct
// idempotency keys is the well-keyed batch-writer shape — many tools return
// the same tiny success ack for every distinct row, and the fresh key per call
// is the caller's proof of distinct intent. Without keys, uniform acks over
// changing args still warrant a warning (the agent may be ignoring output).
func batchShaped(facts detectorFacts) bool {
	return facts.ArgsChanging &&
		!isNoProgressClass(facts.ResultClass) &&
		facts.Stats.DistinctKeyStreak >= facts.MaxRepeated
}

func pendingExceeded(stats ToolStats, profile ToolProfile, cfg Config) bool {
	if stats.LastResultClass != ResultPending && stats.PendingCount == 0 {
		return false
	}
	// Unprofiled tools get the same default tolerance as a polling profile:
	// pending is a normal transient state for many tools (job queues, deploys),
	// and zero tolerance blocks every opaque poll loop after a handful of
	// calls. Pending is still never a bypass — count, duration, and cost
	// bounds all apply; explicit profiles tune them.
	maxCount := profile.MaxPendingCount
	if maxCount <= 0 {
		maxCount = 12
	}
	maxDuration := profile.MaxPendingDurationMs
	if maxDuration <= 0 {
		maxDuration = 120_000
	}
	maxCost := profile.MaxPendingCostUSD
	if maxCost <= 0 {
		maxCost = 0.10
	}
	duration := int64(0)
	if stats.PendingStartMs > 0 && stats.LastSeenMs > 0 {
		duration = stats.LastSeenMs - stats.PendingStartMs
	}
	return stats.PendingCount > maxCount || (duration > maxDuration && stats.PendingCount > 1) || stats.PendingCostUSD > maxCost
}

func pendingEvidence(f detectorFacts) string {
	duration := int64(0)
	if f.Stats.PendingStartMs > 0 && f.Stats.LastSeenMs > 0 {
		duration = f.Stats.LastSeenMs - f.Stats.PendingStartMs
	}
	return fmt.Sprintf("pending repeated count=%d duration_ms=%d cost_usd=%.4f", f.Stats.PendingCount, duration, f.Stats.PendingCostUSD)
}

func cheapMechanicalLoop(facts detectorFacts) bool {
	deep := facts.DeepRepeated
	return facts.Stats.SameArgsAndClassCount >= deep ||
		(facts.Stats.SameArgsCount >= deep && isNoProgressClass(facts.ResultClass)) ||
		facts.Stats.SameFailureChangingArgsCount >= deep
}

// hasCostCamouflage detects slow-burn cross-tool loops: a tool that has
// accumulated the deep repeat threshold of same-args + same-result across
// non-consecutive calls (interleaved with other tools), with meaningful cost.
// This catches loops that evade consecutive-streak signals by switching tools.
func hasCostCamouflage(s State, facts detectorFacts, cfg Config) bool {
	now := facts.Obs.UnixMillis
	if now == 0 && s.CostWindow != nil {
		now = s.CostWindow.headTime
	}
	window := cfg.VelocityWindowMs
	if window <= 0 {
		window = DefaultConfig().VelocityWindowMs
	}
	for tool, stats := range s.ToolStats {
		threshold := 2 * effectiveMaxRepeated(tool, cfg)
		if tool == "" || stats.TotalCalls < threshold {
			continue
		}
		if stats.SameArgsCount < threshold {
			continue
		}
		if stats.SameResultCount < threshold && stats.SameFailureChangingArgsCount < threshold {
			continue
		}
		if stats.TotalCost < 0.05 {
			continue
		}
		if now > 0 && stats.LastSeenMs > 0 && now-stats.LastSeenMs > window {
			continue
		}
		return true
	}
	return false
}

func deepNoProgress(s State, facts detectorFacts) bool {
	deep := facts.DeepRepeated
	if facts.Progress == progressTrusted {
		return false
	}
	// Scheduled repeats (cron-shaped successful calls on long gaps) and
	// shallow backoff retries are healthy patterns, not deep loops.
	if facts.ScheduledRepeat || facts.BackoffRetry {
		return false
	}
	// Pending under bound: tool is legitimately polling — suppress repetition checks.
	polling := pendingUnderBound(facts)
	// Reported progress (changing StateDeltaHash) suppresses noop/result-homogeneity
	// the same way v2.2.0's stateProgress did — defer to the tool's reported change.
	// Batch-shaped uniform acks (changing args, non-failure result) are weak
	// evidence and are excluded the same way.
	noopAllowed := !polling && facts.Progress == progressNone && !batchShaped(facts)
	// Cycle detection requires corroborating result evidence; identical call-history
	// from polling or batch work looks like a cycle but is not a stuck loop.
	cycleWithEvidence := noopAllowed && checkCycleN(s.CallHistory, deep/2) && repeatedNoProgressResult(s, facts.MaxRepeated)
	return (!polling && checkRepeatedN(s.CallHistory, deep) && sameNoProgressResult(facts, facts.MaxRepeated)) ||
		checkAlternatingN(s.CallHistory, facts.MaxRepeated) ||
		(noopAllowed && checkNoopN(s.ResultHistory, deep)) ||
		(noopAllowed && checkResultHomogeneityN(s.ResultHistory, deep)) ||
		cycleWithEvidence ||
		facts.Stats.SameArgsAndClassCount >= deep ||
		facts.Stats.SameFailureChangingArgsCount >= deep ||
		facts.Stats.SameStateDeltaCount >= deep ||
		facts.PendingExceeded
}

func scoreSignals(signals []signal, facts detectorFacts, cfg Config) float64 {
	var mechanical, cost, context, output float64
	for _, s := range signals {
		switch s.Name {
		case "cost_velocity_accel":
			cost = maxFloat(cost, s.Strength)
		case "context_growth":
			context = maxFloat(context, s.Strength)
		case "output_degradation":
			output = maxFloat(output, s.Strength)
		case "pending_polling":
		default:
			mechanical = maxFloat(mechanical, s.Strength)
		}
	}
	score := 0.40*mechanical + 0.35*cost + 0.15*context + 0.10*output
	if facts.Progress == progressReported && !hasHardProof(signals) {
		score *= 0.65
	}
	if facts.Progress == progressTrusted {
		score *= 0.25
	}
	if facts.ArgsChanging && !hasNoProgressProof(signals) {
		score *= 0.35
	}
	if hasHardProof(signals) {
		score = maxFloat(score, cfg.WarnConfidence+0.05)
	}
	if hasHardNoProgress(signals) {
		score = maxFloat(score, cfg.BlockConfidence+0.05)
	}
	return clamp(score, 0, 1)
}

func chooseAction(score float64, signals []signal, facts detectorFacts, cfg Config) Action {
	if len(signals) == 0 || !hasMeaningfulSignal(signals) {
		return ActionNone
	}
	canBlockSession := !cfg.RequireSessionForBlock || facts.HadSession
	if canBlockSession && facts.Progress != progressTrusted && hasHardNoProgress(signals) && score >= cfg.BlockConfidence {
		return ActionBlock
	}
	if score >= cfg.WarnConfidence {
		return ActionWarn
	}
	return ActionNone
}

func hasMeaningfulSignal(signals []signal) bool {
	for _, s := range signals {
		if s.Name != "pending_polling" {
			return true
		}
	}
	return false
}

func hasHardProof(signals []signal) bool {
	for _, s := range signals {
		if s.HardProof {
			return true
		}
	}
	return false
}

func hasNoProgressProof(signals []signal) bool {
	for _, s := range signals {
		if s.NoProgress {
			return true
		}
	}
	return false
}

func hasHardNoProgress(signals []signal) bool {
	for _, s := range signals {
		if s.HardProof && s.NoProgress {
			return true
		}
	}
	return false
}

func needsSemanticReview(signals []signal, facts detectorFacts, ceiling Action) bool {
	if ceiling != ActionWarn || facts.Progress == progressTrusted {
		return false
	}
	hasContext, hasExact := false, false
	for _, s := range signals {
		if s.Name == "context_growth" {
			hasContext = true
		}
		if s.Name == "identical_repeat" || s.Name == "state_agnostic_repeat" {
			hasExact = true
		}
	}
	return hasContext && facts.ArgsChanging && !hasExact
}

func evidenceStrings(signals []signal, facts detectorFacts) []string {
	out := make([]string, 0, len(signals)+2)
	for _, s := range signals {
		if s.Name == "pending_polling" {
			continue
		}
		for _, e := range s.Evidence {
			out = append(out, s.Name+": "+e)
		}
	}
	if facts.Progress != progressNone {
		out = append(out, "progress: "+facts.Progress.String())
	}
	if !facts.HadSession {
		out = append(out, "session: missing; block is capped when RequireSessionForBlock=true")
	}
	return out
}

func signalNames(signals []signal) []string {
	out := make([]string, 0, len(signals))
	for _, s := range signals {
		if s.Name == "pending_polling" {
			continue
		}
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}

func reasonFromEvidence(a Action, signals []signal) string {
	if a == ActionNone {
		return "No loop pattern detected."
	}
	d := dominantSignal(signals)
	prefix := "Possible loop forming"
	if a == ActionBlock {
		prefix = "Runaway loop"
	}
	if d.Name == "" || len(d.Evidence) == 0 {
		return prefix + "."
	}
	return prefix + ": " + d.Evidence[0] + "."
}

func dominantSignal(signals []signal) signal {
	var best signal
	for _, s := range signals {
		if s.Name == "pending_polling" {
			continue
		}
		if s.HardProof && !best.HardProof {
			best = s
			continue
		}
		if s.HardProof == best.HardProof && s.Strength > best.Strength {
			best = s
		}
	}
	return best
}

func dedupeSignals(in []signal) []signal {
	seen := map[string]bool{}
	out := make([]signal, 0, len(in))
	for _, s := range in {
		if seen[s.Name] {
			continue
		}
		seen[s.Name] = true
		out = append(out, s)
	}
	return out
}

// ---------- Signal helpers ----------

func checkRepeated(h *ringBuf[callKey], cfg Config) bool { return checkRepeatedN(h, cfg.MaxRepeated) }

func checkRepeatedN(h *ringBuf[callKey], n int) bool {
	if n <= 0 {
		n = DefaultConfig().MaxRepeated
	}
	if h.len < n {
		return false
	}
	ref := h.last()
	for i := 1; i < n; i++ {
		if h.get(h.len-1-i) != ref {
			return false
		}
	}
	return true
}

func checkAlternating(h *ringBuf[callKey], cfg Config) bool {
	return checkAlternatingN(h, cfg.MaxRepeated)
}

func checkAlternatingN(h *ringBuf[callKey], n int) bool {
	if n <= 0 {
		n = DefaultConfig().MaxRepeated
	}
	m := n * 2
	if h.len < m {
		return false
	}
	a := h.get(h.len - m)
	b := h.get(h.len - m + 1)
	if a == b {
		return false
	}
	for i := 0; i < m; i++ {
		want := a
		if i%2 == 1 {
			want = b
		}
		if h.get(h.len-m+i) != want {
			return false
		}
	}
	return true
}

func checkNoop(h *ringBuf[resultKey], cfg Config) bool { return checkNoopN(h, cfg.MaxRepeated) }

func checkNoopN(h *ringBuf[resultKey], n int) bool {
	if n <= 0 {
		n = DefaultConfig().MaxRepeated
	}
	if h.len < n {
		return false
	}
	ref := h.last()
	for i := 1; i < n; i++ {
		if h.get(h.len-1-i) != ref {
			return false
		}
	}
	return true
}

func checkCycle(h *ringBuf[callKey]) bool { return checkCycleN(h, 16) }

func checkCycleN(h *ringBuf[callKey], maxPeriod int) bool {
	_, ok := detectCallCycle(h, maxPeriod)
	return ok
}

// detectCallCycle reports the shortest repeating call-pattern period (two full
// consecutive repetitions of a period-p sequence in the recent history).
func detectCallCycle(h *ringBuf[callKey], maxPeriod int) (int, bool) {
	for period := 3; period <= maxPeriod; period++ {
		needed := period * 2
		if h.len < needed {
			continue
		}
		start := h.len - needed
		match := true
		for i := period; i < needed; i++ {
			if h.get(start+i) != h.get(start+i-period) {
				match = false
				break
			}
		}
		if match {
			return period, true
		}
	}
	return 0, false
}

// noProgressClassRun reports whether the last n results ALL carry a
// no-progress class (failures, empties). Long macro-cycles vary their result
// bodies per tool, so hash-based corroboration misses them — but a full cycle
// of nothing-but-failures is stuck regardless of what each failure looks like.
func noProgressClassRun(h *ringBuf[resultKey], n int) bool {
	if n <= 0 || h.len < n {
		return false
	}
	for i := h.len - n; i < h.len; i++ {
		if !isNoProgressClass(h.get(i).ResultClass) {
			return false
		}
	}
	return true
}

func checkArgsHomogeneity(h *ringBuf[callKey], cfg Config) bool {
	n := cfg.MaxRepeated
	if n <= 0 {
		n = DefaultConfig().MaxRepeated
	}
	if h.len < n {
		return false
	}
	tail := h.slice(h.len-n, h.len)
	first := tail[0]
	sameTool := true
	for _, e := range tail {
		if e.Tool != first.Tool {
			sameTool = false
		}
		if e.ArgsHash != first.ArgsHash {
			return false
		}
	}
	return !sameTool
}

func checkResultHomogeneity(h *ringBuf[resultKey], cfg Config) bool {
	n := cfg.MaxRepeated
	if n <= 0 {
		n = DefaultConfig().MaxRepeated
	}
	return checkResultHomogeneityN(h, n)
}

func checkResultHomogeneityN(h *ringBuf[resultKey], n int) bool {
	if n <= 0 {
		n = DefaultConfig().MaxRepeated
	}
	if h.len < n {
		return false
	}
	tail := h.slice(h.len-n, h.len)
	first := tail[0]
	sameTool := true
	for _, e := range tail {
		if e.Tool != first.Tool {
			sameTool = false
		}
		if e.ResultHash != first.ResultHash {
			return false
		}
	}
	return !sameTool
}

func isWithinBurstAllowance(h *ringBuf[callKey], cfg Config) bool {
	if h.len < 2 {
		return false
	}
	last := h.last()
	profile, ok := cfg.ToolProfiles[last.Tool]
	if !ok || profile.BurstAllowance <= 0 {
		return false
	}
	count := 1
	for i := h.len - 2; i >= 0 && h.get(i) == last; i-- {
		count++
	}
	return count <= profile.BurstAllowance+1
}

// ---------- State updates ----------

func (s *State) updateToolStats(obs Observation, argsHash, resultHash, resultClass string) {
	stats := s.ToolStats[obs.ToolName]
	stale := stats.LastSeenMs > 0 && obs.UnixMillis > 0 && obs.UnixMillis-stats.LastSeenMs > perToolStreakGapMs
	if stale {
		stats.SameArgsCount = 0
		stats.SameResultCount = 0
		stats.SameFailureChangingArgsCount = 0
		stats.SameStateDeltaCount = 0
		stats.SameArgsAndClassCount = 0
		stats.PendingCount = 0
		stats.PendingCostUSD = 0
		stats.PendingStartMs = 0
		stats.DistinctKeyStreak = 0
		stats.LastIdemKeyHash = ""
		stats.SameCanonArgsCount = 0
	}

	stats.TotalCalls++
	stats.TotalCost += obs.CostUSD
	if stats.LastSeenMs > 0 && obs.UnixMillis > 0 {
		stats.PrevGapMs = stats.LastGapMs
		stats.LastGapMs = obs.UnixMillis - stats.LastSeenMs
	}
	stats.LastSeenMs = obs.UnixMillis

	if stats.LastArgsHash == "" || stats.LastArgsHash == argsHash {
		stats.SameArgsCount++
	} else {
		stats.SameArgsCount = 1
	}

	canonHash := hashAny(canonicalizeValue(obs.Args))
	if stats.LastCanonArgsHash == "" || stats.LastCanonArgsHash == canonHash {
		stats.SameCanonArgsCount++
	} else {
		stats.SameCanonArgsCount = 1
	}
	stats.LastCanonArgsHash = canonHash

	if stats.LastResultHash == "" || stats.LastResultHash == resultHash {
		stats.SameResultCount++
	} else {
		stats.SameResultCount = 1
	}

	stateChanged := obs.StateDeltaHash != "" && stats.LastStateDeltaHash != "" && stats.LastStateDeltaHash != obs.StateDeltaHash
	if stats.LastArgsHash != "" && stats.LastArgsHash != argsHash && stats.LastResultClass == resultClass && isNoProgressClass(resultClass) && !stateChanged {
		stats.SameFailureChangingArgsCount++
	} else if stats.LastResultClass != resultClass || !isNoProgressClass(resultClass) || stateChanged {
		stats.SameFailureChangingArgsCount = 0
	}

	if obs.StateDeltaHash != "" {
		if stats.LastStateDeltaHash == obs.StateDeltaHash {
			stats.SameStateDeltaCount++
		} else {
			stats.SameStateDeltaCount = 1
		}
	}

	if argsHash == stats.LastArgsHash && isNoProgressClass(resultClass) && resultClass == stats.LastResultClass {
		stats.SameArgsAndClassCount++
	} else {
		stats.SameArgsAndClassCount = 1
	}

	if resultClass == ResultPending {
		if stats.PendingCount == 0 {
			stats.PendingStartMs = obs.UnixMillis
		}
		stats.PendingCount++
		stats.PendingCostUSD += obs.CostUSD
	} else {
		if stats.PendingCount > 0 && !isFailureClass(resultClass) {
			// A pending streak that resolved without failure was legitimate
			// waiting, not loop iterations — the accumulated same-args streak
			// must not trip deep-repeat signals on the completion call.
			stats.SameArgsCount = 1
			stats.SameResultCount = 1
			stats.SameArgsAndClassCount = 1
			stats.SameCanonArgsCount = 1
		}
		stats.PendingCount = 0
		stats.PendingCostUSD = 0
		stats.PendingStartMs = 0
	}

	if obs.IdempotencyKey != "" {
		keyHash := hashAny(obs.IdempotencyKey)
		if stats.LastIdemKeyHash != "" && stats.LastIdemKeyHash != keyHash {
			stats.DistinctKeyStreak++
		} else {
			stats.DistinctKeyStreak = 0
		}
		stats.LastIdemKeyHash = keyHash
	} else {
		stats.DistinctKeyStreak = 0
		stats.LastIdemKeyHash = ""
	}

	stats.LastArgsHash = argsHash
	stats.LastResultHash = resultHash
	stats.LastResultClass = resultClass
	if obs.StateDeltaHash != "" {
		stats.LastStateDeltaHash = obs.StateDeltaHash
	}
	s.ToolStats[obs.ToolName] = stats
	s.LastTool = obs.ToolName
}

func strongestToolStats(s State, obs Observation) ToolStats {
	if obs.ToolName != "" {
		return s.ToolStats[obs.ToolName]
	}
	if s.LastTool != "" {
		return s.ToolStats[s.LastTool]
	}
	var best ToolStats
	for _, stats := range s.ToolStats {
		if stats.SameArgsAndClassCount > best.SameArgsAndClassCount || stats.SameFailureChangingArgsCount > best.SameFailureChangingArgsCount || stats.SameArgsCount > best.SameArgsCount || stats.TotalCost > best.TotalCost {
			best = stats
		}
	}
	return best
}

func effectiveMaxRepeated(tool string, cfg Config) int {
	n := cfg.MaxRepeated
	if cfg.ToolProfiles != nil {
		if profile, ok := cfg.ToolProfiles[tool]; ok && profile.MaxRepeated > 0 {
			n = profile.MaxRepeated
		}
	}
	if n <= 0 {
		return DefaultConfig().MaxRepeated
	}
	return n
}

// ---------- Context / output signals ----------

func contextRunaway(sizes *ringIntBuf, minAbsoluteGrowth int) bool {
	if minAbsoluteGrowth <= 0 {
		minAbsoluteGrowth = DefaultConfig().MinContextGrowth
	}
	if sizes.len < 6 {
		return false
	}
	arr := sizes.slice(sizes.len-6, sizes.len)
	grew := 0
	for i := 1; i < len(arr); i++ {
		if arr[i] > arr[i-1] {
			grew++
		}
	}
	return grew >= 4 && arr[len(arr)-1]-arr[0] >= minAbsoluteGrowth
}

func outputDegrading(out, ctx *ringIntBuf, ratio float64) bool {
	if out.len < 6 || ctx.len < 2 {
		return false
	}
	recent := median3(out.slice(out.len-3, out.len))
	prior := median3(out.slice(out.len-6, out.len-3))
	contextGrowing := ctx.get(ctx.len-1) > ctx.get(ctx.len-2)
	return prior > 0 && recent < prior*ratio && contextGrowing
}

// ---------- Cost window ----------

type costWindow struct {
	buckets     []float64
	head        int
	headTime    int64
	full        bool
	recentSum   float64
	priorSum    float64
	half        int
	firstSeenMs int64
	lastSeenMs  int64
}

func newCostWindow() *costWindow { return newCostWindowWith(300_000, 1000) }

func newCostWindowWith(windowMs, resolutionMs int64) *costWindow {
	half := int(windowMs / resolutionMs)
	if half < 1 {
		half = 1
	}
	return &costWindow{buckets: make([]float64, half*2), half: half, head: -1}
}

func (w *costWindow) add(nowMs int64, cost float64) {
	if nowMs <= 0 {
		if w.lastSeenMs > 0 {
			nowMs = w.lastSeenMs + 1000
		} else {
			nowMs = 1000
		}
	}
	if w.firstSeenMs == 0 {
		w.firstSeenMs = nowMs
	}
	if nowMs >= w.lastSeenMs {
		w.lastSeenMs = nowMs
	}

	bucketTime := (nowMs / 1000) * 1000
	if w.head == -1 {
		w.head = 0
		w.headTime = bucketTime
		w.buckets[0] = cost
		w.recentSum = cost
		return
	}
	if bucketTime < w.headTime {
		w.buckets[w.head] += cost
		w.recentSum += cost
		return
	}
	for w.headTime < bucketTime {
		w.head = (w.head + 1) % len(w.buckets)
		if w.full {
			oldRecentIdx := (w.head - w.half + len(w.buckets)) % len(w.buckets)
			w.priorSum += w.buckets[oldRecentIdx]
			w.recentSum -= w.buckets[oldRecentIdx]
		}
		w.buckets[w.head] = 0
		w.headTime += 1000
		if !w.full && w.head >= w.half {
			w.full = true
		}
	}
	w.buckets[w.head] += cost
	w.recentSum += cost
}

func (w *costWindow) velocityRatio() float64 {
	if w.recentSum < 1e-12 || w.priorSum < 1e-12 {
		return 1.0
	}
	return w.recentSum / w.priorSum
}

func (w *costWindow) observedSpan() int64 {
	if w.firstSeenMs == 0 || w.lastSeenMs == 0 || w.lastSeenMs < w.firstSeenMs {
		return 0
	}
	return w.lastSeenMs - w.firstSeenMs
}

// timeSpan is an alias for observedSpan kept for backward compatibility.
func (w *costWindow) timeSpan() int64 { return w.observedSpan() }

func (w *costWindow) clone() *costWindow {
	if w == nil {
		return newCostWindow()
	}
	return &costWindow{
		buckets:     append([]float64(nil), w.buckets...),
		head:        w.head,
		headTime:    w.headTime,
		full:        w.full,
		recentSum:   w.recentSum,
		priorSum:    w.priorSum,
		half:        w.half,
		firstSeenMs: w.firstSeenMs,
		lastSeenMs:  w.lastSeenMs,
	}
}

// ---------- Ring buffers ----------

type ringBuf[T comparable] struct {
	buf   []T
	start int
	len   int
	cap   int
}

func newRing[T comparable](cap int) *ringBuf[T] { return &ringBuf[T]{buf: make([]T, cap), cap: cap} }

func (r *ringBuf[T]) push(v T) {
	if r.len == r.cap {
		r.start = (r.start + 1) % r.cap
	} else {
		r.len++
	}
	r.buf[(r.start+r.len-1)%r.cap] = v
}

func (r *ringBuf[T]) last() T     { return r.buf[(r.start+r.len-1)%r.cap] }
func (r *ringBuf[T]) get(i int) T { return r.buf[(r.start+i)%r.cap] }
func (r *ringBuf[T]) slice(from, to int) []T {
	out := make([]T, to-from)
	for i := from; i < to; i++ {
		out[i-from] = r.get(i)
	}
	return out
}
func (r *ringBuf[T]) clone() *ringBuf[T] {
	if r == nil {
		return newRing[T](historyCap)
	}
	out := newRing[T](r.cap)
	for _, item := range r.slice(0, r.len) {
		out.push(item)
	}
	return out
}

type ringIntBuf struct {
	buf   []int
	start int
	len   int
	cap   int
}

func newIntRing(cap int) *ringIntBuf { return &ringIntBuf{buf: make([]int, cap), cap: cap} }
func (r *ringIntBuf) push(v int) {
	if r.len == r.cap {
		r.start = (r.start + 1) % r.cap
	} else {
		r.len++
	}
	r.buf[(r.start+r.len-1)%r.cap] = v
}
func (r *ringIntBuf) get(i int) int { return r.buf[(r.start+i)%r.cap] }
func (r *ringIntBuf) slice(from, to int) []int {
	out := make([]int, to-from)
	for i := from; i < to; i++ {
		out[i-from] = r.get(i)
	}
	return out
}
func (r *ringIntBuf) clone() *ringIntBuf {
	if r == nil {
		return newIntRing(32)
	}
	out := newIntRing(r.cap)
	for _, item := range r.slice(0, r.len) {
		out.push(item)
	}
	return out
}

// ---------- JSON serialization ----------

func (r *ringBuf[T]) MarshalJSON() ([]byte, error) {
	if r == nil || r.len == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(r.slice(0, r.len))
}
func (r *ringBuf[T]) UnmarshalJSON(data []byte) error {
	var items []T
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}
	c := historyCap
	if len(items) > c {
		items = items[len(items)-c:]
	}
	r.buf = make([]T, c)
	r.cap = c
	r.start = 0
	r.len = len(items)
	copy(r.buf, items)
	return nil
}
func (r *ringIntBuf) MarshalJSON() ([]byte, error) {
	if r == nil || r.len == 0 {
		return []byte("[]"), nil
	}
	return json.Marshal(r.slice(0, r.len))
}
func (r *ringIntBuf) UnmarshalJSON(data []byte) error {
	var items []int
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}
	c := 32
	if len(items) > c {
		items = items[len(items)-c:]
	}
	r.buf = make([]int, c)
	r.cap = c
	r.start = 0
	r.len = len(items)
	copy(r.buf, items)
	return nil
}

type costWindowJSON struct {
	Buckets     []float64 `json:"buckets"`
	Head        int       `json:"head"`
	HeadTime    int64     `json:"head_time"`
	Full        bool      `json:"full"`
	RecentSum   float64   `json:"recent_sum"`
	PriorSum    float64   `json:"prior_sum"`
	Half        int       `json:"half"`
	FirstSeenMs int64     `json:"first_seen_ms"`
	LastSeenMs  int64     `json:"last_seen_ms"`
}

func (w *costWindow) MarshalJSON() ([]byte, error) {
	if w == nil {
		return []byte("null"), nil
	}
	return json.Marshal(costWindowJSON{
		Buckets: w.buckets, Head: w.head, HeadTime: w.headTime,
		Full: w.full, RecentSum: w.recentSum, PriorSum: w.priorSum, Half: w.half,
		FirstSeenMs: w.firstSeenMs, LastSeenMs: w.lastSeenMs,
	})
}
func (w *costWindow) UnmarshalJSON(data []byte) error {
	var j costWindowJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}
	w.buckets = j.Buckets
	w.head = j.Head
	w.headTime = j.HeadTime
	w.full = j.Full
	w.recentSum = j.RecentSum
	w.priorSum = j.PriorSum
	w.half = j.Half
	w.firstSeenMs = j.FirstSeenMs
	w.lastSeenMs = j.LastSeenMs
	return nil
}

func (s *State) ensureInit() {
	if s.CallHistory == nil {
		s.CallHistory = newRing[callKey](historyCap)
	}
	if s.ResultHistory == nil {
		s.ResultHistory = newRing[resultKey](historyCap)
	}
	if s.ContextSizes == nil {
		s.ContextSizes = newIntRing(32)
	}
	if s.OutputSizes == nil {
		s.OutputSizes = newIntRing(32)
	}
	if s.CostWindow == nil {
		s.CostWindow = newCostWindow()
	}
	if s.ToolCallStreak == nil {
		s.ToolCallStreak = make(map[string]int)
	}
	if s.ToolStats == nil {
		s.ToolStats = make(map[string]ToolStats)
	}
}

func (s State) clone() State {
	s.ensureInit()
	out := State{
		CallHistory:    s.CallHistory.clone(),
		ResultHistory:  s.ResultHistory.clone(),
		ContextSizes:   s.ContextSizes.clone(),
		OutputSizes:    s.OutputSizes.clone(),
		CostWindow:     s.CostWindow.clone(),
		ToolCallStreak: make(map[string]int, len(s.ToolCallStreak)),
		ToolStats:      make(map[string]ToolStats, len(s.ToolStats)),
		LastTool:       s.LastTool,
		LastEventMs:    s.LastEventMs,
		PrevEventMs:    s.PrevEventMs,
	}
	for k, v := range s.ToolCallStreak {
		out.ToolCallStreak[k] = v
	}
	for k, v := range s.ToolStats {
		out.ToolStats[k] = v
	}
	return out
}

// ---------- Hashing ----------

// canonicalizeValue normalizes string content (lowercase, collapsed
// whitespace) recursively so textually paraphrased arguments hash alike.
// Numbers, booleans, and structure are preserved untouched.
func canonicalizeValue(v any) any {
	switch val := v.(type) {
	case string:
		return strings.Join(strings.Fields(strings.ToLower(val)), " ")
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, item := range val {
			out[k] = canonicalizeValue(item)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = canonicalizeValue(item)
		}
		return out
	default:
		return v
	}
}

func hashAny(v any) string {
	if s, ok := v.(string); ok {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	b, err := json.Marshal(canonical(v))
	if err != nil {
		b = []byte(stringify(v))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func canonical(v any) any {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make([][2]any, 0, len(keys))
		for _, k := range keys {
			out = append(out, [2]any{k, canonical(val[k])})
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, e := range val {
			out[i] = canonical(e)
		}
		return out
	default:
		return v
	}
}
func stringify(v any) string {
	b, _ := json.Marshal(v)
	if len(b) == 0 {
		return "null"
	}
	return string(b)
}

// ---------- Helpers ----------

func median3(x []int) float64 {
	c := append([]int(nil), x...)
	sort.Ints(c)
	return float64(c[len(c)/2])
}
func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }
func round2(v float64) float64        { return math.Round(v*100) / 100 }
func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
func isSuccessClass(class string) bool { return class == ResultSuccess || class == "partial_success" }
func textContains(s, needle string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(needle))
}
