// Package loop is Witness's runaway-loop detector (Tier 1, Production‑Hardened).
//
// DESIGN PHILOSOPHY
//   - Pure, deterministic, dependency‑free (stdlib only).
//   - O(1) work per observation – all history is in fixed‑size ring buffers.
//   - Constant memory: cost tracking uses bucketed windows, never an unbounded slice.
//
// V2 HYBRID UPGRADES
//   - canonical() now recursively traverses slices and maps (no nested‑array evasions).
//   - Cost tracker replaced with a constant‑memory two‑window bucket ring.
//   - Context growth requires an absolute token floor (not just a percentage).
//   - HistoryCap raised to 32 to catch 8‑step cognitive cycles.
//   - NeedsSemanticReview flag for asynchronous Tier‑2 LLM/embedding analysis.
//   - Block ceiling now considers ALL mechanical patterns as no‑progress,
//     including alternating and cycling.
//   - Full 256‑bit SHA‑256 hashes – no truncation.
package loop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
)

// ---------- Configuration ----------

type Config struct {
	Action                 string                 // "shadow", "warn", "block" – operator maximum
	MaxRepeated            int                    // default 3
	VelocityAccelRatio     float64                // default 1.5
	VelocityWindowMs       int64                  // half‑window for velocity, default 5 min
	WarnConfidence         float64                // default 0.40
	BlockConfidence        float64                // default 0.70
	RequireSessionForBlock bool                   // default true – no block without session id
	MinContextGrowth       int                    // absolute token increase to flag context runaway (default 2000)
	ToolProfiles           map[string]ToolProfile // per‑tool overrides
}

type ToolProfile struct {
	MaxRepeated    int // override global MaxRepeated; 0 = use global
	BurstAllowance int // consecutive identical (tool,args) calls that are still considered normal
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
}

// ---------- State – constant memory ----------

// State holds all per‑session memory. All fields are fixed‑size rings
// or bucketed accumulators; the total memory footprint never grows.
type State struct {
	CallHistory    *ringBuf[callKey]   // last 32 (callKey = tool + full args hash)
	ResultHistory  *ringBuf[resultKey] // last 32
	ContextSizes   *ringIntBuf         // last 32
	OutputSizes    *ringIntBuf         // last 32
	CostWindow     *costWindow         // constant‑memory two‑window tracker
	ToolCallStreak map[string]int      // consecutive calls per tool (for burst allowance)
	ToolStats      map[string]ToolStats
	LastTool       string
}

type callKey struct {
	Tool     string
	ArgsHash string // full SHA‑256 hex
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
	LastArgsHash                 string
	LastResultHash               string
	LastResultClass              string
	LastStateDeltaHash           string
	TotalCost                    float64
	LastSeenMs                   int64
}

const perToolStreakGapMs = 30_000

// NewState returns a ready‑to‑use zero State.
func NewState() State {
	return State{
		CallHistory:    newRing[callKey](32),
		ResultHistory:  newRing[resultKey](32),
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

const DetectorVersion = "2.2.0"

type Decision struct {
	SignalsFired        []string
	Confidence          float64
	ActionCeiling       Action
	DetectorVersion     string
	Reason              string
	HadSession          bool
	PolicyVersion       string
	DecisionEvidence    []string
	NeedsSemanticReview bool // true → suspicious but hash‑evasive → send to Tier 2
}

// ---------- Main entry point ----------

// Decide evaluates the current state without mutating it and returns a Decision.
// Use this for read-only pre-checks (e.g., before forwarding a request) where
// you want to know if the state is looping but don't want to record an observation.
func Decide(s State, obs Observation, cfg Config) Decision {
	clone := s.clone()
	_, d := Observe(clone, obs, cfg)
	return d
}

// Observe updates State with one turn and returns a Decision. Pure, deterministic, O(1).
func Observe(s State, obs Observation, cfg Config) (State, Decision) {
	s.ensureInit()

	if obs.ToolName != "" {
		argsHash := hashAny(obs.Args)
		resultHash := hashAny(obs.Result)
		resultClass := normalizeResultClass(obs.ResultClass)
		if resultClass == "" {
			resultClass = ClassifyResult(obs.Result)
		}

		prevTool := ""
		if s.CallHistory.len > 0 {
			prevTool = s.CallHistory.last().Tool
		}
		if obs.ToolName == prevTool {
			s.ToolCallStreak[obs.ToolName]++
		} else {
			s.ToolCallStreak[obs.ToolName] = 1
		}

		s.CallHistory.push(callKey{
			Tool:     obs.ToolName,
			ArgsHash: argsHash,
		})
		s.ResultHistory.push(resultKey{
			Tool:        obs.ToolName,
			ResultHash:  resultHash,
			ResultClass: resultClass,
		})
		s.updateToolStats(obs, argsHash, resultHash, resultClass)
	}

	s.ContextSizes.push(obs.PromptTokens)
	s.OutputSizes.push(obs.OutputTokens)
	s.CostWindow.add(obs.UnixMillis, obs.CostUSD)

	return s, decide(s, obs, cfg)
}

// EffectiveAction caps the operator's configured action by the evidence.
func EffectiveAction(configured Action, ceiling Action) Action {
	rank := map[Action]int{ActionNone: 0, ActionWarn: 1, ActionBlock: 2}
	if rank[configured] < rank[ceiling] {
		return configured
	}
	return ceiling
}

// ---------- Decision core ----------

func decide(s State, obs Observation, cfg Config) Decision {
	var fired []string
	var s1, s2, s3, s4 float64

	// --- S1: Mechanical repetition (all patterns) ---
	identical := checkRepeated(s.CallHistory, cfg)
	alternating := checkAlternating(s.CallHistory, cfg)
	noop := checkNoop(s.ResultHistory, cfg)
	cycle := checkCycle(s.CallHistory) // up to period 16 (32/2)
	argsHomogeneous := checkArgsHomogeneity(s.CallHistory, cfg)
	resultHomogeneous := checkResultHomogeneity(s.ResultHistory, cfg)
	stats := strongestToolStats(s, obs, cfg)
	maxRepeated := cfg.MaxRepeated
	if maxRepeated <= 0 {
		maxRepeated = DefaultConfig().MaxRepeated
	}
	stateProgress := obs.StateDeltaHash != "" && stats.SameStateDeltaCount < maxRepeated
	if stateProgress {
		noop = false
		argsHomogeneous = false
		resultHomogeneous = false
	}
	sameFailureArgDrift := stats.SameFailureChangingArgsCount >= maxRepeated
	noStateDelta := stats.SameStateDeltaCount >= maxRepeated
	identicalNoProgress := identical && !stateProgress && (noop || stats.SameResultCount >= maxRepeated || sameFailureArgDrift || noStateDelta)
	perToolIdentical := stats.SameArgsCount >= maxRepeated && !stateProgress && (stats.SameResultCount >= maxRepeated || sameFailureArgDrift || noStateDelta)
	cycleNoProgress := cycle && !stateProgress && (noop || resultHomogeneous || sameFailureArgDrift || noStateDelta)
	costCamouflage := hasRecentCostCamouflage(s, obs, cfg)

	// Per‑tool burst allowance: suppress identical if within allowed burst.
	if identical && isWithinBurstAllowance(s.CallHistory, cfg) {
		identical = false
	}
	if identical && !identicalNoProgress {
		identical = false
	}

	if identical || alternating || noop || cycleNoProgress || argsHomogeneous || resultHomogeneous ||
		perToolIdentical || sameFailureArgDrift || noStateDelta || costCamouflage {
		s1 = 1.0
		if identical {
			fired = append(fired, "identical_repeat")
		}
		if alternating {
			fired = append(fired, "alternating_repeat")
		}
		if noop {
			fired = append(fired, "noop_repeat")
		}
		if cycleNoProgress {
			fired = append(fired, "cycle_repeat")
		}
		if resultHomogeneous {
			fired = append(fired, "result_homogeneity")
		}
		if argsHomogeneous {
			fired = append(fired, "args_homogeneity")
		}
		if perToolIdentical && !identical {
			fired = append(fired, "per_tool_identical_repeat")
		}
		if sameFailureArgDrift {
			fired = append(fired, "same_failure_arg_drift")
		}
		if noStateDelta {
			fired = append(fired, "no_state_delta")
		}
		if costCamouflage {
			fired = append(fired, "cost_camouflage")
		}
	}

	// --- S2: Cost velocity (the PROGRESS signal) ---
	ratio := s.CostWindow.velocityRatio()
	accelerating := ratio > cfg.VelocityAccelRatio
	if accelerating {
		s2 = clamp((ratio-1.0)/2.0, 0, 1)
		fired = append(fired, "cost_velocity_accel")
	}

	// --- S3: Context runaway (absolute token floor) ---
	if contextRunaway(s.ContextSizes, cfg.MinContextGrowth) {
		s3 = 1.0
		fired = append(fired, "context_growth")
	}

	// --- S4: Output degradation ---
	if outputDegrading(s.OutputSizes, s.ContextSizes, 0.6) {
		s4 = 1.0
		fired = append(fired, "output_degradation")
	}

	weighted := 0.40*s1 + 0.35*s2 + 0.15*s3 + 0.10*s4

	// Changing‑args override: same tool repeats but args change → legitimate batch?
	argsChanging := false
	if !identical && s.CallHistory.len >= maxRepeated {
		lastTool := s.CallHistory.last().Tool
		count := 0
		for i := 0; i < maxRepeated; i++ {
			if s.CallHistory.get(s.CallHistory.len-1-i).Tool == lastTool {
				count++
			}
		}
		if count == maxRepeated {
			argsChanging = true
		}
	}
	if argsChanging {
		if sameFailureArgDrift || noStateDelta || costCamouflage {
			weighted += 0.25
		} else if noop || resultHomogeneous {
			weighted *= 0.5 // different inputs, same output → partial progress
		} else {
			weighted *= 0.3 // genuine batch work
		}
	}

	// Sustained repetition (deep threshold) – covers all patterns.
	deep := 2 * maxRepeated
	deepNoProgress := !stateProgress && (checkNoopN(s.ResultHistory, deep) ||
		checkResultHomogeneityN(s.ResultHistory, deep) ||
		stats.SameResultCount >= deep ||
		stats.SameFailureChangingArgsCount >= deep ||
		stats.SameStateDeltaCount >= deep)
	deepRepetition := (checkRepeatedN(s.CallHistory, deep) && deepNoProgress) ||
		checkAlternatingN(s.CallHistory, deep) ||
		checkNoopN(s.ResultHistory, deep) ||
		checkResultHomogeneityN(s.ResultHistory, deep) ||
		(checkCycleN(s.CallHistory, deep/2) && deepNoProgress) ||
		(stats.SameArgsCount >= deep && deepNoProgress) ||
		stats.SameFailureChangingArgsCount >= deep ||
		stats.SameStateDeltaCount >= deep ||
		costCamouflage

	if deepRepetition {
		weighted += 0.35
		fired = append(fired, "sustained_repetition")
	}

	confidence := clamp(weighted, 0, 1)

	// ---- No‑progress definition (all mechanical patterns) ----
	noProgress := identicalNoProgress || alternating || noop || cycleNoProgress ||
		argsHomogeneous || resultHomogeneous ||
		perToolIdentical || sameFailureArgDrift || noStateDelta || costCamouflage ||
		outputDegrading(s.OutputSizes, s.ContextSizes, 0.6)

	// Time span for deep qualification.
	// For identical repeats we skip the time gate (stop bursts immediately).
	// For other patterns, require at least VelocityWindowMs/10 (default 30s).
	costSpan := s.CostWindow.timeSpan()
	minSpan := cfg.VelocityWindowMs / 10
	deepQualifies := deepRepetition && (identicalNoProgress || perToolIdentical || sameFailureArgDrift || noStateDelta || costCamouflage || costSpan >= minSpan)

	hadSession := obs.SessionID != ""
	ceiling := ActionNone
	switch {
	case (!cfg.RequireSessionForBlock || hadSession) &&
		len(fired) >= 2 &&
		(accelerating || deepQualifies) &&
		noProgress &&
		confidence >= cfg.BlockConfidence:
		ceiling = ActionBlock
	case len(fired) >= 1 && confidence >= cfg.WarnConfidence:
		ceiling = ActionWarn
	}

	// Semantic review hook: repeating tool with changing args, no hash match, context growing.
	needsSemanticReview := ceiling == ActionWarn && s3 > 0 &&
		repeatedToolN(s.CallHistory, cfg.MaxRepeated) && !identical

	return Decision{
		SignalsFired:        fired,
		Confidence:          round2(confidence),
		ActionCeiling:       ceiling,
		Reason:              reason(ceiling, fired, ratio, argsChanging),
		HadSession:          hadSession,
		NeedsSemanticReview: needsSemanticReview,
		DetectorVersion:     DetectorVersion,
	}
}

// ---------- Signal implementations ----------

func checkRepeated(h *ringBuf[callKey], cfg Config) bool { return checkRepeatedN(h, cfg.MaxRepeated) }
func checkRepeatedN(h *ringBuf[callKey], n int) bool {
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

func checkCycle(h *ringBuf[callKey]) bool { return checkCycleN(h, 16) } // 32/2
func checkCycleN(h *ringBuf[callKey], maxPeriod int) bool {
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
			return true
		}
	}
	return false
}

func checkArgsHomogeneity(h *ringBuf[callKey], cfg Config) bool {
	n := cfg.MaxRepeated
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
func checkResultHomogeneityN(h *ringBuf[resultKey], n int) bool {
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

// isWithinBurstAllowance returns true when the last (BurstAllowance+1) calls
// are identical and the tool's burst allowance covers them.
func isWithinBurstAllowance(h *ringBuf[callKey], cfg Config) bool {
	if h.len < 2 {
		return false
	}
	last := h.last()
	tool := last.Tool
	profile, ok := cfg.ToolProfiles[tool]
	if !ok || profile.BurstAllowance == 0 {
		return false
	}
	limit := profile.BurstAllowance + 1
	if h.len < limit {
		return false
	}
	for i := 1; i < limit; i++ {
		if h.get(h.len-1-i) != last {
			return false
		}
	}
	return true
}

// repeatedToolN returns true if the last n calls all use the same tool.
func repeatedToolN(h *ringBuf[callKey], n int) bool {
	if h.len < n {
		return false
	}
	tool := h.last().Tool
	for i := 1; i < n; i++ {
		if h.get(h.len-1-i).Tool != tool {
			return false
		}
	}
	return true
}

func (s *State) updateToolStats(obs Observation, argsHash, resultHash, resultClass string) {
	stats := s.ToolStats[obs.ToolName]
	staleStreak := stats.LastSeenMs > 0 && obs.UnixMillis > 0 && obs.UnixMillis-stats.LastSeenMs > perToolStreakGapMs
	if staleStreak {
		stats.SameArgsCount = 0
		stats.SameResultCount = 0
		stats.SameFailureChangingArgsCount = 0
		stats.SameStateDeltaCount = 0
	}
	stats.TotalCalls++
	stats.TotalCost += obs.CostUSD
	stats.LastSeenMs = obs.UnixMillis

	if stats.LastArgsHash == "" || stats.LastArgsHash == argsHash {
		stats.SameArgsCount++
	} else {
		stats.SameArgsCount = 1
	}

	if stats.LastResultHash == "" || stats.LastResultHash == resultHash {
		stats.SameResultCount++
	} else {
		stats.SameResultCount = 1
	}

	stateChanged := obs.StateDeltaHash != "" &&
		stats.LastStateDeltaHash != "" &&
		stats.LastStateDeltaHash != obs.StateDeltaHash
	if stats.LastArgsHash != "" &&
		stats.LastArgsHash != argsHash &&
		stats.LastResultClass == resultClass &&
		isNoProgressClass(resultClass) &&
		!stateChanged {
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

	stats.LastArgsHash = argsHash
	stats.LastResultHash = resultHash
	stats.LastResultClass = resultClass
	if obs.StateDeltaHash != "" {
		stats.LastStateDeltaHash = obs.StateDeltaHash
	}

	s.ToolStats[obs.ToolName] = stats
	s.LastTool = obs.ToolName
}

func strongestToolStats(s State, obs Observation, cfg Config) ToolStats {
	if obs.ToolName != "" {
		return s.ToolStats[obs.ToolName]
	}
	if s.LastTool != "" {
		return s.ToolStats[s.LastTool]
	}

	var best ToolStats
	for _, stats := range s.ToolStats {
		if stats.SameFailureChangingArgsCount > best.SameFailureChangingArgsCount ||
			stats.SameArgsCount > best.SameArgsCount ||
			stats.TotalCost > best.TotalCost {
			best = stats
		}
	}
	return best
}

func hasRecentCostCamouflage(s State, obs Observation, cfg Config) bool {
	now := obs.UnixMillis
	if now == 0 && s.CostWindow != nil {
		now = s.CostWindow.headTime
	}
	window := cfg.VelocityWindowMs
	if window <= 0 {
		window = DefaultConfig().VelocityWindowMs
	}
	for tool, stats := range s.ToolStats {
		if tool == "" || stats.TotalCalls < 2*effectiveMaxRepeated(tool, cfg) {
			continue
		}
		if stats.SameArgsCount < 2*effectiveMaxRepeated(tool, cfg) {
			continue
		}
		if stats.SameResultCount < 2*effectiveMaxRepeated(tool, cfg) && stats.SameFailureChangingArgsCount < 2*effectiveMaxRepeated(tool, cfg) {
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

// contextRunaway: requires 4 out of 5 monotonic increases AND an absolute growth
// of at least minAbsoluteGrowth tokens. This prevents false positives on small
// fluctuations and is robust for large context windows.
func contextRunaway(sizes *ringIntBuf, minAbsoluteGrowth int) bool {
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
	totalGrowth := arr[len(arr)-1] - arr[0]
	return grew >= 4 && totalGrowth >= minAbsoluteGrowth
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

// ---------- Cost window (constant memory, O(1)) ----------

// costWindow tracks cost in two fixed half‑windows using 1‑second buckets.
// Memory footprint is constant regardless of session length or event count.
type costWindow struct {
	buckets   []float64
	head      int   // index of current bucket
	headTime  int64 // UnixMillis of current bucket start (rounded to second)
	full      bool  // true once the ring has wrapped
	recentSum float64
	priorSum  float64
	half      int // number of buckets per half‑window
}

func newCostWindow() *costWindow {
	return newCostWindowWith(300_000, 1000) // 5 min half‑window, 1 sec resolution
}

func newCostWindowWith(windowMs, resolutionMs int64) *costWindow {
	half := int(windowMs / resolutionMs)
	if half < 1 {
		half = 1
	}
	return &costWindow{
		buckets: make([]float64, half*2),
		half:    half,
		head:    -1,
	}
}

func (w *costWindow) add(nowMs int64, cost float64) {
	bucketTime := (nowMs / 1000) * 1000 // floor to seconds
	if w.head == -1 {
		w.head = 0
		w.headTime = bucketTime
		w.buckets[0] = cost
		w.recentSum = cost
		return
	}

	// Advance time, clearing expired buckets
	for w.headTime < bucketTime {
		w.head = (w.head + 1) % len(w.buckets)
		if w.full {
			// The bucket about to be overwritten is moving from recent to prior.
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

// timeSpan returns a lower‑bound estimate of the total time covered (ms).
func (w *costWindow) timeSpan() int64 {
	if w.head == -1 {
		return 0
	}
	return int64(w.half*2) * 1000
}

func (w *costWindow) clone() *costWindow {
	if w == nil {
		return newCostWindow()
	}
	out := &costWindow{
		buckets:   append([]float64(nil), w.buckets...),
		head:      w.head,
		headTime:  w.headTime,
		full:      w.full,
		recentSum: w.recentSum,
		priorSum:  w.priorSum,
		half:      w.half,
	}
	return out
}

// ---------- Ring buffers ----------

type ringBuf[T comparable] struct {
	buf   []T
	start int
	len   int
	cap   int
}

func newRing[T comparable](cap int) *ringBuf[T] {
	return &ringBuf[T]{buf: make([]T, cap), cap: cap}
}

func (r *ringBuf[T]) push(v T) {
	if r.len == r.cap {
		r.start = (r.start + 1) % r.cap
	} else {
		r.len++
	}
	r.buf[(r.start+r.len-1)%r.cap] = v
}

func (r *ringBuf[T]) last() T {
	return r.buf[(r.start+r.len-1)%r.cap]
}

func (r *ringBuf[T]) get(i int) T {
	return r.buf[(r.start+i)%r.cap]
}

func (r *ringBuf[T]) slice(from, to int) []T {
	out := make([]T, to-from)
	for i := from; i < to; i++ {
		out[i-from] = r.get(i)
	}
	return out
}

func (r *ringBuf[T]) clone() *ringBuf[T] {
	if r == nil {
		return newRing[T](32)
	}
	out := newRing[T](r.cap)
	items := r.slice(0, r.len)
	for _, item := range items {
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

func newIntRing(cap int) *ringIntBuf {
	return &ringIntBuf{buf: make([]int, cap), cap: cap}
}

func (r *ringIntBuf) push(v int) {
	if r.len == r.cap {
		r.start = (r.start + 1) % r.cap
	} else {
		r.len++
	}
	r.buf[(r.start+r.len-1)%r.cap] = v
}

func (r *ringIntBuf) get(i int) int {
	return r.buf[(r.start+i)%r.cap]
}

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
	items := r.slice(0, r.len)
	for _, item := range items {
		out.push(item)
	}
	return out
}

// ---------- JSON serialization (for Redis persistence) ----------

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
	c := 32
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
	Buckets   []float64 `json:"buckets"`
	Head      int       `json:"head"`
	HeadTime  int64     `json:"head_time"`
	Full      bool      `json:"full"`
	RecentSum float64   `json:"recent_sum"`
	PriorSum  float64   `json:"prior_sum"`
	Half      int       `json:"half"`
}

func (w *costWindow) MarshalJSON() ([]byte, error) {
	if w == nil {
		return []byte("null"), nil
	}
	return json.Marshal(costWindowJSON{
		Buckets: w.buckets, Head: w.head, HeadTime: w.headTime,
		Full: w.full, RecentSum: w.recentSum, PriorSum: w.priorSum, Half: w.half,
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
	return nil
}

// ensureInit fills in nil pointer fields so the State is safe to use.
// Called after JSON deserialization or when a zero‑value State is encountered.
func (s *State) ensureInit() {
	if s.CallHistory == nil {
		s.CallHistory = newRing[callKey](32)
	}
	if s.ResultHistory == nil {
		s.ResultHistory = newRing[resultKey](32)
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
	}
	for k, v := range s.ToolCallStreak {
		out.ToolCallStreak[k] = v
	}
	for k, v := range s.ToolStats {
		out.ToolStats[k] = v
	}
	return out
}

// ---------- Hashing (full SHA‑256, canonical traverses arrays + maps) ----------

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

// ---------- Small helpers ----------

func median3(x []int) float64 {
	c := append([]int(nil), x...)
	sort.Ints(c)
	return float64(c[len(c)/2])
}

func clamp(v, lo, hi float64) float64 {
	return math.Max(lo, math.Min(hi, v))
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func reason(a Action, fired []string, ratio float64, argsChanging bool) string {
	switch a {
	case ActionBlock:
		return "Runaway loop: repeated calls with no progress and accelerating cost (" +
			ratioStr(ratio) + "). Session halted."
	case ActionWarn:
		if argsChanging {
			return "High-volume repetition with changing arguments — likely batch work; watching only."
		}
		return "Possible loop forming (" + strings.Join(fired, ", ") + "); warning only."
	default:
		return "No loop pattern detected."
	}
}

func ratioStr(r float64) string {
	return strconv.FormatFloat(r, 'f', 1, 64) + "x"
}
