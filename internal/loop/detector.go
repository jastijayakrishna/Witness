// Package loop is Witness's runaway-loop detector.
//
// Design philosophy: this file is intentionally small, fully deterministic, and
// dependency-free (stdlib only). It is an ENFORCEMENT component — it can return a
// 429 on a customer's production traffic — so every decision it makes must be
// explainable in one sentence and reproducible from the same inputs. No ML, no
// embeddings, no model calls in the request path. Reliability beats cleverness.
//
// What it does:
//   - Three mechanical loop patterns (identical / alternating / no-op), an approach
//     proven in production by pydantic-deepagents (MIT, vstorm-co/pydantic-deepagents,
//     pydantic_deep/capabilities/stuck_loop.py). Credited in NOTICE.
//   - One deterministic PROGRESS signal that the prior art does NOT have:
//     cost-velocity acceleration. Mechanical repetition tells you the agent is
//     repeating; cost acceleration tells you it is repeating WITHOUT making progress.
//     The combination is what makes blocking safe instead of just warning.
//   - A confluence ceiling so a legitimate high-volume batch job can never be blocked.
//
// The detector is pure: feed it Observations, get a Decision. All state is passed in,
// so it is trivially unit-testable and the same trace always yields the same verdict.
// (Production wires the State to Redis; the logic here never touches I/O.)
package loop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
)

// ---------- Inputs ----------

// Observation is everything the detector learns from one proxied request/response.
// The proxy fills this in; the detector never parses raw bodies itself.
type Observation struct {
	Project       string
	SessionID     string  // "" when the client sent no X-Session-ID header
	ToolName      string  // "" for a plain completion with no tool call
	Args          any     // tool arguments (map/struct/slice); hashed, never stored raw
	Result        any     // tool result; hashed for no-op detection
	PromptTokens  int     // context size this turn
	OutputTokens  int     // output size this turn
	CostUSD       float64 // cost of this turn
	UnixMillis    int64   // when this turn happened
}

// Config holds the thresholds. Defaults are conservative and safe-by-construction.
type Config struct {
	Action             string  // operator-configured action: "shadow" (default), "warn", "block"
	MaxRepeated        int     // identical/alternating/no-op repetitions to fire (>=2). Default 3.
	VelocityAccelRatio float64 // cost(last 5m)/cost(prior 5m) above this = accelerating. Default 1.5.
	VelocityWindowMs   int64   // half-window for velocity (each window this wide). Default 300000 (5m).
	WarnConfidence     float64 // confidence to allow a warn. Default 0.40.
	BlockConfidence    float64 // confidence to allow a block. Default 0.70.
	RequireSessionForBlock bool // safety floor. Default true.
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
	}
}

// State is the per-(project,session) memory. In production this is mirrored in Redis
// with a 10-minute TTL; here it is a plain struct so the logic stays pure and testable.
// Keep the slices bounded (the detector trims them) so memory can't grow unboundedly.
type State struct {
	CallHistory   []callKey   // (tool, argsHash) per turn
	ResultHistory []resultKey // (tool, resultHash) per turn
	ContextSizes  []int       // last N prompt-token counts
	OutputSizes   []int       // last N completion-token counts
	CostEvents    []costEvent // (unixMillis, cost) within the velocity window
}

type callKey struct{ Tool, ArgsHash string }
type resultKey struct{ Tool, ResultHash string }
type costEvent struct {
	T    int64
	Cost float64
}

const historyCap = 12 // we only ever need the last 2*MaxRepeated; 12 covers MaxRepeated up to 6

// ---------- Output ----------

type Action string

const (
	ActionNone  Action = "none"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

// Decision is fully explainable: which signals fired, the confidence, the ceiling,
// and a one-line human reason. Everything a Slack alert or a 429 body needs.
// DetectorVersion is stamped on every Decision and WAL record so future
// replay and training pipelines know which algorithm made which verdict.
// Bump this string whenever detector logic changes — never omit it.
const DetectorVersion = "1.1.0"

type Decision struct {
	SignalsFired    []string // e.g. ["identical_repeat","cost_velocity_accel"]
	Confidence      float64  // 0..1
	ActionCeiling   Action   // the strongest action the evidence permits
	DetectorVersion string   // always loop.DetectorVersion — set by Observe()
	Reason        string   // one human-readable sentence
	HadSession    bool
}

// ---------- Hashing (stable, matches the proven prior art: md5-equivalent via sha256) ----------

func hashAny(v any) string {
	if s, ok := v.(string); ok {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:8])
	}
	b, err := json.Marshal(canonical(v))
	if err != nil {
		// Fall back to a stable string form; never panic in the request path.
		b = []byte(stringify(v))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

// canonical sorts map keys so {"a":1,"b":2} and {"b":2,"a":1} hash identically.
func canonical(v any) any {
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([][2]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, [2]any{k, canonical(m[k])})
	}
	return out
}

func stringify(v any) string {
	b, _ := json.Marshal(v)
	if len(b) == 0 {
		return "null"
	}
	return string(b)
}

// ---------- Ingest one observation, then evaluate ----------

// Observe updates State with one turn and returns the Decision for the session.
// Pure: (state, obs, cfg) -> (newState, decision). Same inputs, same output, always.
func Observe(s State, obs Observation, cfg Config) (State, Decision) {
	// --- update call/result history (only meaningful when a tool was used) ---
	if obs.ToolName != "" {
		s.CallHistory = appendCapped(s.CallHistory, callKey{obs.ToolName, hashAny(obs.Args)})
		s.ResultHistory = appendCappedR(s.ResultHistory, resultKey{obs.ToolName, hashAny(obs.Result)})
	}
	// --- update token trends ---
	s.ContextSizes = appendCappedInt(s.ContextSizes, obs.PromptTokens)
	s.OutputSizes = appendCappedInt(s.OutputSizes, obs.OutputTokens)
	// --- update cost window, dropping events older than 2 windows ---
	cutoff := obs.UnixMillis - 2*cfg.VelocityWindowMs
	kept := s.CostEvents[:0:0]
	for _, e := range s.CostEvents {
		if e.T >= cutoff {
			kept = append(kept, e)
		}
	}
	if obs.CostUSD > 0 {
		kept = append(kept, costEvent{obs.UnixMillis, obs.CostUSD})
	}
	s.CostEvents = kept

	return s, decide(s, obs, cfg)
}

// ---------- The four signals + confluence ----------

func decide(s State, obs Observation, cfg Config) Decision {
	var fired []string
	var s1, s2, s3, s4 float64 // magnitudes 0..1

	// S1 — mechanical repetition: identical / alternating / no-op / cycle /
	// cross-tool homogeneity. The original three patterns (identical, alternating,
	// noop) are proven in production by pydantic-deepagents (MIT). The new patterns
	// (cycle, args_homogeneity, result_homogeneity) close evasion gaps found by
	// adversarial testing: 3+ tool rotations and cross-tool identical payloads
	// were completely invisible to v1.0.0.
	identical := checkRepeated(s.CallHistory, cfg.MaxRepeated)
	alternating := checkAlternating(s.CallHistory, cfg.MaxRepeated)
	noop := checkNoop(s.ResultHistory, cfg.MaxRepeated)
	cycle := checkCycle(s.CallHistory, historyCap/2)
	argsHomogeneous := checkArgsHomogeneity(s.CallHistory, cfg.MaxRepeated)
	resultHomogeneous := checkResultHomogeneity(s.ResultHistory, cfg.MaxRepeated)
	argsChanging := !identical && repeatedTool(s.CallHistory, cfg.MaxRepeated)

	if identical || alternating || noop || cycle || argsHomogeneous || resultHomogeneous {
		s1 = 1.0
		// Report ALL matching S1 patterns — they describe different facets of the
		// same repetitive behavior and are valuable for debugging / alerting.
		if identical {
			fired = append(fired, "identical_repeat")
		}
		if alternating {
			fired = append(fired, "alternating_repeat")
		}
		if noop {
			fired = append(fired, "noop_repeat")
		}
		if cycle {
			fired = append(fired, "cycle_repeat")
		}
		if resultHomogeneous {
			fired = append(fired, "result_homogeneity")
		}
		if argsHomogeneous {
			fired = append(fired, "args_homogeneity")
		}
	}

	// S2 — cost-velocity acceleration: the deterministic PROGRESS signal.
	// Flat/linear cost = batch work (ratio ~1.0). Geometric cost = runaway (ratio >> 1).
	ratio := costVelocityRatio(s.CostEvents, obs.UnixMillis, cfg.VelocityWindowMs)
	accelerating := ratio > cfg.VelocityAccelRatio
	if accelerating {
		s2 = clamp((ratio-1.0)/2.0, 0, 1) // ratio 1.0 -> 0, ratio 3.0+ -> 1
		fired = append(fired, "cost_velocity_accel")
	}

	// S3 — context runaway growth (monotonic compounding context).
	if contextRunaway(s.ContextSizes, 0.20) {
		s3 = 1.0
		fired = append(fired, "context_growth")
	}

	// S4 — output degradation (shrinking output while context grows). Weakest corroborator.
	if outputDegrading(s.OutputSizes, s.ContextSizes, 0.6) {
		s4 = 1.0
		fired = append(fired, "output_degradation")
	}

	// Weighted confidence. S1 and S2 dominate because together they separate
	// "repeating" from "repeating without progress".
	weighted := 0.40*s1 + 0.35*s2 + 0.15*s3 + 0.10*s4

	// PROGRESS OVERRIDE — if the tool is repeating but ARGUMENTS change, that's
	// the signature of legitimate batch work (ticket 1, 2, 3...). Discount confidence.
	// However, if the RESULTS are identical despite changing args (noop/resultHomogeneous),
	// that's weaker evidence of progress — the inputs vary but produce nothing new.
	if argsChanging {
		if noop || resultHomogeneous {
			weighted *= 0.5 // partial: different inputs, same output
		} else {
			weighted *= 0.3 // full override: genuine batch work
		}
	}

	// SUSTAINED REPETITION — when stuck-ness far exceeds the base threshold, it is
	// strong enough evidence to amplify confidence and substitute for cost acceleration
	// in the block ceiling. This closes the v1.0.0 gap where flat-cost runaways
	// (100 identical failing calls at $0.05 each) could only ever reach WARN.
	deepThreshold := 2 * cfg.MaxRepeated
	deepRepetition := checkRepeated(s.CallHistory, deepThreshold) ||
		checkNoop(s.ResultHistory, deepThreshold) ||
		checkResultHomogeneity(s.ResultHistory, deepThreshold)
	if deepRepetition {
		weighted += 0.35
		fired = append(fired, "sustained_repetition")
	}

	confidence := clamp(weighted, 0, 1)

	// ---- Confluence ceiling: the safety core. ----
	// BLOCK requires ALL of: a session id, >=2 signals, evidence of stuck-ness
	// (cost acceleration OR sustained repetition over time), evidence of
	// no-progress, and high confidence. A flat-cost changing-args batch job
	// cannot satisfy this.
	//
	// Deep repetition without cost acceleration only qualifies for block when
	// the repeating calls span at least VelocityWindowMs/10 (~30s). This
	// prevents blocking legitimate rapid bursts (50 embedding calls in 2s).
	hadSession := obs.SessionID != ""
	noProgress := identical || noop || s4 > 0 || cycle || argsHomogeneous || resultHomogeneous

	costSpan := int64(0)
	if len(s.CostEvents) >= 2 {
		costSpan = s.CostEvents[len(s.CostEvents)-1].T - s.CostEvents[0].T
	}
	minSpan := cfg.VelocityWindowMs / 10
	deepQualifies := deepRepetition && costSpan >= minSpan

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

	return Decision{
		SignalsFired:    fired,
		Confidence:      round2(confidence),
		ActionCeiling:   ceiling,
		Reason:          reason(ceiling, fired, ratio, argsChanging),
		HadSession:      hadSession,
		DetectorVersion: DetectorVersion,
	}
}

// EffectiveAction caps the operator's configured action by what the evidence permits.
// Config can only RELAX (block->warn->none), never escalate past the ceiling.
func EffectiveAction(configured Action, ceiling Action) Action {
	rank := map[Action]int{ActionNone: 0, ActionWarn: 1, ActionBlock: 2}
	if rank[configured] < rank[ceiling] {
		return configured
	}
	return ceiling
}

// ---------- Signal implementations (each is a few lines, each is deterministic) ----------

func checkRepeated(h []callKey, n int) bool {
	if len(h) < n {
		return false
	}
	tail := h[len(h)-n:]
	for _, e := range tail {
		if e != tail[0] {
			return false
		}
	}
	return true
}

func checkAlternating(h []callKey, n int) bool {
	m := n * 2
	if len(h) < m {
		return false
	}
	tail := h[len(h)-m:]
	a, b := tail[0], tail[1]
	if a == b {
		return false // that's repeated, not alternating
	}
	for i := 0; i < m; i++ {
		want := a
		if i%2 == 1 {
			want = b
		}
		if tail[i] != want {
			return false
		}
	}
	return true
}

func checkNoop(h []resultKey, n int) bool {
	if len(h) < n {
		return false
	}
	tail := h[len(h)-n:]
	for _, e := range tail {
		if e != tail[0] {
			return false
		}
	}
	return true
}

// repeatedTool reports whether the same TOOL repeated N times (regardless of args).
// Combined with !identical, this is the "changing args" batch signature.
func repeatedTool(h []callKey, n int) bool {
	if len(h) < n {
		return false
	}
	tail := h[len(h)-n:]
	for _, e := range tail {
		if e.Tool != tail[0].Tool {
			return false
		}
	}
	return true
}

// checkCycle detects repeating subsequences of length 3..maxPeriod in call history.
// Catches A-B-C-A-B-C, A-B-C-D-A-B-C-D, etc. that checkAlternating (period-2 only) misses.
// Requires 2 complete cycles to fire. With historyCap=12, maxPeriod=6.
func checkCycle(h []callKey, maxPeriod int) bool {
	for period := 3; period <= maxPeriod; period++ {
		needed := period * 2
		if len(h) < needed {
			continue
		}
		tail := h[len(h)-needed:]
		match := true
		for i := period; i < needed; i++ {
			if tail[i] != tail[i-period] {
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

// checkArgsHomogeneity detects identical arguments across different tools.
// Catches the evasion where an agent retries the same payload with different tools.
func checkArgsHomogeneity(h []callKey, n int) bool {
	if len(h) < n {
		return false
	}
	tail := h[len(h)-n:]
	// Must involve multiple tools; otherwise checkRepeated already covers it.
	sameTool := true
	for _, e := range tail {
		if e.Tool != tail[0].Tool {
			sameTool = false
			break
		}
		if e.ArgsHash != tail[0].ArgsHash {
			return false
		}
	}
	if sameTool {
		return false // same tool + same args = identical_repeat, not this signal
	}
	for _, e := range tail {
		if e.ArgsHash != tail[0].ArgsHash {
			return false
		}
	}
	return true
}

// checkResultHomogeneity detects identical results across different tools (cross-tool noop).
// checkNoop requires same (tool, result) pair; this ignores the tool name.
func checkResultHomogeneity(h []resultKey, n int) bool {
	if len(h) < n {
		return false
	}
	tail := h[len(h)-n:]
	// Must involve multiple tools; otherwise checkNoop already covers it.
	sameTool := true
	for _, e := range tail {
		if e.Tool != tail[0].Tool {
			sameTool = false
		}
		if e.ResultHash != tail[0].ResultHash {
			return false
		}
	}
	return !sameTool
}

// costVelocityRatio = cost in [now-W, now] divided by cost in [now-2W, now-W].
// ~1.0 means flat (batch). >>1 means accelerating (runaway). 1.0 when no prior history.
func costVelocityRatio(events []costEvent, now, windowMs int64) float64 {
	var recent, prior float64
	for _, e := range events {
		switch {
		case e.T >= now-windowMs:
			recent += e.Cost
		case e.T >= now-2*windowMs:
			prior += e.Cost
		}
	}
	if prior < 1e-9 {
		return 1.0 // not enough history yet -> treat as neutral, never as accelerating
	}
	return recent / prior
}

// contextRunaway: 4 of the last 5 turns grew by more than pct.
func contextRunaway(sizes []int, pct float64) bool {
	if len(sizes) < 6 {
		return false
	}
	tail := sizes[len(sizes)-6:]
	grew := 0
	for i := 1; i < len(tail); i++ {
		if float64(tail[i]) > float64(tail[i-1])*(1+pct) {
			grew++
		}
	}
	return grew >= 4
}

// outputDegrading: median of last 3 outputs dropped below ratio of the prior 3,
// AND context is still growing (so it's "spinning", not just finishing up).
func outputDegrading(out, ctx []int, ratio float64) bool {
	if len(out) < 6 || len(ctx) < 2 {
		return false
	}
	recent := median3(out[len(out)-3:])
	prior := median3(out[len(out)-6 : len(out)-3])
	contextGrowing := ctx[len(ctx)-1] > ctx[len(ctx)-2]
	return prior > 0 && recent < prior*ratio && contextGrowing
}

// ---------- small helpers ----------

func reason(a Action, fired []string, ratio float64, argsChanging bool) string {
	switch a {
	case ActionBlock:
		return "Runaway: repeated calls with no progress and accelerating cost (" +
			ratioStr(ratio) + "). Session halted."
	case ActionWarn:
		if argsChanging {
			return "High-volume repetition with changing arguments — looks like legitimate batch work; watching only."
		}
		return "Possible loop forming (" + joinSignals(fired) + "); warning only."
	default:
		return "No loop pattern."
	}
}

func appendCapped(s []callKey, v callKey) []callKey {
	s = append(s, v)
	if len(s) > historyCap {
		s = s[len(s)-historyCap:]
	}
	return s
}
func appendCappedR(s []resultKey, v resultKey) []resultKey {
	s = append(s, v)
	if len(s) > historyCap {
		s = s[len(s)-historyCap:]
	}
	return s
}
func appendCappedInt(s []int, v int) []int {
	s = append(s, v)
	if len(s) > historyCap {
		s = s[len(s)-historyCap:]
	}
	return s
}

func median3(x []int) float64 {
	c := append([]int(nil), x...)
	sort.Ints(c)
	return float64(c[len(c)/2])
}
func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }
func round2(v float64) float64        { return math.Round(v*100) / 100 }

func joinSignals(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
func ratioStr(r float64) string {
	// 1.83 -> "1.8x"
	return trimZero(math.Round(r*10)/10) + "x"
}
func trimZero(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}