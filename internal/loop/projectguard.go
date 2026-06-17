package loop

// Project guard: cross-session runaway detection.
//
// The session detector is blind by construction to a loop that spreads across
// sessions — an agent fleet re-dispatching the same side effect, or a single
// runaway that restarts its session every few calls. The guard tracks UNKEYED
// side-effect calls (tool + args fingerprint) at PROJECT scope inside a short
// sliding window and flags the storm shape: the same exact unkeyed write
// hammered from several distinct sessions.
//
// Deliberate exclusions keep it quiet on legitimate traffic:
//   - read-risk calls: hot-key reads across sessions are normal (caches, lookups);
//   - keyed calls: an idempotency key is proof of deliberate work, and same-key
//     duplicates are already the action firewall's domain (project-wide ledger);
//   - few sessions: concurrent agents legitimately overlap — a storm needs
//     crossSessionMinSessions distinct sessions;
//   - old activity: everything outside projectGuardWindowMs is pruned.
//
// State is bounded: at most projectGuardMaxArgs tracked fingerprints per
// project, each holding at most projectGuardSessionCap session ids.

import (
	"fmt"
	"sort"
)

const (
	projectGuardWindowMs    = int64(10 * 60 * 1000)
	projectGuardMaxArgs     = 128
	projectGuardSessionCap  = 8
	crossSessionMinSessions = 3
	crossSessionWarnCount   = 6
	crossSessionBlockCount  = 9

	SignalCrossSessionRepeat = "cross_session_repeat"
)

// ProjectArgStats tracks one (tool, args fingerprint) across sessions.
type ProjectArgStats struct {
	Tool     string   `json:"tool"`
	ArgsHash string   `json:"args_hash"`
	Count    int      `json:"count"`
	FirstMs  int64    `json:"first_ms"`
	LastMs   int64    `json:"last_ms"`
	Sessions []string `json:"sessions,omitempty"` // distinct recent session ids, capped
	Keyed    bool     `json:"keyed,omitempty"`    // any call carried an idempotency key
}

// ProjectState is the bounded project-scope guard state.
type ProjectState struct {
	Args []ProjectArgStats `json:"args,omitempty"`
}

func NewProjectState() ProjectState { return ProjectState{} }

// ObserveProject records one proposed side-effect call at project scope and
// returns the guard's decision. risk is the server-floored action risk.
func ObserveProject(ps ProjectState, obs Observation, risk string) (ProjectState, Decision) {
	if obs.ToolName == "" || obs.UnixMillis <= 0 || NormalizeActionRisk(risk) == ActionRiskRead {
		return ps, allowProjectDecision("project guard not applicable")
	}

	now := obs.UnixMillis
	kept := ps.Args[:0]
	for _, entry := range ps.Args {
		if now-entry.LastMs <= projectGuardWindowMs {
			kept = append(kept, entry)
		}
	}
	ps.Args = kept

	argsHash := hashAny(obs.Args)
	idx := -1
	for i := range ps.Args {
		if ps.Args[i].Tool == obs.ToolName && ps.Args[i].ArgsHash == argsHash {
			idx = i
			break
		}
	}
	if idx < 0 {
		if len(ps.Args) >= projectGuardMaxArgs {
			evictOldestProjectArg(&ps)
		}
		ps.Args = append(ps.Args, ProjectArgStats{
			Tool: obs.ToolName, ArgsHash: argsHash, FirstMs: now,
		})
		idx = len(ps.Args) - 1
	}

	entry := &ps.Args[idx]
	entry.Count++
	entry.LastMs = now
	if obs.IdempotencyKey != "" {
		entry.Keyed = true
	}
	if obs.SessionID != "" && !hasString(entry.Sessions, obs.SessionID) && len(entry.Sessions) < projectGuardSessionCap {
		entry.Sessions = append(entry.Sessions, obs.SessionID)
	}

	if entry.Keyed || len(entry.Sessions) < crossSessionMinSessions || entry.Count < crossSessionWarnCount {
		return ps, allowProjectDecision("no cross-session storm evidence")
	}

	evidence := []string{
		fmt.Sprintf("tool=%s", entry.Tool),
		fmt.Sprintf("identical_unkeyed_calls=%d", entry.Count),
		fmt.Sprintf("distinct_sessions=%d", len(entry.Sessions)),
		fmt.Sprintf("window_ms=%d", projectGuardWindowMs),
	}
	action := ActionWarn
	confidence := 0.55
	reason := "same unkeyed side-effect call repeating across sessions"
	if entry.Count >= crossSessionBlockCount {
		action = ActionBlock
		confidence = 0.85
		reason = "cross-session storm: identical unkeyed side-effect call hammered from multiple sessions"
	}
	return ps, Decision{
		SignalsFired:     []string{SignalCrossSessionRepeat},
		Confidence:       confidence,
		ActionCeiling:    action,
		DetectorVersion:  DetectorVersion,
		Reason:           reason,
		HadSession:       obs.SessionID != "",
		DecisionEvidence: evidence,
	}
}

func evictOldestProjectArg(ps *ProjectState) {
	sort.Slice(ps.Args, func(i, j int) bool { return ps.Args[i].LastMs > ps.Args[j].LastMs })
	ps.Args = ps.Args[:projectGuardMaxArgs-1]
}

func allowProjectDecision(reason string) Decision {
	return Decision{
		ActionCeiling:   ActionNone,
		DetectorVersion: DetectorVersion,
		Reason:          reason,
	}
}

func hasString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
