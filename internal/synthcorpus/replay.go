package synthcorpus

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/hubbleops/hubbleops/internal/loop"
)

// SessionResult is the scored outcome of replaying one session.
type SessionResult struct {
	Project        string   `json:"project"`
	SessionID      string   `json:"session_id"`
	Label          string   `json:"label"`
	ExpectedAction string   `json:"expected_action"`
	ExpectedSignal string   `json:"expected_signal,omitempty"`
	SourceIncident string   `json:"source_incident,omitempty"`
	Verdict        string   `json:"verdict"` // max action across the stream: allow|warn|block
	Signals        []string `json:"signals,omitempty"`
	FirstBlock     int      `json:"first_block_event,omitempty"` // 1-based; 0 = never
	BlockReason    string   `json:"block_reason,omitempty"`
	Events         int      `json:"events"`
	TotalCostUSD   float64  `json:"total_cost_usd"`
	SavedCostUSD   float64  `json:"saved_cost_usd"` // cost of events after the first block
}

// ReplaySession drives one session through the combined pipeline exactly as the
// proxy does per tool event: pre_tool loop.Decide on the proposed call (results
// stripped) + ActionStore.Decide, then post_tool loop.Observe + ledger
// commit/release per ResultClassDisposition. The verdict is the MAX action across
// every stage of every event — never the final turn.
func ReplaySession(ctx context.Context, events []Event, cfg loop.Config, store *loop.ActionStore) (SessionResult, error) {
	res := SessionResult{Verdict: "allow", Events: len(events)}
	state := loop.NewState()
	signals := map[string]bool{}
	maxRank := 1

	record := func(d loop.Decision, eventIndex int) {
		for _, s := range d.SignalsFired {
			signals[s] = true
		}
		if r := actionRank(d.ActionCeiling); r > maxRank {
			maxRank = r
			res.Verdict = verdictName(d.ActionCeiling)
		}
		if d.ActionCeiling == loop.ActionBlock && res.FirstBlock == 0 {
			res.FirstBlock = eventIndex + 1
			res.BlockReason = d.Reason
		}
	}

	for i, ev := range events {
		if ev.Label != "" {
			res.Label = ev.Label
		}
		if ev.ExpectedAction != "" {
			res.ExpectedAction = ev.ExpectedAction
		}
		if ev.ExpectedSignal != "" {
			res.ExpectedSignal = ev.ExpectedSignal
		}
		if ev.SourceIncident != "" {
			res.SourceIncident = ev.SourceIncident
		}
		if res.Project == "" {
			res.Project, res.SessionID = ev.Project, ev.SessionID
		}
		res.TotalCostUSD += ev.CostUSD

		// ---- pre_tool: loop detector sees only the proposed call (no result). ----
		pre := loop.Decide(state, loop.Observation{
			Project:       ev.Project,
			SessionID:     ev.SessionID,
			StepID:        ev.StepID,
			DecisionStage: "pre_tool",
			ToolName:      ev.ToolName,
			Args:          ev.Args,
			UnixMillis:    ev.UnixMillis,
		}, cfg)
		record(pre, i)

		// ---- pre_tool: action firewall (idempotency, amount, backup, recipient). ----
		risk := effectiveRisk(ev)
		claimNonce := ""
		if store != nil {
			ad, err := store.Decide(ctx, loop.ActionObservation{
				Project:                ev.Project,
				SessionID:              ev.SessionID,
				StepID:                 ev.StepID,
				ToolName:               ev.ToolName,
				ActionRisk:             risk,
				RawActionRisk:          ev.ActionRisk,
				IdempotencyKey:         ev.IdempotencyKey,
				AgentID:                ev.AgentID,
				UserID:                 ev.UserID,
				ResourceID:             ev.ResourceID,
				AmountCents:            ev.AmountCents,
				MaxAmountCents:         ev.MaxAmountCents,
				BackupID:               ev.BackupID,
				Recipient:              ev.Recipient,
				AllowedDomain:          ev.AllowedDomain,
				CapabilityToken:        ev.CapabilityToken,
				DuplicateWindowSeconds: ev.DuplicateWindowSeconds,
				UnixMillis:             ev.UnixMillis,
			})
			if err != nil {
				return res, err
			}
			record(ad.Decision, i)
			// A well-behaved SDK echoes the claim nonce back on the result event so the
			// release path can prove it owns the pending lease.
			claimNonce = ad.ClaimNonce
		}

		// ---- post_tool: observe the result; same class fallback as the proxy. ----
		resultClass := loop.NormalizeResultClassForAPI(ev.ResultClass)
		if resultClass == "" {
			resultClass = loop.ClassifyResult(ev.Result)
		}
		var post loop.Decision
		state, post = loop.Observe(state, loop.Observation{
			Project:        ev.Project,
			SessionID:      ev.SessionID,
			StepID:         ev.StepID,
			DecisionStage:  "post_tool",
			ToolName:       ev.ToolName,
			Args:           ev.Args,
			Result:         ev.Result,
			ResultClass:    resultClass,
			StateDeltaHash: ev.StateDeltaHash,
			PromptTokens:   ev.PromptTokens,
			OutputTokens:   ev.OutputTokens,
			CostUSD:        ev.CostUSD,
			UnixMillis:     ev.UnixMillis,
			IdempotencyKey: ev.IdempotencyKey,
		}, cfg)
		record(post, i)

		// ---- reconcile the pending claim like the proxy result path. ----
		if store != nil && ev.IdempotencyKey != "" && risk != loop.ActionRiskRead {
			switch loop.ResultDisposition(resultClass, ev.ActionRisk, risk) {
			case loop.ActionDispositionCommit:
				raw, _ := json.Marshal(ev.Result)
				if err := store.Commit(ctx, loop.ActionResult{
					Project:                ev.Project,
					IdempotencyKey:         ev.IdempotencyKey,
					ToolName:               ev.ToolName,
					ActionRisk:             risk,
					RawActionRisk:          ev.ActionRisk,
					ResourceID:             ev.ResourceID,
					AmountCents:            ev.AmountCents,
					Recipient:              ev.Recipient,
					ResultClass:            resultClass,
					Result:                 raw,
					DuplicateWindowSeconds: ev.DuplicateWindowSeconds,
					UnixMillis:             ev.UnixMillis,
				}); err != nil {
					return res, err
				}
			case loop.ActionDispositionRelease:
				if err := store.Release(ctx, ev.Project, ev.IdempotencyKey, claimNonce); err != nil {
					return res, err
				}
			}
		}
	}

	if res.FirstBlock > 0 {
		for _, ev := range events[res.FirstBlock:] {
			res.SavedCostUSD += ev.CostUSD
		}
	}
	res.Signals = sortedKeys(signals)
	return res, nil
}

// effectiveRisk mirrors the proxy's effectiveActionRisk: an unlabeled action that
// carries an idempotency key is treated as a write.
func effectiveRisk(ev Event) string {
	if ev.ActionRisk == "" && ev.IdempotencyKey != "" {
		return loop.ActionRiskWrite
	}
	return loop.NormalizeActionRisk(ev.ActionRisk)
}

func actionRank(a loop.Action) int {
	switch a {
	case loop.ActionBlock:
		return 3
	case loop.ActionWarn:
		return 2
	default:
		return 1
	}
}

func verdictName(a loop.Action) string {
	switch a {
	case loop.ActionBlock:
		return "block"
	case loop.ActionWarn:
		return "warn"
	default:
		return "allow"
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func hasString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
