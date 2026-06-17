package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/hubbleops/hubbleops/internal/auth"
	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

type toolEventRequest struct {
	Project                string  `json:"project"`
	SessionID              string  `json:"session_id"`
	TrajectoryID           string  `json:"trajectory_id"`
	StepID                 string  `json:"step_id"`
	ActionName             string  `json:"action_name"`
	ToolName               string  `json:"tool_name"`
	Args                   any     `json:"args"`
	Result                 any     `json:"result"`
	ResultClass            string  `json:"result_class"`
	StateDeltaHash         string  `json:"state_delta_hash"`
	PromptTokens           int     `json:"prompt_tokens"`
	OutputTokens           int     `json:"output_tokens"`
	CostUSD                float64 `json:"cost_usd"`
	UnixMillis             int64   `json:"unix_millis"`
	AgentID                string  `json:"agent_id"`
	UserID                 string  `json:"user_id"`
	ActionRisk             string  `json:"action_risk"`
	IdempotencyKey         string  `json:"idempotency_key"`
	ResourceID             string  `json:"resource_id"`
	AmountCents            int64   `json:"amount_cents"`
	MaxAmountCents         int64   `json:"max_amount_cents"`
	BackupID               string  `json:"backup_id"`
	Recipient              string  `json:"recipient"`
	AllowedDomain          string  `json:"allowed_domain"`
	CapabilityToken        string  `json:"capability_token"`
	DuplicateWindowSeconds int     `json:"duplicate_window_seconds"`
	// ClaimNonce is echoed back on the result event from the pre-tool check response. It
	// proves the result belongs to the attempt that claimed the pending lease, so a late
	// failure callback cannot release a newer attempt's lease.
	ClaimNonce string `json:"claim_nonce"`
}

type toolEventResponse struct {
	Action              string             `json:"action"`
	WouldAction         string             `json:"would_action,omitempty"`
	Signals             []string           `json:"signals,omitempty"`
	Confidence          float64            `json:"confidence"`
	Reason              string             `json:"reason"`
	OverrideToken       string             `json:"override_token,omitempty"`
	FailOpen            bool               `json:"fail_open,omitempty"`
	FailOpenReason      string             `json:"fail_open_reason,omitempty"`
	DetectorVersion     string             `json:"detector_version"`
	Receipt             *receipt           `json:"receipt,omitempty"`
	IdempotencyKeyHash  string             `json:"idempotency_key_hash,omitempty"`
	ResourceFingerprint string             `json:"resource_fingerprint,omitempty"`
	ActionRisk          string             `json:"action_risk,omitempty"`
	ActionName          string             `json:"action_name,omitempty"`
	PolicyVersion       string             `json:"policy_version,omitempty"`
	DecisionID          string             `json:"decision_id,omitempty"`
	Evidence            []string           `json:"evidence,omitempty"`
	Replay              *loop.ActionReplay `json:"replay,omitempty"`
	// ClaimNonce is set when this check acquired the pending idempotency lease. The
	// caller must echo it as claim_nonce on the matching result event.
	ClaimNonce string `json:"claim_nonce,omitempty"`
}

type receipt struct {
	DecisionID          string   `json:"decision_id"`
	AgentID             string   `json:"agent_id,omitempty"`
	UserID              string   `json:"user_id,omitempty"`
	Project             string   `json:"project"`
	SessionID           string   `json:"session_id,omitempty"`
	ActionName          string   `json:"action_name"`
	ToolName            string   `json:"tool_name"`
	ActionRisk          string   `json:"action_risk"`
	Action              string   `json:"action"`
	Reason              string   `json:"reason"`
	IdempotencyKeyHash  string   `json:"idempotency_key_hash,omitempty"`
	ResourceFingerprint string   `json:"resource_fingerprint,omitempty"`
	AmountCents         int64    `json:"amount_cents,omitempty"`
	MaxAmountCents      int64    `json:"max_amount_cents,omitempty"`
	BackupID            string   `json:"backup_id,omitempty"`
	RecipientDomain     string   `json:"recipient_domain,omitempty"`
	AllowedDomain       string   `json:"allowed_domain,omitempty"`
	PolicyVersion       string   `json:"policy_version,omitempty"`
	Evidence            []string `json:"evidence,omitempty"`
	Signature           string   `json:"signature,omitempty"`
	KeyID               string   `json:"key_id,omitempty"`
}

func (h *Handler) HandleActionCheck(w http.ResponseWriter, r *http.Request) {
	req, obs, err := h.parseToolEvent(r, "pre_tool")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	overridden := h.consumeOverride(r.Context(), r.Header.Get("X-HubbleOps-Override"), obs.Project, obs.SessionID)
	loopDecision := h.decideToolEvent(r.Context(), obs, overridden)
	actionDecision := h.decideActionEvent(r.Context(), req, obs, overridden)
	projectDecision := h.decideProjectEvent(r.Context(), req, obs, overridden)
	decision := combineDecisions(combineDecisions(loopDecision, actionDecision.Decision), projectDecision)
	effective := h.effectiveLoopAction(decision, obs.SessionID)

	action := "allow"
	status := http.StatusOK
	var overrideToken string
	var replay *loop.ActionReplay
	// The action firewall only enforces its terminal outcomes (replay / in-flight) when
	// it is actually enforcing; in shadow mode it records what it would do and lets the
	// call through unchanged.
	enforcing := !overridden && h.LoopCfg.Action != "shadow"
	switch {
	case overridden:
		action = "allow"
		effective = loop.ActionNone
	case enforcing && actionDecision.Outcome == loop.ActionOutcomeCommittedReplay:
		// The action already committed. Return its recorded outcome so the caller is none
		// the wiser, instead of forcing a well-behaved retry through a 429.
		action = "duplicate"
		status = http.StatusOK
		replay = actionDecision.Replay
	case enforcing && actionDecision.Outcome == loop.ActionOutcomeInFlight:
		// The first attempt is still within its pending lease. Tell the caller to retry
		// shortly (409) rather than blocking it as a permanent duplicate. We deliberately
		// do NOT mint an override here: forcing past an in-flight claim would run a
		// concurrent duplicate, which is exactly what the lease prevents. Retrying resolves
		// to a replay (if it commits) or a fresh claim (if it fails/expires).
		action = "block"
		status = http.StatusConflict
	case effective == loop.ActionBlock:
		action = "block"
		status = http.StatusTooManyRequests
		// A key reused with a contradictory payload is a client bug or
		// tampering, not a replay/loop, so surface it as 422 (not 429) and
		// don't offer Retry-After — retrying the same contradiction won't help.
		if hasSignal(decision, loop.SignalIdempotencyKeyReuseMismatch) {
			status = http.StatusUnprocessableEntity
		}
		overrideToken = h.mintOverride(obs.Project, obs.SessionID)
	case effective == loop.ActionWarn:
		action = "warn"
	}

	walAction := action
	if h.LoopCfg.Action == "shadow" && decision.ActionCeiling != loop.ActionNone {
		walAction = "shadow_would_" + string(decision.ActionCeiling)
		action = "allow"
		status = http.StatusOK
	}
	if action == "duplicate" {
		walAction = "duplicate_replay"
	}
	if status == http.StatusConflict {
		walAction = "in_flight"
	}
	if overridden {
		walAction = "overridden"
	}
	if hasSignal(decision, loop.SignalDuplicateSideEffect) {
		obs.ResultClass = loop.ResultDuplicateAction
	}

	failOpenReason := ""
	blocked := status == http.StatusTooManyRequests || status == http.StatusUnprocessableEntity
	// High-stakes blocks (dangerous / money-movement) must not be downgraded to allow
	// just because the audit receipt write failed — for these we'd rather enforce a
	// block we can't perfectly prove than let real money / destructive actions through.
	failClosed := blocked && h.failClosedAction(req)
	receiptRecord, receiptSignature, receiptKeyID, walErr := h.writeToolEventWAL(r.Context(), req, obs, decision, walAction, status)
	if walErr != nil && blocked {
		if !failClosed && h.shouldFailOpenBlockOnReceiptError(walErr) {
			status = http.StatusOK
			action = "allow"
			blocked = false
			failOpenReason = "audit WAL write failed; HubbleOps did not enforce an unaudited block"
		} else {
			// Block stays in force despite a failed receipt write — either the operator
			// opted in (EnforceWithoutReceipt) or this is a fail-closed high-risk action.
			// Never drop the receipt silently: log CRITICAL and persist it to the durable
			// dead-letter queue so it is replayed once the WAL recovers (even after restart).
			h.enforceBlockWithoutReceipt(receiptRecord, obs, walAction, walErr, failClosed)
		}
	}
	// Every enforced block is a circuit-breaker trip for this agent. Shadow
	// decisions and fail-open downgrades never count: only blocks that actually
	// held. Best-effort: a failed trip write must not affect the response.
	if blocked && h.LimitStore != nil {
		if err := h.LimitStore.RecordTrip(r.Context(), obs.Project, h.agentKey(r.Context()), obs.UnixMillis); err != nil {
			loopRedisFailures.WithLabelValues("limit_trip").Inc()
			log.Warn().Err(err).Str("project", obs.Project).Msg("circuit breaker trip record failed")
		}
	}
	h.writeToolEventResponse(w, status, toolEventResponse{
		Action:              action,
		WouldAction:         string(decision.ActionCeiling),
		Signals:             decision.SignalsFired,
		Confidence:          decision.Confidence,
		Reason:              decision.Reason,
		OverrideToken:       overrideToken,
		FailOpen:            failOpenReason != "",
		FailOpenReason:      failOpenReason,
		DetectorVersion:     decision.DetectorVersion,
		Receipt:             h.buildReceipt(req, obs, action, decision, receiptSignature, receiptKeyID),
		IdempotencyKeyHash:  safeReceiptFingerprint(req.IdempotencyKey),
		ResourceFingerprint: safeReceiptFingerprint(req.ResourceID),
		ActionRisk:          h.flooredRisk(req),
		ActionName:          req.ActionName,
		PolicyVersion:       decision.PolicyVersion,
		DecisionID:          decisionID(req, obs.DecisionStage),
		Evidence:            decision.DecisionEvidence,
		Replay:              replay,
		ClaimNonce:          actionDecision.ClaimNonce,
	})
}

func (h *Handler) HandleToolCheck(w http.ResponseWriter, r *http.Request) {
	h.HandleActionCheck(w, r)
}

func (h *Handler) HandleActionResult(w http.ResponseWriter, r *http.Request) {
	req, obs, err := h.parseToolEvent(r, "post_tool")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	decision := h.observeToolEvent(r.Context(), obs)
	// Reconcile the two-phase idempotency claim: a successful side effect is promoted to
	// the full duplicate window; a failed one releases the pending lease so a retry is
	// allowed. This is what closes the crash-gap — an action that never reports success
	// never holds the window.
	h.reconcileActionLedger(r.Context(), req, obs)
	effective := h.effectiveLoopAction(decision, obs.SessionID)
	action := "allow"
	if effective == loop.ActionBlock {
		action = "block"
	} else if effective == loop.ActionWarn {
		action = "warn"
	}
	walAction := action
	if h.LoopCfg.Action == "shadow" && decision.ActionCeiling != loop.ActionNone {
		walAction = "shadow_would_" + string(decision.ActionCeiling)
		action = "allow"
	}

	_, receiptSignature, receiptKeyID, _ := h.writeToolEventWAL(r.Context(), req, obs, decision, walAction, http.StatusOK)
	h.writeToolEventResponse(w, http.StatusOK, toolEventResponse{
		Action:              action,
		WouldAction:         string(decision.ActionCeiling),
		Signals:             decision.SignalsFired,
		Confidence:          decision.Confidence,
		Reason:              decision.Reason,
		DetectorVersion:     decision.DetectorVersion,
		Receipt:             h.buildReceipt(req, obs, action, decision, receiptSignature, receiptKeyID),
		IdempotencyKeyHash:  safeReceiptFingerprint(req.IdempotencyKey),
		ResourceFingerprint: safeReceiptFingerprint(req.ResourceID),
		ActionRisk:          h.flooredRisk(req),
		ActionName:          req.ActionName,
		PolicyVersion:       decision.PolicyVersion,
		DecisionID:          decisionID(req, obs.DecisionStage),
		Evidence:            decision.DecisionEvidence,
	})
}

func (h *Handler) HandleToolResult(w http.ResponseWriter, r *http.Request) {
	h.HandleActionResult(w, r)
}

func (h *Handler) parseToolEvent(r *http.Request, stage string) (toolEventRequest, loop.Observation, error) {
	defer r.Body.Close()

	var req toolEventRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestBodySize+1)).Decode(&req); err != nil {
		return req, loop.Observation{}, fmt.Errorf("invalid JSON body: %w", err)
	}
	if project, ok := auth.ProjectFromContext(r.Context()); ok {
		req.Project = project
	} else if req.Project == "" {
		req.Project = ResolveProject(r)
	}
	if req.SessionID == "" {
		req.SessionID = ResolveSession(r)
	}
	// Scope the session under the authenticated key identity so detector state, the
	// action ledger, and receipts key on something the client cannot rotate or forge.
	req.SessionID = BindSession(r, req.SessionID)
	if req.ToolName == "" {
		req.ToolName = req.ActionName
	}
	if req.ActionName == "" {
		req.ActionName = req.ToolName
	}
	if req.ToolName == "" {
		return req, loop.Observation{}, fmt.Errorf("action_name or tool_name is required")
	}
	if req.UnixMillis == 0 {
		req.UnixMillis = time.Now().UnixMilli()
	}

	resultClass := loop.NormalizeResultClassForAPI(req.ResultClass)
	if resultClass == "" && stage == "post_tool" {
		resultClass = loop.ClassifyResult(req.Result)
	}

	obs := loop.Observation{
		Project:        req.Project,
		SessionID:      req.SessionID,
		StepID:         req.StepID,
		DecisionStage:  stage,
		ToolName:       req.ToolName,
		Args:           req.Args,
		Result:         req.Result,
		ResultClass:    resultClass,
		StateDeltaHash: req.StateDeltaHash,
		PromptTokens:   req.PromptTokens,
		OutputTokens:   req.OutputTokens,
		CostUSD:        req.CostUSD,
		UnixMillis:     req.UnixMillis,
		IdempotencyKey: req.IdempotencyKey,
	}
	return req, obs, nil
}

func (h *Handler) decideToolEvent(ctx context.Context, obs loop.Observation, overridden bool) loop.Decision {
	if h.LoopStore == nil || overridden {
		return loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Loop detection disabled or overridden.", DetectorVersion: loop.DetectorVersion}
	}
	decisionObs := obs
	if obs.DecisionStage == "pre_tool" {
		// Keep the proposed call (tool + args) so the loop detector evaluates the
		// specific action about to run, not just session state — this is what lets
		// call-based repeat signals block before the side effect. Decide() runs
		// against a throwaway clone (detector.go), so feeding the proposed call here
		// never double-counts; the real count happens once at /result. We drop only
		// the result fields: there is no result before execution, and an empty one
		// would otherwise trip result-based signals (those are gated off at pre_tool).
		decisionObs = loop.Observation{
			Project:       obs.Project,
			SessionID:     obs.SessionID,
			StepID:        obs.StepID,
			DecisionStage: obs.DecisionStage,
			ToolName:      obs.ToolName,
			Args:          obs.Args,
			UnixMillis:    obs.UnixMillis,
		}
	}
	txCtx, cancel := context.WithTimeout(ctx, loopRedisTimeout)
	defer cancel()
	state, err := h.LoopStore.Load(txCtx, obs.Project, obs.SessionID)
	if err != nil {
		loopRedisFailures.WithLabelValues("tool_load").Inc()
		log.Warn().Err(err).Str("project", obs.Project).Msg("tool loop state load failed")
		return loop.Decide(loop.NewState(), decisionObs, h.LoopCfg)
	}
	return loop.Decide(state, decisionObs, h.LoopCfg)
}

func (h *Handler) observeToolEvent(ctx context.Context, obs loop.Observation) loop.Decision {
	if h.LoopStore == nil {
		return loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Loop detection disabled.", DetectorVersion: loop.DetectorVersion}
	}
	txCtx, cancel := context.WithTimeout(ctx, 2*loopRedisTimeout)
	defer cancel()
	var decision loop.Decision
	_, err := h.LoopStore.Transact(txCtx, obs.Project, obs.SessionID, func(state loop.State) loop.State {
		var next loop.State
		next, decision = loop.Observe(state, obs, h.LoopCfg)
		return next
	})
	if err != nil {
		loopRedisFailures.WithLabelValues("tool_transact").Inc()
		log.Warn().Err(err).Str("project", obs.Project).Msg("tool loop state transact failed")
		_, decision = loop.Observe(loop.NewState(), obs, h.LoopCfg)
	}
	return decision
}

func (h *Handler) decideActionEvent(ctx context.Context, req toolEventRequest, obs loop.Observation, overridden bool) loop.ActionDecision {
	if overridden || obs.DecisionStage != "pre_tool" {
		return loop.ActionDecision{Decision: loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Action firewall disabled or not applicable.", DetectorVersion: loop.DetectorVersion}}
	}
	risk := h.flooredRisk(req)

	// Resource limits run BEFORE the idempotency claim: an action a limit
	// rejects must not acquire a pending lease it will never reconcile.
	if h.LimitStore != nil {
		limitCtx, limitCancel := context.WithTimeout(ctx, loopRedisTimeout)
		decision, fired, err := h.LimitStore.Check(limitCtx, loop.LimitObservation{
			Project:     obs.Project,
			AgentKey:    h.agentKey(ctx),
			SessionID:   obs.SessionID,
			ToolName:    obs.ToolName,
			Risk:        risk,
			RawRisk:     req.ActionRisk,
			ResourceID:  req.ResourceID,
			Recipient:   req.Recipient,
			AmountCents: req.AmountCents,
			UnixMillis:  obs.UnixMillis,
		})
		limitCancel()
		if err != nil {
			loopRedisFailures.WithLabelValues("limit_check").Inc()
			log.Warn().Err(err).Str("project", obs.Project).Msg("resource limit check failed")
			if h.failClosedAction(req) {
				return loop.ActionDecision{Decision: loop.Decision{
					SignalsFired:     []string{loop.SignalActionFirewallUnavailable},
					Confidence:       0.95,
					ActionCeiling:    loop.ActionBlock,
					DetectorVersion:  loop.DetectorVersion,
					Reason:           "resource limits could not be checked; failing closed for high-risk action",
					HadSession:       obs.SessionID != "",
					PolicyVersion:    loop.ActionPolicyVersion,
					DecisionEvidence: []string{"limits=unavailable", "fail_mode=closed"},
				}, Reason: "resource limits could not be checked; failing closed for high-risk action"}
			}
		} else if fired {
			return decision
		}
	}

	if h.ActionStore == nil {
		return loop.ActionDecision{Decision: loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Action firewall disabled or not applicable.", DetectorVersion: loop.DetectorVersion}}
	}
	txCtx, cancel := context.WithTimeout(ctx, loopRedisTimeout)
	defer cancel()
	decision, err := h.ActionStore.Decide(txCtx, loop.ActionObservation{
		Project:                obs.Project,
		SessionID:              obs.SessionID,
		StepID:                 obs.StepID,
		ToolName:               obs.ToolName,
		ActionRisk:             risk,
		RawActionRisk:          req.ActionRisk,
		IdempotencyKey:         req.IdempotencyKey,
		AgentID:                req.AgentID,
		UserID:                 req.UserID,
		ResourceID:             req.ResourceID,
		AmountCents:            req.AmountCents,
		MaxAmountCents:         req.MaxAmountCents,
		BackupID:               req.BackupID,
		Recipient:              req.Recipient,
		AllowedDomain:          req.AllowedDomain,
		CapabilityToken:        req.CapabilityToken,
		DuplicateWindowSeconds: req.DuplicateWindowSeconds,
		UnixMillis:             obs.UnixMillis,
	})
	if err != nil {
		loopRedisFailures.WithLabelValues("action_idempotency").Inc()
		// Fail posture is risk-aware. For read/write we fail OPEN so a ledger outage
		// doesn't halt the agent. For dangerous/money-movement we fail CLOSED: better
		// to block a high-stakes action we couldn't verify than to let a duplicate
		// refund or destructive call execute unchecked during an outage.
		if loop.FailClosedRisk(req.ActionRisk) || risk == loop.ActionRiskDangerous {
			log.Error().Err(err).Str("project", obs.Project).Str("tool", obs.ToolName).Str("risk", risk).Msg("CRITICAL: action firewall unreachable; failing closed on high-risk action")
			return loop.ActionDecision{
				Decision: loop.Decision{
					SignalsFired:     []string{loop.SignalActionFirewallUnavailable},
					Confidence:       1.0,
					ActionCeiling:    loop.ActionBlock,
					DetectorVersion:  loop.DetectorVersion,
					PolicyVersion:    loop.ActionPolicyVersion,
					Reason:           "action firewall unreachable; high-risk action blocked (fail-closed)",
					HadSession:       obs.SessionID != "",
					DecisionEvidence: []string{"fail_posture=closed", "risk=" + risk, "ledger=unreachable"},
				},
				Reason:   "action firewall unreachable; high-risk action blocked (fail-closed)",
				Evidence: []string{"fail_posture=closed", "risk=" + risk, "ledger=unreachable"},
			}
		}
		log.Warn().Err(err).Str("project", obs.Project).Str("tool", obs.ToolName).Str("risk", risk).Msg("action firewall failed open")
		return loop.ActionDecision{Decision: loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Action firewall failed open.", DetectorVersion: loop.DetectorVersion}}
	}
	return decision
}

// decideProjectEvent runs the cross-session project guard: unkeyed side-effect
// storms spread across sessions are invisible to per-session loop state, so a
// bounded project-scope tracker watches for them. Fails OPEN on store errors —
// the guard is an extra net, never an availability risk.
func (h *Handler) decideProjectEvent(ctx context.Context, req toolEventRequest, obs loop.Observation, overridden bool) loop.Decision {
	if h.LoopStore == nil || overridden {
		return loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Project guard disabled or overridden.", DetectorVersion: loop.DetectorVersion}
	}
	risk := h.flooredRisk(req)
	if risk == loop.ActionRiskRead {
		return loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Project guard not applicable to reads.", DetectorVersion: loop.DetectorVersion}
	}
	txCtx, cancel := context.WithTimeout(ctx, loopRedisTimeout)
	defer cancel()
	var decision loop.Decision
	_, err := h.LoopStore.TransactProject(txCtx, obs.Project, func(state loop.ProjectState) loop.ProjectState {
		var next loop.ProjectState
		next, decision = loop.ObserveProject(state, obs, risk)
		return next
	})
	if err != nil {
		loopRedisFailures.WithLabelValues("project_guard").Inc()
		log.Warn().Err(err).Str("project", obs.Project).Msg("project guard state transact failed; failing open")
		return loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Project guard failed open.", DetectorVersion: loop.DetectorVersion}
	}
	return decision
}

// flooredRisk applies the per-tool server-side risk floor to the client-supplied
// label so a client cannot downgrade a tool the operator classified.
func (h *Handler) flooredRisk(req toolEventRequest) string {
	risk := effectiveActionRisk(req)
	if h.LoopCfg.ToolRiskFloor == nil {
		return risk
	}
	return loop.FloorRisk(risk, h.LoopCfg.ToolRiskFloor[firstNonEmpty(req.ToolName, req.ActionName)])
}

// failClosedAction reports whether a block for this request must stay in force even
// if the audit receipt cannot be written. It keys on the raw client label (so an
// honest "money_movement" is caught) and on the server-floored risk (so a tool the
// operator classified as dangerous is caught even if the client lied).
func (h *Handler) failClosedAction(req toolEventRequest) bool {
	return loop.FailClosedRisk(req.ActionRisk) || h.flooredRisk(req) == loop.ActionRiskDangerous
}

// agentKey is the server-derived identity that resource limits and the circuit
// breaker are scoped to. Empty (unauthenticated) collapses to the per-project
// anonymous bucket inside the limit store.
func (h *Handler) agentKey(ctx context.Context) string {
	keyID, _ := auth.KeyIDFromContext(ctx)
	return keyID
}

// enforceBlockWithoutReceipt records that a block is being enforced despite a failed
// receipt write and persists the built receipt to the durable dead-letter queue, so
// the evidence trail is repaired once the WAL recovers (surviving process restarts)
// rather than depending on an in-process retry that dies with the process.
func (h *Handler) enforceBlockWithoutReceipt(rec wal.Record, obs loop.Observation, action string, cause error, failClosed bool) {
	blockEnforcedWithoutReceiptTotal.WithLabelValues(obs.DecisionStage).Inc()
	log.Error().
		Err(cause).
		Bool("fail_closed", failClosed).
		Str("project", obs.Project).
		Str("session_id", obs.SessionID).
		Str("tool", obs.ToolName).
		Str("action", action).
		Str("decision_id", rec.DecisionID).
		Msg("CRITICAL: enforcing action block without durable receipt; persisted to dead-letter for retry")
	h.queueReceiptForRetry(rec, obs.DecisionStage)
}

func combineDecisions(a, b loop.Decision) loop.Decision {
	if b.DetectorVersion == "" {
		return a
	}
	if a.DetectorVersion == "" {
		return b
	}
	out := a
	out.SignalsFired = append(append([]string{}, a.SignalsFired...), b.SignalsFired...)
	if b.Confidence > out.Confidence {
		out.Confidence = b.Confidence
	}
	if actionRank(b.ActionCeiling) > actionRank(out.ActionCeiling) {
		out.ActionCeiling = b.ActionCeiling
		out.Reason = b.Reason
	}
	if out.Reason == "" {
		out.Reason = b.Reason
	}
	if b.PolicyVersion != "" {
		out.PolicyVersion = b.PolicyVersion
	}
	if len(b.DecisionEvidence) > 0 {
		out.DecisionEvidence = append(out.DecisionEvidence, b.DecisionEvidence...)
	}
	if len(out.DecisionEvidence) == 0 && a.Reason != "" {
		out.DecisionEvidence = append(out.DecisionEvidence, a.Reason)
	}
	return out
}

func actionRank(action loop.Action) int {
	switch action {
	case loop.ActionBlock:
		return 3
	case loop.ActionWarn:
		return 2
	default:
		return 1
	}
}

func hasSignal(decision loop.Decision, signal string) bool {
	for _, fired := range decision.SignalsFired {
		if fired == signal {
			return true
		}
	}
	return false
}

func (h *Handler) effectiveLoopAction(decision loop.Decision, sessionID string) loop.Action {
	effective := loop.EffectiveAction(loop.Action(h.LoopCfg.Action), decision.ActionCeiling)
	if sessionID == "" && h.LoopCfg.RequireSessionForBlock && effective == loop.ActionBlock {
		return loop.ActionWarn
	}
	return effective
}

func (h *Handler) consumeOverride(ctx context.Context, token, project, sessionID string) bool {
	if token == "" || h.OverrideStore == nil {
		return false
	}
	consumed, err := h.OverrideStore.Consume(ctx, token, project, sessionID)
	if err != nil {
		log.Warn().Err(err).Msg("failed to consume tool override token")
		return false
	}
	if consumed {
		loopOverridesTotal.Inc()
		h.labelTrajectory(project, sessionID)
	}
	return consumed
}

func (h *Handler) mintOverride(project, sessionID string) string {
	if h.OverrideStore == nil {
		return ""
	}
	token, err := h.OverrideStore.Mint(context.Background(), project, sessionID)
	if err != nil {
		log.Warn().Err(err).Msg("failed to mint tool override token")
		return ""
	}
	return token
}

// reconcileActionLedger promotes or releases the pending idempotency claim made at the
// pre-tool check, based on whether the side effect succeeded. It is best-effort: if the
// ledger is unreachable the pending lease simply expires, which still keeps the firewall
// from blocking a retry of an action that never committed.
func (h *Handler) reconcileActionLedger(ctx context.Context, req toolEventRequest, obs loop.Observation) {
	if h.ActionStore == nil || req.IdempotencyKey == "" {
		return
	}
	risk := h.flooredRisk(req)
	if risk == loop.ActionRiskRead {
		return
	}
	switch loop.ResultDisposition(obs.ResultClass, req.ActionRisk, risk) {
	case loop.ActionDispositionCommit:
		resultFingerprint := ""
		if obs.Result != nil {
			resultFingerprint = fingerprintAny(obs.Result)
		}
		err := h.ActionStore.Commit(ctx, loop.ActionResult{
			Project:                obs.Project,
			IdempotencyKey:         req.IdempotencyKey,
			ToolName:               obs.ToolName,
			ActionRisk:             risk,
			RawActionRisk:          req.ActionRisk,
			ResourceID:             req.ResourceID,
			AmountCents:            req.AmountCents,
			Recipient:              req.Recipient,
			DecisionID:             decisionID(req, obs.DecisionStage),
			ResultClass:            obs.ResultClass,
			ResultFingerprint:      resultFingerprint,
			Result:                 rawActionResult(obs.Result),
			DuplicateWindowSeconds: req.DuplicateWindowSeconds,
			UnixMillis:             obs.UnixMillis,
		})
		if err != nil {
			loopRedisFailures.WithLabelValues("action_commit").Inc()
			log.Warn().Err(err).Str("project", obs.Project).Str("tool", obs.ToolName).Msg("action ledger commit failed; pending lease will expire")
		}
	case loop.ActionDispositionRelease:
		if err := h.ActionStore.Release(ctx, obs.Project, req.IdempotencyKey, req.ClaimNonce); err != nil {
			loopRedisFailures.WithLabelValues("action_release").Inc()
			log.Warn().Err(err).Str("project", obs.Project).Str("tool", obs.ToolName).Msg("action ledger release failed; pending lease will expire")
		}
	}
}

// rawActionResult returns the result body to retain for replay, but only when the SDK
// sent the real value. When capture is in fingerprint mode the result is a hubbleops
// fingerprint envelope, which must not be replayed back to the caller as if it were the
// original result, so we drop it and keep only the fingerprint.
func rawActionResult(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]any); ok {
		if capture, _ := m["hubbleops_capture"].(string); capture == "fingerprint" {
			return nil
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

func (h *Handler) writeToolEventWAL(ctx context.Context, req toolEventRequest, obs loop.Observation, decision loop.Decision, action string, status int) (wal.Record, string, string, error) {
	resultFingerprint := ""
	if obs.Result != nil {
		resultFingerprint = fingerprintAny(obs.Result)
	}
	result, err := h.WriteDecisionReceipt(ctx, DecisionReceiptInput{
		Project:           obs.Project,
		Provider:          "_tool",
		Model:             obs.DecisionStage,
		PromptHash:        hashPrompt([]byte(obs.ToolName)),
		StatusCode:        status,
		SessionID:         obs.SessionID,
		TrajectoryID:      firstNonEmpty(req.TrajectoryID, trajectoryID(obs.SessionID)),
		ToolName:          obs.ToolName,
		ArgsFingerprint:   fingerprintAny(obs.Args),
		ResultFingerprint: resultFingerprint,
		StepID:            obs.StepID,
		ResultClass:       obs.ResultClass,
		StateDeltaHash:    obs.StateDeltaHash,
		DecisionStage:     obs.DecisionStage,
		Signals:           decision.SignalsFired,
		Confidence:        decision.Confidence,
		Action:            action,
		Reason:            decision.Reason,
		Evidence:          decision.DecisionEvidence,
		DetectorVersion:   decision.DetectorVersion,
		PolicyVersion:     decision.PolicyVersion,
		Framework:         "sdk",
		ImmediateOutcome:  immediateOutcome(status, action, obs.ResultClass),
		AgentID:           req.AgentID,
		UserID:            req.UserID,
		ActionRisk:        h.flooredRisk(req),
		IdempotencyKey:    req.IdempotencyKey,
		ResourceID:        req.ResourceID,
		AmountCents:       req.AmountCents,
		MaxAmountCents:    req.MaxAmountCents,
		BackupID:          req.BackupID,
		RecipientDomain:   recipientDomain(req.Recipient),
		AllowedDomain:     strings.ToLower(strings.TrimSpace(req.AllowedDomain)),
		CapabilityHash:    receipts.HashToken(req.CapabilityToken),
		DecisionID:        decisionID(req, obs.DecisionStage),
		Cost:              obs.CostUSD,
	})
	return result.Record, result.Signature, result.KeyID, err
}

func (h *Handler) writeToolEventResponse(w http.ResponseWriter, status int, resp toolEventResponse) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "300")
	}
	// 409 = the first attempt is still in flight; a short retry is the right move, so
	// advertise a much shorter Retry-After than a loop block.
	if status == http.StatusConflict {
		w.Header().Set("Retry-After", "2")
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) buildReceipt(req toolEventRequest, obs loop.Observation, action string, decision loop.Decision, signature, keyID string) *receipt {
	return &receipt{
		DecisionID:          decisionID(req, obs.DecisionStage),
		AgentID:             req.AgentID,
		UserID:              req.UserID,
		Project:             obs.Project,
		SessionID:           obs.SessionID,
		ActionName:          req.ActionName,
		ToolName:            obs.ToolName,
		ActionRisk:          h.flooredRisk(req),
		Action:              action,
		Reason:              decision.Reason,
		IdempotencyKeyHash:  safeReceiptFingerprint(req.IdempotencyKey),
		ResourceFingerprint: safeReceiptFingerprint(req.ResourceID),
		AmountCents:         req.AmountCents,
		MaxAmountCents:      req.MaxAmountCents,
		BackupID:            req.BackupID,
		RecipientDomain:     recipientDomain(req.Recipient),
		AllowedDomain:       strings.ToLower(strings.TrimSpace(req.AllowedDomain)),
		PolicyVersion:       decision.PolicyVersion,
		Evidence:            decision.DecisionEvidence,
		Signature:           signature,
		KeyID:               keyID,
	}
}

func decisionID(req toolEventRequest, stage string) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%d", req.Project, req.SessionID, req.StepID, req.ToolName, stage, req.UnixMillis)
	sum := sha256.Sum256([]byte(raw))
	return "dec_" + fmt.Sprintf("%x", sum[:8])
}

func effectiveActionRisk(req toolEventRequest) string {
	if req.ActionRisk == "" && req.IdempotencyKey != "" {
		return loop.ActionRiskWrite
	}
	return loop.NormalizeActionRisk(req.ActionRisk)
}

func fingerprintAny(v any) string {
	return strings.TrimPrefix(privacy.FingerprintJSON(v), "sha256:")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func recipientDomain(recipient string) string {
	recipient = strings.TrimSpace(strings.ToLower(recipient))
	at := strings.LastIndex(recipient, "@")
	if at < 0 || at == len(recipient)-1 {
		return ""
	}
	return recipient[at+1:]
}
