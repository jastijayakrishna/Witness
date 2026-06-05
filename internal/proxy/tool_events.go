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

	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/receipts"
	"github.com/witness-proxy/witness-proxy/internal/wal"
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
}

type toolEventResponse struct {
	Action          string   `json:"action"`
	WouldAction     string   `json:"would_action,omitempty"`
	Signals         []string `json:"signals,omitempty"`
	Confidence      float64  `json:"confidence"`
	Reason          string   `json:"reason"`
	OverrideToken   string   `json:"override_token,omitempty"`
	FailOpen        bool     `json:"fail_open,omitempty"`
	FailOpenReason  string   `json:"fail_open_reason,omitempty"`
	DetectorVersion string   `json:"detector_version"`
	Receipt         *receipt `json:"receipt,omitempty"`
	IdempotencyKey  string   `json:"idempotency_key,omitempty"`
	ActionRisk      string   `json:"action_risk,omitempty"`
	ActionName      string   `json:"action_name,omitempty"`
	PolicyVersion   string   `json:"policy_version,omitempty"`
	DecisionID      string   `json:"decision_id,omitempty"`
	Evidence        []string `json:"evidence,omitempty"`
}

type receipt struct {
	DecisionID      string   `json:"decision_id"`
	AgentID         string   `json:"agent_id,omitempty"`
	UserID          string   `json:"user_id,omitempty"`
	Project         string   `json:"project"`
	SessionID       string   `json:"session_id,omitempty"`
	ActionName      string   `json:"action_name"`
	ToolName        string   `json:"tool_name"`
	ActionRisk      string   `json:"action_risk"`
	Action          string   `json:"action"`
	Reason          string   `json:"reason"`
	IdempotencyKey  string   `json:"idempotency_key,omitempty"`
	ResourceID      string   `json:"resource_id,omitempty"`
	AmountCents     int64    `json:"amount_cents,omitempty"`
	MaxAmountCents  int64    `json:"max_amount_cents,omitempty"`
	BackupID        string   `json:"backup_id,omitempty"`
	RecipientDomain string   `json:"recipient_domain,omitempty"`
	AllowedDomain   string   `json:"allowed_domain,omitempty"`
	PolicyVersion   string   `json:"policy_version,omitempty"`
	Evidence        []string `json:"evidence,omitempty"`
	Signature       string   `json:"signature,omitempty"`
	KeyID           string   `json:"key_id,omitempty"`
}

func (h *Handler) HandleActionCheck(w http.ResponseWriter, r *http.Request) {
	req, obs, err := h.parseToolEvent(r, "pre_tool")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	overridden := h.consumeOverride(r.Context(), r.Header.Get("X-Witness-Override"), obs.Project, obs.SessionID)
	loopDecision := h.decideToolEvent(r.Context(), obs, overridden)
	actionDecision := h.decideActionEvent(r.Context(), req, obs, overridden)
	decision := combineDecisions(loopDecision, actionDecision.Decision)
	effective := h.effectiveLoopAction(decision, obs.SessionID)

	action := "allow"
	status := http.StatusOK
	var overrideToken string
	if overridden {
		action = "allow"
		effective = loop.ActionNone
	} else if effective == loop.ActionBlock {
		action = "block"
		status = http.StatusTooManyRequests
		overrideToken = h.mintOverride(obs.Project, obs.SessionID)
	} else if effective == loop.ActionWarn {
		action = "warn"
	}

	walAction := action
	if h.LoopCfg.Action == "shadow" && decision.ActionCeiling != loop.ActionNone {
		walAction = "shadow_would_" + string(decision.ActionCeiling)
		action = "allow"
		status = http.StatusOK
	}
	if overridden {
		walAction = "overridden"
	}
	if hasSignal(decision, loop.SignalDuplicateSideEffect) {
		obs.ResultClass = loop.ResultDuplicateAction
	}

	failOpenReason := ""
	receiptSignature, receiptKeyID, walErr := h.writeToolEventWAL(r.Context(), req, obs, decision, walAction, status)
	if walErr != nil && status == http.StatusTooManyRequests {
		status = http.StatusOK
		action = "allow"
		failOpenReason = "audit WAL write failed; Witness did not enforce an unaudited block"
	}
	h.writeToolEventResponse(w, status, toolEventResponse{
		Action:          action,
		WouldAction:     string(decision.ActionCeiling),
		Signals:         decision.SignalsFired,
		Confidence:      decision.Confidence,
		Reason:          decision.Reason,
		OverrideToken:   overrideToken,
		FailOpen:        failOpenReason != "",
		FailOpenReason:  failOpenReason,
		DetectorVersion: decision.DetectorVersion,
		Receipt:         buildReceipt(req, obs, action, decision, receiptSignature, receiptKeyID),
		IdempotencyKey:  req.IdempotencyKey,
		ActionRisk:      effectiveActionRisk(req),
		ActionName:      req.ActionName,
		PolicyVersion:   decision.PolicyVersion,
		DecisionID:      decisionID(req, obs.DecisionStage),
		Evidence:        decision.DecisionEvidence,
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

	receiptSignature, receiptKeyID, _ := h.writeToolEventWAL(r.Context(), req, obs, decision, walAction, http.StatusOK)
	h.writeToolEventResponse(w, http.StatusOK, toolEventResponse{
		Action:          action,
		WouldAction:     string(decision.ActionCeiling),
		Signals:         decision.SignalsFired,
		Confidence:      decision.Confidence,
		Reason:          decision.Reason,
		DetectorVersion: decision.DetectorVersion,
		Receipt:         buildReceipt(req, obs, action, decision, receiptSignature, receiptKeyID),
		IdempotencyKey:  req.IdempotencyKey,
		ActionRisk:      effectiveActionRisk(req),
		ActionName:      req.ActionName,
		PolicyVersion:   decision.PolicyVersion,
		DecisionID:      decisionID(req, obs.DecisionStage),
		Evidence:        decision.DecisionEvidence,
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
	if req.Project == "" {
		req.Project = ResolveProject(r)
	}
	if req.SessionID == "" {
		req.SessionID = ResolveSession(r)
	}
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
	}
	return req, obs, nil
}

func (h *Handler) decideToolEvent(ctx context.Context, obs loop.Observation, overridden bool) loop.Decision {
	if h.LoopStore == nil || overridden {
		return loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Loop detection disabled or overridden.", DetectorVersion: loop.DetectorVersion}
	}
	decisionObs := obs
	if obs.DecisionStage == "pre_tool" {
		decisionObs = loop.Observation{
			Project:       obs.Project,
			SessionID:     obs.SessionID,
			DecisionStage: obs.DecisionStage,
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
	if h.ActionStore == nil || overridden || obs.DecisionStage != "pre_tool" {
		return loop.ActionDecision{Decision: loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Action firewall disabled or not applicable.", DetectorVersion: loop.DetectorVersion}}
	}
	risk := effectiveActionRisk(req)
	txCtx, cancel := context.WithTimeout(ctx, loopRedisTimeout)
	defer cancel()
	decision, err := h.ActionStore.Decide(txCtx, loop.ActionObservation{
		Project:                obs.Project,
		SessionID:              obs.SessionID,
		StepID:                 obs.StepID,
		ToolName:               obs.ToolName,
		ActionRisk:             risk,
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
		log.Warn().Err(err).Str("project", obs.Project).Str("tool", obs.ToolName).Msg("action firewall failed open")
		return loop.ActionDecision{Decision: loop.Decision{ActionCeiling: loop.ActionNone, Reason: "Action firewall failed open.", DetectorVersion: loop.DetectorVersion}}
	}
	return decision
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

func (h *Handler) writeToolEventWAL(ctx context.Context, req toolEventRequest, obs loop.Observation, decision loop.Decision, action string, status int) (string, string, error) {
	if h.WAL == nil {
		return "", "", nil
	}
	rec := wal.Record{
		Project:          obs.Project,
		Provider:         "_tool",
		Model:            obs.DecisionStage,
		PromptHash:       hashPrompt([]byte(obs.ToolName)),
		InputTokens:      obs.PromptTokens,
		OutputTokens:     obs.OutputTokens,
		TotalTokens:      obs.PromptTokens + obs.OutputTokens,
		Cost:             obs.CostUSD,
		StatusCode:       status,
		SessionID:        obs.SessionID,
		ToolSignature:    obs.ToolName,
		ArgsFingerprint:  fingerprintAny(obs.Args),
		StepID:           obs.StepID,
		ResultClass:      obs.ResultClass,
		StateDeltaHash:   obs.StateDeltaHash,
		DecisionStage:    obs.DecisionStage,
		LoopSignalsFired: strings.Join(decision.SignalsFired, ","),
		LoopConfidence:   decision.Confidence,
		LoopAction:       action,
		LoopEvidence:     decision.Reason,
		TrajectoryID:     firstNonEmpty(req.TrajectoryID, trajectoryID(obs.SessionID)),
		DetectorVersion:  decision.DetectorVersion,
		NearMiss:         decision.Confidence >= 0.50 && decision.Confidence < 0.70,
		ImmediateOutcome: immediateOutcome(status, action, obs.ResultClass),
		Framework:        "sdk",
		DecisionID:       decisionID(req, obs.DecisionStage),
		AgentID:          req.AgentID,
		UserID:           req.UserID,
		ActionRisk:       effectiveActionRisk(req),
		IdempotencyKey:   req.IdempotencyKey,
		ResourceID:       req.ResourceID,
		AmountCents:      req.AmountCents,
		MaxAmountCents:   req.MaxAmountCents,
		BackupID:         req.BackupID,
		RecipientDomain:  recipientDomain(req.Recipient),
		AllowedDomain:    strings.ToLower(strings.TrimSpace(req.AllowedDomain)),
		CapabilityHash:   receipts.HashToken(req.CapabilityToken),
		PolicyVersion:    decision.PolicyVersion,
		DecisionReason:   decision.Reason,
		DecisionEvidence: strings.Join(decision.DecisionEvidence, "; "),
	}
	var receiptSignature, receiptKeyID string
	if h.ReceiptSigner != nil {
		var err error
		receiptSignature, receiptKeyID, err = h.ReceiptSigner.SignRecord(rec)
		if err != nil {
			walWriteFailures.Inc()
			log.Error().Err(err).Msg("failed to sign action receipt")
			return "", "", err
		}
	}
	rec.ReceiptSignature = receiptSignature
	rec.ReceiptKeyID = receiptKeyID
	if err := h.WAL.Write(rec); err != nil {
		walWriteFailures.Inc()
		log.Error().Err(err).Msg("failed to write tool event WAL")
		return "", "", err
	}
	return receiptSignature, receiptKeyID, nil
}

func (h *Handler) writeToolEventResponse(w http.ResponseWriter, status int, resp toolEventResponse) {
	w.Header().Set("Content-Type", "application/json")
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "300")
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func buildReceipt(req toolEventRequest, obs loop.Observation, action string, decision loop.Decision, signature, keyID string) *receipt {
	return &receipt{
		DecisionID:      decisionID(req, obs.DecisionStage),
		AgentID:         req.AgentID,
		UserID:          req.UserID,
		Project:         obs.Project,
		SessionID:       obs.SessionID,
		ActionName:      req.ActionName,
		ToolName:        obs.ToolName,
		ActionRisk:      effectiveActionRisk(req),
		Action:          action,
		Reason:          decision.Reason,
		IdempotencyKey:  req.IdempotencyKey,
		ResourceID:      req.ResourceID,
		AmountCents:     req.AmountCents,
		MaxAmountCents:  req.MaxAmountCents,
		BackupID:        req.BackupID,
		RecipientDomain: recipientDomain(req.Recipient),
		AllowedDomain:   strings.ToLower(strings.TrimSpace(req.AllowedDomain)),
		PolicyVersion:   decision.PolicyVersion,
		Evidence:        decision.DecisionEvidence,
		Signature:       signature,
		KeyID:           keyID,
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
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(fmt.Sprintf("%v", v))
	}
	canonical := canonicalJSON(string(b))
	sum := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("%x", sum[:])
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
