package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/wal"
)

// HandleReceiptPublicKey publishes the Ed25519 receipt verification key so an external
// auditor can verify exported receipts without holding the signing secret (and without
// asking the operator for the key out of band). Unauthenticated by design: a public key
// is meant to be public, and it grants verification, never the ability to sign.
func (h *Handler) HandleReceiptPublicKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if h.ReceiptSigner == nil || h.ReceiptSigner.PublicKeyBase64() == "" {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"receipt signing is not enabled on this proxy"}`)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"algorithm":  "ed25519",
		"key_id":     h.ReceiptSigner.KeyID(),
		"public_key": h.ReceiptSigner.PublicKeyBase64(),
		"verify_cmd": "hubbleops verify-receipts -receipt-public-key <public_key> receipts.jsonl",
	})
}

type DecisionReceiptInput struct {
	Project           string
	Provider          string
	Model             string
	PromptHash        string
	StatusCode        int
	SessionID         string
	TrajectoryID      string
	ToolName          string
	ArgsFingerprint   string
	ResultFingerprint string
	StepID            string
	ResultClass       string
	StateDeltaHash    string
	DecisionStage     string
	Signals           []string
	Confidence        float64
	Action            string
	Reason            string
	Evidence          []string
	DetectorVersion   string
	PolicyVersion     string
	Framework         string
	ImmediateOutcome  string
	AgentID           string
	UserID            string
	ActionRisk        string
	IdempotencyKey    string
	ResourceID        string
	AmountCents       int64
	MaxAmountCents    int64
	BackupID          string
	RecipientDomain   string
	AllowedDomain     string
	CapabilityHash    string
	DecisionID        string
	Cost              float64
	// Semantic capture hints. Optional; normalized to canonical taxonomy values at
	// capture time and, where absent, derived from other fields (tool name, domains).
	Environment   string
	RecipientType string
	OperationType string
}

type DecisionReceiptResult struct {
	Signature string
	KeyID     string
	// Record is the fully-built, signed, fingerprinted record that was (attempted to
	// be) written. It is populated even when the WAL write fails so callers that must
	// enforce a block can persist it to the dead-letter queue for durable retry.
	Record wal.Record
}

func (h *Handler) WriteDecisionReceipt(ctx context.Context, in DecisionReceiptInput) (DecisionReceiptResult, error) {
	if in.DecisionID == "" {
		in.DecisionID = decisionReceiptID(in)
	}
	if in.Provider == "" {
		in.Provider = "_proxy"
	}
	if in.Model == "" {
		in.Model = in.DecisionStage
	}
	if in.PromptHash == "" {
		in.PromptHash = hashPrompt([]byte(firstNonEmpty(in.ToolName, in.Reason, in.DecisionStage)))
	}
	if in.TrajectoryID == "" {
		in.TrajectoryID = trajectoryID(in.SessionID)
	}
	if in.Framework == "" {
		in.Framework = "unknown"
	}
	if in.ImmediateOutcome == "" {
		in.ImmediateOutcome = immediateOutcome(in.StatusCode, in.Action, in.ResultClass)
	}
	evidence := in.Evidence
	if len(evidence) == 0 && in.Reason != "" {
		evidence = []string{in.Reason}
	}
	in.Evidence = evidence

	var result DecisionReceiptResult
	defer func() {
		h.captureDecisionReceiptOutcome(ctx, in, result)
	}()

	if h.WAL == nil {
		err := fmt.Errorf("decision receipt WAL unavailable")
		h.recordDecisionReceiptFailure(in, err, "unavailable")
		return DecisionReceiptResult{}, err
	}

	rec := wal.Record{
		Project:             in.Project,
		Provider:            in.Provider,
		Model:               in.Model,
		PromptHash:          in.PromptHash,
		Cost:                in.Cost,
		StatusCode:          in.StatusCode,
		SessionID:           in.SessionID,
		ToolSignature:       in.ToolName,
		ArgsFingerprint:     in.ArgsFingerprint,
		StepID:              in.StepID,
		ResultClass:         in.ResultClass,
		StateDeltaHash:      in.StateDeltaHash,
		DecisionStage:       in.DecisionStage,
		LoopSignalsFired:    strings.Join(in.Signals, ","),
		LoopConfidence:      in.Confidence,
		LoopAction:          in.Action,
		LoopEvidence:        in.Reason,
		TrajectoryID:        in.TrajectoryID,
		DetectorVersion:     in.DetectorVersion,
		PolicyVersion:       in.PolicyVersion,
		Framework:           in.Framework,
		NearMiss:            in.Confidence >= 0.50 && in.Confidence < 0.70,
		ImmediateOutcome:    in.ImmediateOutcome,
		DecisionID:          in.DecisionID,
		AgentID:             in.AgentID,
		UserID:              in.UserID,
		ActionRisk:          in.ActionRisk,
		IdempotencyKeyHash:  safeReceiptFingerprint(in.IdempotencyKey),
		ResourceFingerprint: safeReceiptFingerprint(in.ResourceID),
		AmountCents:         in.AmountCents,
		MaxAmountCents:      in.MaxAmountCents,
		BackupID:            in.BackupID,
		RecipientDomain:     in.RecipientDomain,
		AllowedDomain:       in.AllowedDomain,
		CapabilityHash:      in.CapabilityHash,
		DecisionReason:      in.Reason,
		DecisionEvidence:    strings.Join(evidence, "; "),
	}

	if h.ReceiptSigner != nil {
		sig, keyID, err := h.ReceiptSigner.SignRecord(rec)
		if err != nil {
			h.recordDecisionReceiptFailure(in, err, "sign")
			return DecisionReceiptResult{}, err
		}
		result.Signature = sig
		result.KeyID = keyID
	}
	rec.ReceiptSignature = result.Signature
	rec.ReceiptKeyID = result.KeyID
	// Capture the decision time on the record now so that, if the durable write fails
	// and this is queued, the recovered receipt reflects when the decision happened.
	rec.Time = time.Now().UTC()
	result.Record = rec

	if err := h.WAL.Write(rec); err != nil {
		h.recordDecisionReceiptFailure(in, err, "write")
		return result, err
	}
	return result, nil
}

// queueReceiptForRetry persists a receipt that failed its WAL write to the durable
// dead-letter queue, so it survives restarts and is replayed once the WAL recovers.
// A block may stand briefly without a durable receipt, but the receipt is never
// silently dropped.
func (h *Handler) queueReceiptForRetry(rec wal.Record, stage string) {
	if h.ReceiptQueue == nil {
		log.Error().Str("stage", stage).Str("decision_id", rec.DecisionID).Msg("CRITICAL: no dead-letter queue configured; decision receipt permanently lost")
		return
	}
	if err := h.ReceiptQueue.Enqueue(rec); err != nil {
		log.Error().Err(err).Str("stage", stage).Str("decision_id", rec.DecisionID).Msg("CRITICAL: failed to dead-letter decision receipt; receipt lost")
		return
	}
	receiptDeadLetterEnqueuedTotal.Inc()
	if pending, perr := h.ReceiptQueue.Pending(); perr == nil {
		receiptDeadLetterPending.Set(float64(pending))
	}
}

// DrainReceiptQueue replays any dead-lettered receipts into the WAL. Safe to call
// repeatedly and concurrently with serving; returns the number recovered this pass.
func (h *Handler) DrainReceiptQueue() int {
	if h.ReceiptQueue == nil || h.WAL == nil {
		return 0
	}
	recovered, _, err := h.ReceiptQueue.Drain(h.WAL)
	if recovered > 0 {
		receiptDeadLetterRecoveredTotal.Add(float64(recovered))
		log.Info().Int("recovered", recovered).Msg("recovered decision receipts from dead-letter queue into WAL")
	}
	if pending, perr := h.ReceiptQueue.Pending(); perr == nil {
		receiptDeadLetterPending.Set(float64(pending))
	}
	if err != nil {
		log.Warn().Err(err).Msg("dead-letter receipt drain stopped early; will retry next tick")
	}
	return recovered
}

// StartReceiptDrainer recovers receipts left by a previous run immediately, then
// drains on the given interval until stop is closed. Returns at once; draining runs
// in the background.
func (h *Handler) StartReceiptDrainer(interval time.Duration, stop <-chan struct{}) {
	if h.ReceiptQueue == nil || h.WAL == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	h.DrainReceiptQueue()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				h.DrainReceiptQueue()
			}
		}
	}()
}

func (h *Handler) recordDecisionReceiptFailure(in DecisionReceiptInput, err error, op string) {
	decisionReceiptWriteFailures.WithLabelValues(in.DecisionStage, in.Action).Inc()
	walWriteFailures.Inc()
	log.Error().
		Err(err).
		Str("op", op).
		Str("project", in.Project).
		Str("stage", in.DecisionStage).
		Str("action", in.Action).
		Str("decision_id", in.DecisionID).
		Msg("failed to write decision receipt")
}

func (h *Handler) shouldFailOpenBlockOnReceiptError(err error) bool {
	return err != nil && h.RequireReceiptForBlock && !h.EnforceWithoutReceipt
}

func (h *Handler) logEnforceWithoutReceipt(err error, project, sessionID, action string) {
	if err == nil || !h.EnforceWithoutReceipt {
		return
	}
	log.Error().
		Err(err).
		Bool("enforce_without_receipt", true).
		Str("project", project).
		Str("session_id", sessionID).
		Str("action", action).
		Msg("CRITICAL: enforcing block without durable receipt")
}

func writeFailOpenDecision(w http.ResponseWriter, reason string, fields map[string]any) {
	body := map[string]any{
		"action":           "allow",
		"would_action":     "block",
		"fail_open":        true,
		"fail_open_reason": reason,
	}
	for k, v := range fields {
		body[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(body)
}

func decisionReceiptID(in DecisionReceiptInput) string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s", in.Project, in.SessionID, in.StepID, in.ToolName, in.DecisionStage, in.Action, in.Reason)
	sum := sha256.Sum256([]byte(raw))
	return "dec_" + fmt.Sprintf("%x", sum[:8])
}

func (h *Handler) writeLoopPreDecisionReceipt(ctx context.Context, project, sessionID, providerName string, body []byte, result loopCheckResult, action loop.Action, status int) (wal.Record, error) {
	evidence := append([]string{}, result.SignalsFired...)
	if result.Reason != "" {
		evidence = append(evidence, result.Reason)
	}
	res, err := h.WriteDecisionReceipt(ctx, DecisionReceiptInput{
		Project:          project,
		Provider:         providerName,
		Model:            "pre_llm",
		PromptHash:       hashPrompt(body),
		StatusCode:       status,
		SessionID:        sessionID,
		ToolName:         "_prompt",
		ArgsFingerprint:  hashPrompt(body),
		DecisionStage:    "pre_llm",
		Signals:          result.SignalsFired,
		Confidence:       result.Confidence,
		Action:           string(action),
		Reason:           result.Reason,
		Evidence:         evidence,
		DetectorVersion:  loop.DetectorVersion,
		PolicyVersion:    "loop_precheck_v1",
		Framework:        "unknown",
		ImmediateOutcome: immediateOutcome(status, string(action), ""),
	})
	return res.Record, err
}

func (h *Handler) writeBudgetDecisionReceipt(ctx context.Context, project, sessionID, providerName string, check loop.BudgetCheck, action loop.Action, status int) (wal.Record, error) {
	reason := "daily budget hard limit exceeded"
	if action == loop.ActionWarn {
		reason = "daily budget soft limit reached"
	}
	evidence := []string{
		fmt.Sprintf("spent_today_usd=%.4f", check.SpentToday),
		fmt.Sprintf("soft_limit_usd=%.4f", check.SoftLimitUSD),
		fmt.Sprintf("hard_limit_usd=%.4f", check.HardLimitUSD),
	}
	res, err := h.WriteDecisionReceipt(ctx, DecisionReceiptInput{
		Project:          project,
		Provider:         providerName,
		Model:            "pre_budget",
		PromptHash:       hashPrompt([]byte(project + "|" + sessionID + "|budget")),
		StatusCode:       status,
		SessionID:        sessionID,
		DecisionStage:    "pre_budget",
		Signals:          []string{"budget_" + string(check.Status)},
		Confidence:       1.0,
		Action:           string(action),
		Reason:           reason,
		Evidence:         evidence,
		DetectorVersion:  loop.DetectorVersion,
		PolicyVersion:    "budget_policy_v1",
		Framework:        "unknown",
		ImmediateOutcome: immediateOutcome(status, string(action), ""),
		Cost:             check.SpentToday,
	})
	return res.Record, err
}

func safeReceiptFingerprint(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if privacy.IsFingerprint(value) {
		return value
	}
	return privacy.FingerprintString(value)
}
