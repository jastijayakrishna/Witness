package proxy

import (
	"context"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/moatmetrics"
	"github.com/hubbleops/hubbleops/internal/outcomes"
	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/storage"
)

const outcomeCaptureTimeout = 500 * time.Millisecond

type OutcomeCaptureConfig struct {
	Enabled bool
	Mode    string
	Raw     bool
}

type OutcomeStore interface {
	InsertActionDecisionOutcome(ctx context.Context, outcome storage.ActionDecisionOutcome) (storage.ActionDecisionOutcome, error)
}

type unreviewedDecisionCounter interface {
	CountUnreviewedDecisions(ctx context.Context) (int, error)
}

func (h *Handler) captureDecisionReceiptOutcome(ctx context.Context, in DecisionReceiptInput, receipt DecisionReceiptResult) {
	if h == nil || h.OutcomeStore == nil || !h.OutcomeCapture.Enabled {
		return
	}
	if !h.outcomeCaptureModeAllowed(in.DecisionStage, in.Action) {
		return
	}
	outcome := outcomeFromDecisionReceipt(in, receipt)
	h.writeOutcome(ctx, outcome, in.DecisionStage, outcome.HubbleOpsAction)
}

func (h *Handler) capturePostLLMOutcome(ctx context.Context, in postLLMOutcomeInput) {
	if h == nil || h.OutcomeStore == nil || !h.OutcomeCapture.Enabled {
		return
	}
	if !h.outcomeCaptureModeAllowed("post_llm", in.Action) {
		return
	}
	if in.Action == "" || in.Action == "allow" {
		return
	}
	if strings.TrimSpace(in.Signals) == "" && !strings.Contains(in.Action, "warn") && !strings.Contains(in.Action, "block") {
		return
	}
	cost := in.Cost
	risk := in.Confidence
	outcome := storage.ActionDecisionOutcome{
		Project:                in.Project,
		SessionID:              in.SessionID,
		TrajectoryID:           trajectoryID(in.SessionID),
		DecisionID:             firstNonEmpty(in.DecisionID, generatedOutcomeDecisionID(in.Project, in.SessionID, in.ActionName, "post_llm", in.Action, in.PromptHash)),
		ActionName:             firstNonEmpty(in.ActionName, "_prompt"),
		ActionType:             "provider_response",
		ActionRisk:             loop.ActionRiskWrite,
		ToolSignatureHash:      fingerprintString(firstNonEmpty(in.ActionName, "_prompt")),
		ArgsFingerprint:        fingerprintString(in.ArgsFingerprint),
		ResultFingerprint:      fingerprintBytes(in.ProviderResponseBody),
		ResultClass:            firstNonEmpty(in.ResultClass, loop.ResultSuccess),
		HubbleOpsAction:          normalizeOutcomeAction(in.Action),
		DecisionReason:         safeDecisionReason(firstNonEmpty(in.Reason, "post_llm_loop_observation")),
		EvidenceJSON:           safeOutcomeEvidence(splitSignals(in.Signals), []string{in.Reason}),
		PolicyVersion:          "loop_post_observe_v1",
		DetectorVersion:        loop.DetectorVersion,
		EstimatedCostUSD:       nullablePositiveFloat(cost),
		EstimatedRiskPrevented: nullablePositiveFloat(risk),
	}
	h.writeOutcome(ctx, outcome, "post_llm", outcome.HubbleOpsAction)
}

func (h *Handler) outcomeCaptureModeAllowed(stage, action string) bool {
	if err := privacy.RejectRawCaptureIfDisabled(h.OutcomeCapture.Mode, h.OutcomeCapture.Raw); err != nil {
		outcomeCaptureWriteFailures.WithLabelValues(stage, action).Inc()
		moatmetrics.RecordOutcomeWriteFailure()
		log.Warn().
			Str("stage", stage).
			Str("action", action).
			Msg("skipping outcome capture because raw outcome capture was requested without explicit enablement")
		return false
	}
	return true
}

type postLLMOutcomeInput struct {
	Project              string
	SessionID            string
	ActionName           string
	ArgsFingerprint      string
	ProviderResponseBody []byte
	ResultClass          string
	Action               string
	Signals              string
	Confidence           float64
	Reason               string
	Cost                 float64
	PromptHash           string
	DecisionID           string
}

func (h *Handler) writeOutcome(ctx context.Context, outcome storage.ActionDecisionOutcome, stage, action string) {
	if strings.TrimSpace(outcome.Project) == "" || strings.TrimSpace(outcome.SessionID) == "" || strings.TrimSpace(outcome.ActionName) == "" {
		outcomeCaptureWriteFailures.WithLabelValues(stage, action).Inc()
		moatmetrics.RecordOutcomeWriteFailure()
		log.Warn().
			Str("project", outcome.Project).
			Str("session_id", outcome.SessionID).
			Str("decision_id", outcome.DecisionID).
			Str("stage", stage).
			Str("action", action).
			Msg("skipping outcome capture because required identifiers are missing")
		return
	}

	writeCtx, cancel := context.WithTimeout(ctx, outcomeCaptureTimeout)
	defer cancel()
	if _, err := h.OutcomeStore.InsertActionDecisionOutcome(writeCtx, outcome); err != nil {
		outcomeCaptureWriteFailures.WithLabelValues(stage, action).Inc()
		moatmetrics.RecordOutcomeWriteFailure()
		log.Warn().
			Str("error", redactedOutcomeError(err)).
			Str("project", outcome.Project).
			Str("session_id", outcome.SessionID).
			Str("decision_id", outcome.DecisionID).
			Str("stage", stage).
			Str("action", action).
			Msg("failed to write privacy-safe action decision outcome")
		return
	}
	moatmetrics.RecordOutcomeRecord()
	h.refreshUnreviewedDecisionMetric(ctx)
}

func (h *Handler) refreshUnreviewedDecisionMetric(ctx context.Context) {
	if h == nil {
		return
	}
	var counter unreviewedDecisionCounter
	if h.OutcomeStore != nil {
		if typed, ok := h.OutcomeStore.(unreviewedDecisionCounter); ok {
			counter = typed
		}
	}
	if counter == nil && h.DecisionReviewStore != nil {
		if typed, ok := h.DecisionReviewStore.(unreviewedDecisionCounter); ok {
			counter = typed
		}
	}
	if counter == nil {
		return
	}
	metricCtx, cancel := context.WithTimeout(ctx, outcomeCaptureTimeout)
	defer cancel()
	count, err := counter.CountUnreviewedDecisions(metricCtx)
	if err != nil {
		log.Warn().Str("error", redactedOutcomeError(err)).Msg("failed to refresh unreviewed decision metric")
		return
	}
	moatmetrics.SetUnreviewedDecisions(count)
}

func redactedOutcomeError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return "outcome write failed"
	}
	if strings.ContainsAny(msg, "{}[]\"'\n\r\t@") {
		return "<redacted>"
	}
	return msg
}

func outcomeFromDecisionReceipt(in DecisionReceiptInput, receipt DecisionReceiptResult) storage.ActionDecisionOutcome {
	cost := in.Cost
	risk := in.Confidence
	return storage.ActionDecisionOutcome{
		Project:                in.Project,
		SessionID:              in.SessionID,
		TrajectoryID:           in.TrajectoryID,
		DecisionID:             firstNonEmpty(in.DecisionID, generatedOutcomeDecisionID(in.Project, in.SessionID, in.ToolName, in.DecisionStage, in.Action, in.Reason)),
		ReceiptID:              receiptFingerprint(receipt),
		ActionName:             firstNonEmpty(in.ToolName, in.Model, in.DecisionStage),
		ActionType:             actionTypeForStage(in.DecisionStage),
		ActionRisk:             outcomeActionRisk(in.ActionRisk),
		ToolSignatureHash:      fingerprintString(firstNonEmpty(in.ToolName, in.Model, in.DecisionStage)),
		IdempotencyKeyHash:     fingerprintString(in.IdempotencyKey),
		ResourceFingerprint:    fingerprintString(in.ResourceID),
		ArgsFingerprint:        firstNonEmpty(normalizeFingerprint(in.ArgsFingerprint), normalizeFingerprint(in.PromptHash)),
		ResultFingerprint:      normalizeFingerprint(in.ResultFingerprint),
		ResultClass:            firstNonEmpty(in.ResultClass, immediateOutcome(in.StatusCode, in.Action, in.ResultClass)),
		StateDeltaHash:         normalizeFingerprint(in.StateDeltaHash),
		HubbleOpsAction:          normalizeOutcomeAction(in.Action),
		DecisionReason:         safeDecisionReason(firstNonEmpty(in.Reason, "decision recorded")),
		EvidenceJSON:           safeOutcomeEvidence(in.Signals, in.Evidence),
		PolicyVersion:          firstNonEmpty(in.PolicyVersion, policyVersionForStage(in.DecisionStage)),
		DetectorVersion:        firstNonEmpty(in.DetectorVersion, loop.DetectorVersion),
		EstimatedCostUSD:       nullablePositiveFloat(cost),
		EstimatedRiskPrevented: nullablePositiveFloat(risk),
		Environment:            semanticEnvironment(in.Environment),
		RecipientType:          semanticRecipientType(in.RecipientType, in.RecipientDomain, in.AllowedDomain),
		OperationType:          semanticOperationType(in.OperationType, firstNonEmpty(in.ToolName, in.Model)),
	}
}

// semanticEnvironment normalizes an explicit environment hint to a canonical token.
// Empty input stays empty ("not captured") rather than being coerced to "unknown".
func semanticEnvironment(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	return string(outcomes.NormalizeEnvironment(raw))
}

// semanticRecipientType prefers an explicit hint; otherwise infers internal vs
// external from the recipient/allowed domain pair captured on the decision.
func semanticRecipientType(raw, recipientDomain, allowedDomain string) string {
	if strings.TrimSpace(raw) != "" {
		return string(outcomes.NormalizeRecipientType(raw))
	}
	recipientDomain = strings.TrimSpace(recipientDomain)
	if recipientDomain == "" {
		return ""
	}
	if allowedDomain = strings.TrimSpace(allowedDomain); allowedDomain != "" && strings.EqualFold(recipientDomain, allowedDomain) {
		return string(outcomes.RecipientInternal)
	}
	return string(outcomes.RecipientExternalCustomer)
}

// semanticOperationType prefers an explicit hint; otherwise tries to derive the
// operation verb from the action/tool name (whole token, then leading token).
func semanticOperationType(raw, actionName string) string {
	if strings.TrimSpace(raw) != "" {
		return string(outcomes.NormalizeOperationType(raw))
	}
	actionName = strings.TrimSpace(actionName)
	if actionName == "" {
		return ""
	}
	op := outcomes.NormalizeOperationType(actionName)
	if op == outcomes.OperationUnknown {
		if i := strings.IndexAny(actionName, "_-. :"); i > 0 {
			op = outcomes.NormalizeOperationType(actionName[:i])
		}
	}
	if op == outcomes.OperationUnknown {
		return ""
	}
	return string(op)
}

func actionTypeForStage(stage string) string {
	switch stage {
	case "pre_budget":
		return "budget"
	case "pre_llm":
		return "provider_preflight"
	case "post_llm":
		return "provider_response"
	case "pre_tool":
		return "action_check"
	case "post_tool":
		return "action_result"
	default:
		return "action_decision"
	}
}

func policyVersionForStage(stage string) string {
	switch stage {
	case "pre_budget":
		return "budget_policy_v1"
	case "pre_llm", "post_llm":
		return "loop_policy_v1"
	case "pre_tool", "post_tool":
		return loop.ActionPolicyVersion
	default:
		return "hubbleops_policy_v1"
	}
}

func outcomeActionRisk(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return loop.ActionRiskWrite
	}
	return loop.NormalizeActionRisk(raw)
}

func normalizeOutcomeAction(action string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	switch {
	case action == "warn":
		return "warn"
	case action == "block":
		return "block"
	case action == "shadow" || strings.HasPrefix(action, "shadow_would_"):
		return "shadow"
	default:
		return "allow"
	}
}

func safeOutcomeEvidence(signals, evidence []string) []byte {
	return privacy.SafeEvidence(signals, evidence)
}

func safeDecisionReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "decision_recorded"
	}
	if strings.ContainsAny(reason, "{}[]\"'\n\r\t@") || privacy.ContainsSensitiveText(reason) {
		return "redacted_reason:" + fingerprintString(reason)
	}
	return reason
}

func splitSignals(signals string) []string {
	if strings.TrimSpace(signals) == "" {
		return nil
	}
	parts := strings.Split(signals, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func receiptFingerprint(receipt DecisionReceiptResult) string {
	if receipt.Signature == "" && receipt.KeyID == "" {
		return ""
	}
	return fingerprintString(receipt.KeyID + "|" + receipt.Signature)
}

func normalizeFingerprint(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if isAcceptedOutcomeFingerprint(value) {
		return value
	}
	return fingerprintString(value)
}

func isAcceptedOutcomeFingerprint(value string) bool {
	return privacy.IsFingerprint(value)
}

func fingerprintString(value string) string {
	return privacy.FingerprintString(value)
}

func fingerprintBytes(value []byte) string {
	return privacy.FingerprintBytes(value)
}

func nullablePositiveFloat(value float64) *float64 {
	if value <= 0 {
		return nil
	}
	return &value
}

func generatedOutcomeDecisionID(project, sessionID, actionName, stage, action, reason string) string {
	return fingerprintString(strings.Join([]string{project, sessionID, actionName, stage, action, reason}, "|"))
}
