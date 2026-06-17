package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/storage"
)

func TestActionCheckAllowDecisionCreatesOutcome(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")
	outcomes := &recordingOutcomeStore{}
	h.OutcomeStore = outcomes
	h.OutcomeCapture = OutcomeCaptureConfig{Enabled: true, Mode: "fingerprint"}
	recordsBefore := metricValue(t, "hubbleops_outcome_records_total", nil)

	body := map[string]any{
		"project":         "moat-test",
		"session_id":      "allow-session",
		"step_id":         "email-1",
		"action_name":     "send_email",
		"action_risk":     "write",
		"idempotency_key": "email:customer@example.com:welcome",
		"resource_id":     "crm_contact_123",
		"args":            map[string]any{"to": "customer@example.com", "body": "super-secret-body"},
		"unix_millis":     int64(1_000),
	}
	rec := httptest.NewRecorder()
	h.HandleActionCheck(rec, toolReq("/v1/action/check", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	got := lastOutcome(t, outcomes)
	if got.HubbleOpsAction != "allow" {
		t.Fatalf("hubbleops_action=%q want allow", got.HubbleOpsAction)
	}
	if got.ActionName != "send_email" || got.ActionType != "action_check" || got.ActionRisk != "write" {
		t.Fatalf("unexpected action metadata: %+v", got)
	}
	if got.DecisionID == "" || got.Project != "moat-test" || got.SessionID != "allow-session" {
		t.Fatalf("missing identifiers: %+v", got)
	}
	if delta := metricValue(t, "hubbleops_outcome_records_total", nil) - recordsBefore; delta != 1 {
		t.Fatalf("outcome records metric delta=%f want 1", delta)
	}
	if got := metricValue(t, "hubbleops_unreviewed_decisions_total", nil); got != 1 {
		t.Fatalf("unreviewed decisions metric=%f want 1", got)
	}
	assertOutcomeDoesNotContain(t, got, "customer@example.com", "super-secret-body", "crm_contact_123", "email:customer@example.com:welcome")
}

func TestActionCheckShadowDecisionCreatesOutcome(t *testing.T) {
	h, _ := newToolEventHandler(t, "shadow")
	outcomes := &recordingOutcomeStore{}
	h.OutcomeStore = outcomes
	h.OutcomeCapture = OutcomeCaptureConfig{Enabled: true, Mode: "fingerprint"}

	body := map[string]any{
		"project":         "moat-test",
		"session_id":      "shadow-session",
		"step_id":         "refund-1",
		"action_name":     "refund_customer",
		"action_risk":     "write",
		"idempotency_key": "refund:invoice_9:5000",
		"args":            map[string]any{"invoice_id": "invoice_9", "amount_cents": 5000},
		"unix_millis":     int64(1_000),
	}
	first := httptest.NewRecorder()
	h.HandleActionCheck(first, toolReq("/v1/action/check", body))
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}

	// Commit the first attempt so the retry is a true duplicate, not an in-flight hold.
	resultBody := map[string]any{
		"project":         "moat-test",
		"session_id":      "shadow-session",
		"step_id":         "refund-1",
		"action_name":     "refund_customer",
		"action_risk":     "write",
		"idempotency_key": "refund:invoice_9:5000",
		"result_class":    "success",
		"unix_millis":     int64(1_500),
	}
	resultRec := httptest.NewRecorder()
	h.HandleActionResult(resultRec, toolReq("/v1/action/result", resultBody))
	if resultRec.Code != http.StatusOK {
		t.Fatalf("result status=%d body=%s", resultRec.Code, resultRec.Body.String())
	}

	body["step_id"] = "refund-2"
	body["unix_millis"] = int64(2_000)
	second := httptest.NewRecorder()
	h.HandleActionCheck(second, toolReq("/v1/action/check", body))
	if second.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", second.Code, second.Body.String())
	}

	got := lastOutcome(t, outcomes)
	if got.HubbleOpsAction != "shadow" {
		t.Fatalf("hubbleops_action=%q want shadow", got.HubbleOpsAction)
	}
	if got.ResultClass != loop.ResultDuplicateAction {
		t.Fatalf("result_class=%q want %q", got.ResultClass, loop.ResultDuplicateAction)
	}
	assertEvidenceIsFingerprintSafe(t, got)
	assertOutcomeDoesNotContain(t, got, "invoice_9", "refund:invoice_9:5000")
}

func TestActionCheckBlockDecisionCreatesOutcome(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")
	outcomes := &recordingOutcomeStore{}
	h.OutcomeStore = outcomes
	h.OutcomeCapture = OutcomeCaptureConfig{Enabled: true, Mode: "fingerprint"}

	body := map[string]any{
		"project":     "moat-test",
		"session_id":  "block-session",
		"step_id":     "delete-1",
		"action_name": "delete_account",
		"action_risk": "dangerous",
		"args":        map[string]any{"account_id": "acct_secret_1"},
		"unix_millis": int64(1_000),
	}
	rec := httptest.NewRecorder()
	h.HandleActionCheck(rec, toolReq("/v1/action/check", body))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429 body=%s", rec.Code, rec.Body.String())
	}

	got := lastOutcome(t, outcomes)
	if got.HubbleOpsAction != "block" {
		t.Fatalf("hubbleops_action=%q want block", got.HubbleOpsAction)
	}
	if got.EstimatedRiskPrevented == nil || *got.EstimatedRiskPrevented <= 0 {
		t.Fatalf("estimated risk prevented missing: %+v", got.EstimatedRiskPrevented)
	}
	assertEvidenceIsFingerprintSafe(t, got)
	assertOutcomeDoesNotContain(t, got, "acct_secret_1")
}

func TestOutcomeWriteFailureDoesNotBreakShadowMode(t *testing.T) {
	h, _ := newToolEventHandler(t, "shadow")
	h.OutcomeStore = &recordingOutcomeStore{err: errors.New("postgres down")}
	h.OutcomeCapture = OutcomeCaptureConfig{Enabled: true, Mode: "fingerprint"}
	failuresBefore := metricValue(t, "hubbleops_outcome_write_failures_total", nil)

	body := map[string]any{
		"project":         "moat-test",
		"session_id":      "shadow-fail-open",
		"step_id":         "refund-1",
		"action_name":     "refund_customer",
		"action_risk":     "write",
		"idempotency_key": "refund:shadow-fail:5000",
		"args":            map[string]any{"invoice_id": "shadow-fail"},
		"unix_millis":     int64(1_000),
	}
	first := httptest.NewRecorder()
	h.HandleActionCheck(first, toolReq("/v1/action/check", body))
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}

	body["step_id"] = "refund-2"
	body["unix_millis"] = int64(2_000)
	second := httptest.NewRecorder()
	h.HandleActionCheck(second, toolReq("/v1/action/check", body))
	if second.Code != http.StatusOK {
		t.Fatalf("shadow decision status=%d want 200 body=%s", second.Code, second.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["action"] != "allow" || resp["would_action"] != "block" {
		t.Fatalf("shadow behavior changed: %s", second.Body.String())
	}
	if delta := metricValue(t, "hubbleops_outcome_write_failures_total", nil) - failuresBefore; delta == 0 {
		t.Fatalf("outcome write failure metric did not increment")
	}
}

func TestOutcomeCaptureRejectsRawModeUnlessExplicitlyEnabled(t *testing.T) {
	outcomes := &recordingOutcomeStore{}
	h := &Handler{
		OutcomeStore:   outcomes,
		OutcomeCapture: OutcomeCaptureConfig{Enabled: true, Mode: "raw"},
	}
	failuresBefore := metricValue(t, "hubbleops_outcome_write_failures_total", nil)
	rejectionsBefore := metricValue(t, "hubbleops_raw_capture_rejections_total", nil)

	h.captureDecisionReceiptOutcome(context.Background(), DecisionReceiptInput{
		Project:          "moat-test",
		SessionID:        "raw-mode-session",
		ToolName:         "send_email",
		DecisionStage:    "pre_tool",
		Action:           "block",
		Reason:           "duplicate side-effect",
		ArgsFingerprint:  fingerprintString(`{"email":"customer@example.com"}`),
		DetectorVersion:  loop.DetectorVersion,
		PolicyVersion:    loop.ActionPolicyVersion,
		ActionRisk:       "write",
		ResultClass:      loop.ResultDuplicateAction,
		ImmediateOutcome: "blocked",
	}, DecisionReceiptResult{})

	if len(outcomes.outcomes) != 0 {
		t.Fatalf("raw mode without explicit enablement wrote outcomes: %+v", outcomes.outcomes)
	}
	if delta := metricValue(t, "hubbleops_outcome_write_failures_total", nil) - failuresBefore; delta != 1 {
		t.Fatalf("outcome write failure metric delta=%f want 1", delta)
	}
	if delta := metricValue(t, "hubbleops_raw_capture_rejections_total", nil) - rejectionsBefore; delta != 1 {
		t.Fatalf("raw capture rejection metric delta=%f want 1", delta)
	}
}

func TestOutcomeEvidenceIsRedactedAndFingerprintSafe(t *testing.T) {
	outcome := outcomeFromDecisionReceipt(DecisionReceiptInput{
		Project:           "moat-test",
		SessionID:         "evidence-session",
		ToolName:          "send_email",
		DecisionStage:     "pre_tool",
		Action:            "block",
		Reason:            "recipient contains customer@example.com",
		Evidence:          []string{`raw_args={"email":"customer@example.com","body":"secret"}`},
		Signals:           []string{loop.SignalRecipientOutOfPolicy},
		DetectorVersion:   loop.DetectorVersion,
		PolicyVersion:     loop.ActionPolicyVersion,
		ArgsFingerprint:   fingerprintString(`{"email":"customer@example.com"}`),
		ResultFingerprint: fingerprintString(`{"body":"secret"}`),
		ActionRisk:        "write",
	}, DecisionReceiptResult{})

	assertEvidenceIsFingerprintSafe(t, outcome)
	assertOutcomeDoesNotContain(t, outcome, "customer@example.com", "raw_args", "secret")
}

func TestOutcomeCapturesSemanticFieldsFromExplicitInput(t *testing.T) {
	outcome := outcomeFromDecisionReceipt(DecisionReceiptInput{
		Project:         "moat-test",
		SessionID:       "semantic-session",
		ToolName:        "refund_payment",
		DecisionStage:   "pre_tool",
		Action:          "block",
		Reason:          "duplicate_side_effect",
		DetectorVersion: loop.DetectorVersion,
		PolicyVersion:   loop.ActionPolicyVersion,
		ActionRisk:      "money_movement",
		Environment:     "PROD",
		RecipientType:   "customer",
		OperationType:   "refund",
	}, DecisionReceiptResult{})

	if outcome.Environment != "production" {
		t.Fatalf("environment=%q want production", outcome.Environment)
	}
	if outcome.RecipientType != "external_customer" {
		t.Fatalf("recipient_type=%q want external_customer", outcome.RecipientType)
	}
	// "refund" is not a recognized operation verb, so it normalizes to unknown
	// rather than being stored as raw free text.
	if outcome.OperationType != "unknown" {
		t.Fatalf("operation_type=%q want unknown", outcome.OperationType)
	}
}

func TestOutcomeDerivesSemanticFieldsWhenNotProvided(t *testing.T) {
	outcome := outcomeFromDecisionReceipt(DecisionReceiptInput{
		Project:         "moat-test",
		SessionID:       "derive-session",
		ToolName:        "delete_account",
		DecisionStage:   "pre_tool",
		Action:          "block",
		Reason:          "destructive_action",
		DetectorVersion: loop.DetectorVersion,
		PolicyVersion:   loop.ActionPolicyVersion,
		ActionRisk:      "destructive",
		RecipientDomain: "acme-customer.com",
		AllowedDomain:   "hubbleops-internal.com",
	}, DecisionReceiptResult{})

	if outcome.Environment != "" {
		t.Fatalf("environment=%q want empty when not captured", outcome.Environment)
	}
	if outcome.OperationType != "delete" {
		t.Fatalf("operation_type=%q want delete (derived from tool name)", outcome.OperationType)
	}
	if outcome.RecipientType != "external_customer" {
		t.Fatalf("recipient_type=%q want external_customer (recipient domain differs from allowed)", outcome.RecipientType)
	}
}

type recordingOutcomeStore struct {
	err      error
	outcomes []storage.ActionDecisionOutcome
}

func (s *recordingOutcomeStore) InsertActionDecisionOutcome(_ context.Context, outcome storage.ActionDecisionOutcome) (storage.ActionDecisionOutcome, error) {
	if s.err != nil {
		return storage.ActionDecisionOutcome{}, s.err
	}
	outcome.ID = int64(len(s.outcomes) + 1)
	s.outcomes = append(s.outcomes, outcome)
	return outcome, nil
}

func (s *recordingOutcomeStore) CountUnreviewedDecisions(_ context.Context) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	return len(s.outcomes), nil
}

func lastOutcome(t *testing.T, store *recordingOutcomeStore) storage.ActionDecisionOutcome {
	t.Helper()
	if len(store.outcomes) == 0 {
		t.Fatalf("no outcomes captured")
	}
	return store.outcomes[len(store.outcomes)-1]
}

func assertOutcomeDoesNotContain(t *testing.T, outcome storage.ActionDecisionOutcome, forbidden ...string) {
	t.Helper()
	data, err := json.Marshal(outcome)
	if err != nil {
		t.Fatalf("marshal outcome: %v", err)
	}
	encoded := string(data)
	for _, value := range forbidden {
		if value != "" && strings.Contains(encoded, value) {
			t.Fatalf("outcome leaked %q: %s", value, encoded)
		}
	}
}

func assertEvidenceIsFingerprintSafe(t *testing.T, outcome storage.ActionDecisionOutcome) {
	t.Helper()
	var evidence []map[string]string
	if err := json.Unmarshal(outcome.EvidenceJSON, &evidence); err != nil {
		t.Fatalf("parse evidence_json: %v", err)
	}
	if len(evidence) == 0 {
		t.Fatalf("evidence_json is empty")
	}
	for _, item := range evidence {
		for key, value := range item {
			if key == "args" || key == "raw_args" || key == "content" || key == "body" {
				t.Fatalf("unsafe evidence key %q in %s", key, outcome.EvidenceJSON)
			}
			if strings.Contains(value, "@") || strings.Contains(value, "{") || strings.Contains(value, "}") {
				t.Fatalf("unsafe evidence value %q in %s", value, outcome.EvidenceJSON)
			}
		}
	}
}
