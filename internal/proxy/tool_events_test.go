package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/receipts"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

func newToolEventHandler(t *testing.T, action string) (*Handler, string) {
	t.Helper()
	dir := t.TempDir()
	w, err := wal.NewWriter(dir, "sync")
	if err != nil {
		t.Fatalf("new wal writer: %v", err)
	}
	t.Cleanup(func() { w.Close() })

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	cfg := loop.DefaultConfig()
	cfg.Action = action
	h := NewHandler(w, loop.NewStateStore(rdb), cfg)
	h.ActionStore = loop.NewActionStore(rdb)
	return h, dir
}

func TestToolCheckBlocksBeforeRepeatedToolExecution(t *testing.T) {
	h, walDir := newToolEventHandler(t, "block")

	for i := 0; i < 6; i++ {
		body := map[string]any{
			"project":       "tool-test",
			"session_id":    "s1",
			"step_id":       "step-result",
			"tool_name":     "expensive_op",
			"args":          map[string]any{"id": 42},
			"result":        map[string]any{"error": "timeout"},
			"prompt_tokens": 1000 + i*100,
			"output_tokens": 10,
			"cost_usd":      0.10,
			"unix_millis":   int64(i * 5000),
		}
		rec := httptest.NewRecorder()
		h.HandleToolResult(rec, toolReq("/v1/tool/result", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("tool result status=%d body=%s", rec.Code, rec.Body.String())
		}
	}

	checkBody := map[string]any{
		"project":     "tool-test",
		"session_id":  "s1",
		"step_id":     "step-check",
		"tool_name":   "expensive_op",
		"args":        map[string]any{"id": 42},
		"unix_millis": int64(30_000),
	}
	rec := httptest.NewRecorder()
	h.HandleToolCheck(rec, toolReq("/v1/tool/check", checkBody))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("tool check status=%d want 429 body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["action"] != "block" {
		t.Fatalf("action=%v want block body=%s", resp["action"], rec.Body.String())
	}

	h.WAL.Close()
	records := readWALRecords(t, walDir)
	last := records[len(records)-1]
	if last.DecisionStage != "pre_tool" {
		t.Fatalf("last WAL decision_stage=%q want pre_tool", last.DecisionStage)
	}
	if last.LoopAction != "block" {
		t.Fatalf("last WAL loop_action=%q want block", last.LoopAction)
	}
	if last.StepID != "step-check" {
		t.Fatalf("last WAL step_id=%q want step-check", last.StepID)
	}
}

func TestToolCheckBlocksDangerousActionMissingIdempotencyKey(t *testing.T) {
	h, walDir := newToolEventHandler(t, "block")

	body := map[string]any{
		"project":     "tool-test",
		"session_id":  "danger-session",
		"step_id":     "delete-1",
		"tool_name":   "delete_account",
		"action_risk": "dangerous",
		"args":        map[string]any{"account_id": "acct_1"},
		"unix_millis": int64(1_000),
	}
	rec := httptest.NewRecorder()
	h.HandleToolCheck(rec, toolReq("/v1/tool/check", body))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429 body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["action"] != "block" {
		t.Fatalf("action=%v want block body=%s", resp["action"], rec.Body.String())
	}
	if resp["receipt"] == nil {
		t.Fatalf("missing receipt body=%s", rec.Body.String())
	}

	h.WAL.Close()
	records := readWALRecords(t, walDir)
	last := records[len(records)-1]
	if last.ActionRisk != "dangerous" {
		t.Fatalf("action_risk=%q want dangerous", last.ActionRisk)
	}
	if !strings.Contains(last.LoopSignalsFired, loop.SignalMissingIdempotency) {
		t.Fatalf("signals=%q missing %s", last.LoopSignalsFired, loop.SignalMissingIdempotency)
	}
	if last.PolicyVersion != loop.ActionPolicyVersion || last.DecisionID == "" {
		t.Fatalf("receipt fields missing: policy=%q decision_id=%q", last.PolicyVersion, last.DecisionID)
	}
}

func TestActionCheckAcceptsActionNameWithoutToolName(t *testing.T) {
	h, walDir := newToolEventHandler(t, "block")

	body := map[string]any{
		"project":         "action-api",
		"session_id":      "s-action",
		"step_id":         "refund-1",
		"action_name":     "refund_customer",
		"action_risk":     "money_movement",
		"idempotency_key": "refund:invoice_9:5000",
		"args":            map[string]any{"invoice_id": "invoice_9", "amount_cents": 5000},
		"unix_millis":     int64(1_000),
	}
	rec := httptest.NewRecorder()
	h.HandleActionCheck(rec, toolReq("/v1/action/check", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["action_name"] != "refund_customer" {
		t.Fatalf("action_name=%v want refund_customer body=%s", resp["action_name"], rec.Body.String())
	}
	receipt, ok := resp["receipt"].(map[string]any)
	if !ok {
		t.Fatalf("missing receipt body=%s", rec.Body.String())
	}
	if receipt["action_name"] != "refund_customer" {
		t.Fatalf("receipt action_name=%v", receipt["action_name"])
	}

	h.WAL.Close()
	records := readWALRecords(t, walDir)
	last := records[len(records)-1]
	if last.ToolSignature != "refund_customer" {
		t.Fatalf("tool_signature=%q want refund_customer", last.ToolSignature)
	}
}

func TestActionCheckBlocksAmountAboveDeclaredLimit(t *testing.T) {
	h, walDir := newToolEventHandler(t, "block")

	body := map[string]any{
		"project":          "action-api",
		"session_id":       "s-amount",
		"step_id":          "refund-over-limit",
		"action_name":      "refund_customer",
		"action_risk":      "money_movement",
		"idempotency_key":  "refund:invoice_9:7500",
		"resource_id":      "invoice_9",
		"amount_cents":     7500,
		"max_amount_cents": 5000,
		"args":             map[string]any{"invoice_id": "invoice_9", "amount_cents": 7500},
		"unix_millis":      int64(1_000),
	}
	rec := httptest.NewRecorder()
	h.HandleActionCheck(rec, toolReq("/v1/action/check", body))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429 body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["action"] != "block" {
		t.Fatalf("action=%v want block body=%s", resp["action"], rec.Body.String())
	}
	if !strings.Contains(strings.Join(anyStringSlice(resp["signals"]), ","), loop.SignalPolicyAmountExceeded) {
		t.Fatalf("signals=%v missing %s", resp["signals"], loop.SignalPolicyAmountExceeded)
	}

	h.WAL.Close()
	records := readWALRecords(t, walDir)
	last := records[len(records)-1]
	if last.ResourceID != "invoice_9" || last.AmountCents != 7500 || last.MaxAmountCents != 5000 {
		t.Fatalf("WAL effect scope missing: resource=%q amount=%d max=%d", last.ResourceID, last.AmountCents, last.MaxAmountCents)
	}
	if !strings.Contains(last.LoopSignalsFired, loop.SignalPolicyAmountExceeded) {
		t.Fatalf("signals=%q missing %s", last.LoopSignalsFired, loop.SignalPolicyAmountExceeded)
	}
}

func TestActionCheckWritesSignedReceipt(t *testing.T) {
	h, walDir := newToolEventHandler(t, "block")
	secret := []byte("receipt-secret")
	h.ReceiptSigner = receipts.NewSigner("test-key", secret)

	body := map[string]any{
		"project":         "action-api",
		"session_id":      "s-signed",
		"step_id":         "refund-signed",
		"action_name":     "refund_customer",
		"action_risk":     "money_movement",
		"idempotency_key": "refund:invoice_9:5000",
		"resource_id":     "invoice_9",
		"amount_cents":    5000,
		"args":            map[string]any{"invoice_id": "invoice_9", "amount_cents": 5000},
		"unix_millis":     int64(1_000),
	}
	rec := httptest.NewRecorder()
	h.HandleActionCheck(rec, toolReq("/v1/action/check", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	receipt, ok := resp["receipt"].(map[string]any)
	if !ok {
		t.Fatalf("missing receipt body=%s", rec.Body.String())
	}
	if receipt["signature"] == "" || receipt["key_id"] != "test-key" {
		t.Fatalf("receipt signature/key missing: %+v", receipt)
	}

	h.WAL.Close()
	records := readWALRecords(t, walDir)
	last := records[len(records)-1]
	if last.ReceiptSignature == "" || last.ReceiptKeyID != "test-key" {
		t.Fatalf("WAL signature/key missing: signature=%q key=%q", last.ReceiptSignature, last.ReceiptKeyID)
	}
	if err := receipts.VerifyRecord(secret, last); err != nil {
		t.Fatalf("verify receipt: %v", err)
	}
}

func TestToolCheckCompatibilityAliasStillWorks(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")

	body := map[string]any{
		"project":     "compat",
		"session_id":  "s-compat",
		"tool_name":   "search_docs",
		"action_risk": "read",
		"args":        map[string]any{"query": "refund policy"},
		"unix_millis": int64(1_000),
	}
	rec := httptest.NewRecorder()
	h.HandleToolCheck(rec, toolReq("/v1/tool/check", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestToolCheckBlocksDuplicateSideEffectByIdempotencyKey(t *testing.T) {
	h, walDir := newToolEventHandler(t, "block")

	body := map[string]any{
		"project":         "tool-test",
		"session_id":      "dup-session",
		"step_id":         "refund-1",
		"tool_name":       "refund_customer",
		"action_risk":     "write",
		"idempotency_key": "refund:cust_1:invoice_9:5000",
		"args":            map[string]any{"customer_id": "cust_1", "invoice_id": "invoice_9", "amount_cents": 5000},
		"unix_millis":     int64(1_000),
	}
	first := httptest.NewRecorder()
	h.HandleToolCheck(first, toolReq("/v1/tool/check", body))
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}

	body["step_id"] = "refund-2"
	body["unix_millis"] = int64(2_000)
	second := httptest.NewRecorder()
	h.HandleToolCheck(second, toolReq("/v1/tool/check", body))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("duplicate status=%d want 429 body=%s", second.Code, second.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse duplicate response: %v", err)
	}
	if resp["action"] != "block" {
		t.Fatalf("action=%v want block body=%s", resp["action"], second.Body.String())
	}
	if resp["idempotency_key"] != "refund:cust_1:invoice_9:5000" {
		t.Fatalf("idempotency_key=%v", resp["idempotency_key"])
	}
	if resp["receipt"] == nil {
		t.Fatalf("missing receipt body=%s", second.Body.String())
	}

	h.WAL.Close()
	records := readWALRecords(t, walDir)
	last := records[len(records)-1]
	if last.ResultClass != loop.ResultDuplicateAction {
		t.Fatalf("result_class=%q want %q", last.ResultClass, loop.ResultDuplicateAction)
	}
	if last.ActionRisk != "write" {
		t.Fatalf("action_risk=%q want write", last.ActionRisk)
	}
	if last.IdempotencyKey != "refund:cust_1:invoice_9:5000" {
		t.Fatalf("idempotency_key=%q", last.IdempotencyKey)
	}
	if last.DecisionID == "" || last.PolicyVersion == "" || last.DecisionReason == "" || last.DecisionEvidence == "" {
		t.Fatalf("receipt fields missing: decision_id=%q policy=%q reason=%q evidence=%q", last.DecisionID, last.PolicyVersion, last.DecisionReason, last.DecisionEvidence)
	}
}

func TestToolCheckShadowDuplicateSideEffectAllowsWithReceipt(t *testing.T) {
	h, walDir := newToolEventHandler(t, "shadow")

	body := map[string]any{
		"project":         "tool-test",
		"session_id":      "shadow-dup",
		"step_id":         "email-1",
		"tool_name":       "send_email",
		"action_risk":     "customer_visible",
		"idempotency_key": "email:cust_1:subject_hash:body_hash",
		"args":            map[string]any{"customer_id": "cust_1"},
		"unix_millis":     int64(1_000),
	}
	rec := httptest.NewRecorder()
	h.HandleToolCheck(rec, toolReq("/v1/tool/check", body))
	if rec.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", rec.Code, rec.Body.String())
	}

	body["step_id"] = "email-2"
	body["unix_millis"] = int64(2_000)
	dup := httptest.NewRecorder()
	h.HandleToolCheck(dup, toolReq("/v1/tool/check", body))
	if dup.Code != http.StatusOK {
		t.Fatalf("shadow duplicate status=%d want 200 body=%s", dup.Code, dup.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(dup.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse shadow response: %v", err)
	}
	if resp["action"] != "allow" {
		t.Fatalf("action=%v want allow body=%s", resp["action"], dup.Body.String())
	}
	if resp["would_action"] != "block" {
		t.Fatalf("would_action=%v want block body=%s", resp["would_action"], dup.Body.String())
	}

	h.WAL.Close()
	records := readWALRecords(t, walDir)
	last := records[len(records)-1]
	if last.LoopAction != "shadow_would_block" {
		t.Fatalf("loop_action=%q want shadow_would_block", last.LoopAction)
	}
	if last.ImmediateOutcome != "blocked" {
		t.Fatalf("immediate_outcome=%q want blocked", last.ImmediateOutcome)
	}
	if last.ResultClass != loop.ResultDuplicateAction {
		t.Fatalf("result_class=%q want duplicate_side_effect", last.ResultClass)
	}
}

func TestToolCheckAllowsPollingWithChangingState(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")

	for i, progress := range []int{0, 25, 50, 75, 100} {
		body := map[string]any{
			"project":          "tool-test",
			"session_id":       "polling",
			"tool_name":        "poll_job_status",
			"args":             map[string]any{"job_id": "j1"},
			"result":           map[string]any{"status": "running", "progress": progress},
			"state_delta_hash": "progress-" + string(rune('a'+i)),
			"prompt_tokens":    100,
			"output_tokens":    10,
			"cost_usd":         0.001,
			"unix_millis":      int64(i * 5000),
		}
		rec := httptest.NewRecorder()
		h.HandleToolResult(rec, toolReq("/v1/tool/result", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("tool result status=%d body=%s", rec.Code, rec.Body.String())
		}
	}

	checkBody := map[string]any{
		"project":     "tool-test",
		"session_id":  "polling",
		"tool_name":   "poll_job_status",
		"args":        map[string]any{"job_id": "j1"},
		"unix_millis": int64(25_000),
	}
	rec := httptest.NewRecorder()
	h.HandleToolCheck(rec, toolReq("/v1/tool/check", checkBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("polling tool check status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["action"] != "allow" {
		t.Fatalf("polling action=%v want allow body=%s", resp["action"], rec.Body.String())
	}
}

func TestToolCheckFailsOpenWhenBlockCannotBeAudited(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")

	for i := 0; i < 6; i++ {
		body := map[string]any{
			"project":       "tool-test",
			"session_id":    "audit-fail-open",
			"tool_name":     "expensive_op",
			"args":          map[string]any{"id": 42},
			"result":        map[string]any{"error": "timeout"},
			"prompt_tokens": 1000 + i*100,
			"output_tokens": 10,
			"cost_usd":      0.10,
			"unix_millis":   int64(i * 5000),
		}
		rec := httptest.NewRecorder()
		h.HandleToolResult(rec, toolReq("/v1/tool/result", body))
		if rec.Code != http.StatusOK {
			t.Fatalf("tool result status=%d body=%s", rec.Code, rec.Body.String())
		}
	}

	if err := h.WAL.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}

	checkBody := map[string]any{
		"project":     "tool-test",
		"session_id":  "audit-fail-open",
		"tool_name":   "expensive_op",
		"args":        map[string]any{"id": 42},
		"unix_millis": int64(30_000),
	}
	rec := httptest.NewRecorder()
	h.HandleToolCheck(rec, toolReq("/v1/tool/check", checkBody))

	if rec.Code != http.StatusOK {
		t.Fatalf("tool check status=%d want 200 fail-open body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["action"] != "allow" {
		t.Fatalf("action=%v want allow body=%s", resp["action"], rec.Body.String())
	}
	if resp["would_action"] != "block" {
		t.Fatalf("would_action=%v want block body=%s", resp["would_action"], rec.Body.String())
	}
	if resp["fail_open"] != true {
		t.Fatalf("fail_open=%v want true body=%s", resp["fail_open"], rec.Body.String())
	}
}

func toolReq(path string, body map[string]any) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func anyStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
