package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/hubbleops/hubbleops/internal/auth"
	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
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

// TestActionCheckClaimNonceRoundtrip covers release ownership at the HTTP boundary: the
// pre-tool check hands out a claim nonce, and only a result event echoing that nonce can
// release the pending lease. A late or nonce-less failure callback must leave the lease
// in place (it expires on its own) instead of opening a window for a duplicate execution.
func TestActionCheckClaimNonceRoundtrip(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")

	checkBody := map[string]any{
		"project":         "tool-test",
		"session_id":      "nonce-rt",
		"step_id":         "refund-1",
		"tool_name":       "refund_customer",
		"action_risk":     "money_movement",
		"idempotency_key": "refund:cust_1:inv_9",
		"args":            map[string]any{"invoice": "inv_9"},
		"unix_millis":     int64(1_000),
	}
	rec := httptest.NewRecorder()
	h.HandleActionCheck(rec, toolReq("/v1/action/check", checkBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("check status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	nonce, _ := resp["claim_nonce"].(string)
	if nonce == "" {
		t.Fatalf("check response missing claim_nonce: %s", rec.Body.String())
	}

	// A failure result WITHOUT the nonce must not release the lease.
	resultBody := map[string]any{
		"project":         "tool-test",
		"session_id":      "nonce-rt",
		"step_id":         "refund-1",
		"tool_name":       "refund_customer",
		"action_risk":     "money_movement",
		"idempotency_key": "refund:cust_1:inv_9",
		"result_class":    "rate_limited",
		"unix_millis":     int64(2_000),
	}
	rec = httptest.NewRecorder()
	h.HandleActionResult(rec, toolReq("/v1/action/result", resultBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("result status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.HandleActionCheck(rec, toolReq("/v1/action/check", checkBody))
	if rec.Code != http.StatusConflict {
		t.Fatalf("recheck status=%d want 409 (nonce-less release must not free the lease) body=%s", rec.Code, rec.Body.String())
	}

	// The same failure result WITH the nonce releases it, allowing a fresh claim.
	resultBody["claim_nonce"] = nonce
	resultBody["unix_millis"] = int64(3_000)
	rec = httptest.NewRecorder()
	h.HandleActionResult(rec, toolReq("/v1/action/result", resultBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("owned result status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.HandleActionCheck(rec, toolReq("/v1/action/check", checkBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("final check status=%d want 200 after owner release body=%s", rec.Code, rec.Body.String())
	}
}

// The W8 regression at the HTTP boundary: five $49 refunds with distinct
// invoices and keys, each under the per-action cap, must die at the cumulative
// cap — scoped to the authenticated agent key, before any idempotency claim.
func TestActionCheckEnforcesCumulativeCap(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")
	h.LimitStore = loop.NewMemoryLimitStore(loop.LimitsConfig{
		Cumulative: []loop.CumulativeRule{{
			Name: "refund-cap", Scope: "agent", WindowSeconds: 3600, MaxAmountCents: 10_000,
		}},
	})

	send := func(step string, amount int64) *httptest.ResponseRecorder {
		body := map[string]any{
			"project":         "tool-test",
			"session_id":      "drain-" + step, // rotating sessions must not matter
			"step_id":         step,
			"tool_name":       "refund_customer",
			"action_risk":     "money_movement",
			"idempotency_key": "refund:" + step,
			"amount_cents":    amount,
			"args":            map[string]any{"invoice": step},
		}
		req := toolReq("/v1/action/check", body)
		req = req.WithContext(auth.WithIdentity(req.Context(), "tool-test", "agentkey11111111"))
		rec := httptest.NewRecorder()
		h.HandleActionCheck(rec, req)
		return rec
	}

	if rec := send("inv1", 4_900); rec.Code != http.StatusOK {
		t.Fatalf("first refund status=%d body=%s", rec.Code, rec.Body.String())
	}
	if rec := send("inv2", 4_900); rec.Code != http.StatusOK {
		t.Fatalf("second refund status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec := send("inv3", 4_900)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third refund status=%d want 429 body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	signals, _ := json.Marshal(resp["signals"])
	if !strings.Contains(string(signals), "cumulative_amount_exceeded") {
		t.Fatalf("signals=%s want cumulative_amount_exceeded", signals)
	}
	// A limit rejection must not have taken an idempotency claim: the same key
	// must be claimable once headroom exists (no in-flight 409 from a ghost lease).
	if rec := send("inv3", 100); rec.Code != http.StatusOK {
		t.Fatalf("headroom retry status=%d want 200 (limit block must not leave a pending claim) body=%s", rec.Code, rec.Body.String())
	}
}

// Repeated enforced blocks open the circuit breaker: the agent's fail-closed
// actions are quarantined even when the next action would otherwise pass.
func TestActionCheckCircuitBreakerQuarantinesAgent(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")
	h.LimitStore = loop.NewMemoryLimitStore(loop.LimitsConfig{
		Breaker: loop.BreakerRule{Trips: 2, WindowSeconds: 600, CooldownSeconds: 900},
	})

	send := func(step string, body map[string]any) *httptest.ResponseRecorder {
		body["project"] = "tool-test"
		body["session_id"] = "breaker-sess"
		body["step_id"] = step
		req := toolReq("/v1/action/check", body)
		req = req.WithContext(auth.WithIdentity(req.Context(), "tool-test", "agentkey22222222"))
		rec := httptest.NewRecorder()
		h.HandleActionCheck(rec, req)
		return rec
	}

	// Two enforced blocks: dangerous deletes with no backup/capability.
	for i := 0; i < 2; i++ {
		rec := send(fmt.Sprintf("del-%d", i), map[string]any{
			"tool_name":       "delete_account",
			"action_risk":     "dangerous",
			"idempotency_key": fmt.Sprintf("delete:acct_%d", i),
			"args":            map[string]any{"account_id": i},
		})
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("dangerous delete %d status=%d want 429 body=%s", i, rec.Code, rec.Body.String())
		}
	}

	// The breaker is now open: a refund that would normally pass is quarantined.
	rec := send("refund-ok", map[string]any{
		"tool_name":       "refund_customer",
		"action_risk":     "money_movement",
		"idempotency_key": "refund:inv_breaker",
		"amount_cents":    1_000,
		"args":            map[string]any{"invoice": "inv_breaker"},
	})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("quarantined refund status=%d want 429 body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "circuit_breaker_open") {
		t.Fatalf("response missing circuit_breaker_open signal: %s", rec.Body.String())
	}

	// Another agent under the same project is untouched.
	other := map[string]any{
		"project":         "tool-test",
		"session_id":      "other-sess",
		"step_id":         "refund-other",
		"tool_name":       "refund_customer",
		"action_risk":     "money_movement",
		"idempotency_key": "refund:inv_other",
		"amount_cents":    1_000,
		"args":            map[string]any{"invoice": "inv_other"},
	}
	reqOther := toolReq("/v1/action/check", other)
	reqOther = reqOther.WithContext(auth.WithIdentity(reqOther.Context(), "tool-test", "agentkey33333333"))
	recOther := httptest.NewRecorder()
	h.HandleActionCheck(recOther, reqOther)
	if recOther.Code != http.StatusOK {
		t.Fatalf("other agent status=%d want 200 body=%s", recOther.Code, recOther.Body.String())
	}
}

// In shadow mode limits are observed, not enforced — and shadow blocks must
// not count as breaker trips.
func TestShadowModeDoesNotEnforceLimitsOrTripBreaker(t *testing.T) {
	h, _ := newToolEventHandler(t, "shadow")
	h.LimitStore = loop.NewMemoryLimitStore(loop.LimitsConfig{
		Cumulative: []loop.CumulativeRule{{
			Name: "refund-cap", Scope: "agent", WindowSeconds: 3600, MaxAmountCents: 1_000,
		}},
		Breaker: loop.BreakerRule{Trips: 1, WindowSeconds: 600, CooldownSeconds: 900},
	})

	send := func(step string) *httptest.ResponseRecorder {
		body := map[string]any{
			"project":         "tool-test",
			"session_id":      "shadow-sess",
			"step_id":         step,
			"tool_name":       "refund_customer",
			"action_risk":     "money_movement",
			"idempotency_key": "refund:" + step,
			"amount_cents":    900,
			"args":            map[string]any{"invoice": step},
		}
		req := toolReq("/v1/action/check", body)
		req = req.WithContext(auth.WithIdentity(req.Context(), "tool-test", "agentkey44444444"))
		rec := httptest.NewRecorder()
		h.HandleActionCheck(rec, req)
		return rec
	}

	if rec := send("s1"); rec.Code != http.StatusOK {
		t.Fatalf("first shadow status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec := send("s2") // over the cap: would block, must still allow
	if rec.Code != http.StatusOK {
		t.Fatalf("shadow over-cap status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if resp["action"] != "allow" || resp["would_action"] != "block" {
		t.Fatalf("shadow response action=%v would=%v want allow/block", resp["action"], resp["would_action"])
	}
	// Breaker must not have opened from shadow decisions.
	if rec := send("s3"); rec.Code != http.StatusOK {
		t.Fatalf("post-shadow status=%d want 200 (shadow must not trip the breaker) body=%s", rec.Code, rec.Body.String())
	}
}

// TestToolEventsScopeSessionToAuthenticatedKey: when a request is authenticated, the
// session that detector state, the action ledger, and receipts key on must be namespaced
// under the API-key identity, not taken verbatim from the client.
func TestToolEventsScopeSessionToAuthenticatedKey(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")

	body := map[string]any{
		"project":     "tool-test",
		"session_id":  "s1",
		"step_id":     "step-1",
		"tool_name":   "search_docs",
		"args":        map[string]any{"q": "hello"},
		"unix_millis": int64(1_000),
	}
	req := toolReq("/v1/tool/check", body)
	req = req.WithContext(auth.WithIdentity(req.Context(), "tool-test", "k1k1k1k1k1k1k1k1"))
	rec := httptest.NewRecorder()
	h.HandleToolCheck(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	receipt, _ := resp["receipt"].(map[string]any)
	if receipt == nil {
		t.Fatalf("response missing receipt: %s", rec.Body.String())
	}
	if got := receipt["session_id"]; got != "key:k1k1k1k1k1k1k1k1:s1" {
		t.Fatalf("receipt session_id=%v want key:k1k1k1k1k1k1k1k1:s1", got)
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

func TestActionCheckUsesAuthenticatedProjectOverBodyProject(t *testing.T) {
	h, walDir := newToolEventHandler(t, "block")

	body := map[string]any{
		"project":         "spoofed-project",
		"session_id":      "auth-session",
		"step_id":         "auth-step",
		"action_name":     "send_email",
		"action_risk":     "write",
		"idempotency_key": "email:user@example.com:welcome",
		"args":            map[string]any{"to": "user@example.com"},
		"unix_millis":     int64(1_000),
	}
	req := toolReq("/v1/action/check", body)
	req = req.WithContext(auth.WithProject(req.Context(), "authenticated-project"))
	rec := httptest.NewRecorder()
	h.HandleActionCheck(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}

	h.WAL.Close()
	records := readWALRecords(t, walDir)
	last := records[len(records)-1]
	if last.Project != "authenticated-project" {
		t.Fatalf("WAL project=%q want authenticated-project", last.Project)
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
	if strings.Contains(rec.Body.String(), "invoice_9") || resp["resource_id"] != nil {
		t.Fatalf("response leaked raw resource id: %s", rec.Body.String())
	}
	if resp["resource_fingerprint"] != privacy.FingerprintString("invoice_9") {
		t.Fatalf("resource_fingerprint=%v", resp["resource_fingerprint"])
	}
	if !strings.Contains(strings.Join(anyStringSlice(resp["signals"]), ","), loop.SignalPolicyAmountExceeded) {
		t.Fatalf("signals=%v missing %s", resp["signals"], loop.SignalPolicyAmountExceeded)
	}

	h.WAL.Close()
	records := readWALRecords(t, walDir)
	last := records[len(records)-1]
	if last.ResourceID != "" {
		t.Fatalf("WAL stored raw resource_id=%q", last.ResourceID)
	}
	if last.ResourceFingerprint != privacy.FingerprintString("invoice_9") || last.AmountCents != 7500 || last.MaxAmountCents != 5000 {
		t.Fatalf("WAL effect scope missing: resource_fingerprint=%q amount=%d max=%d", last.ResourceFingerprint, last.AmountCents, last.MaxAmountCents)
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

	// The refund executes successfully and is recorded; this commits the pending claim
	// for the full duplicate window.
	resultBody := map[string]any{
		"project":         "tool-test",
		"session_id":      "dup-session",
		"step_id":         "refund-1",
		"tool_name":       "refund_customer",
		"action_risk":     "write",
		"idempotency_key": "refund:cust_1:invoice_9:5000",
		"result":          map[string]any{"refunded": true, "txn": "txn_42"},
		"result_class":    "success",
		"unix_millis":     int64(1_500),
	}
	resultRec := httptest.NewRecorder()
	h.HandleToolResult(resultRec, toolReq("/v1/tool/result", resultBody))
	if resultRec.Code != http.StatusOK {
		t.Fatalf("result status=%d body=%s", resultRec.Code, resultRec.Body.String())
	}

	// A well-behaved retry of an already-committed action must be REPLAYED (200 with the
	// recorded outcome), not pushed onto the override/429 path that legitimate retries hit.
	body["step_id"] = "refund-2"
	body["unix_millis"] = int64(2_000)
	second := httptest.NewRecorder()
	h.HandleToolCheck(second, toolReq("/v1/tool/check", body))
	if second.Code != http.StatusOK {
		t.Fatalf("duplicate status=%d want 200 (replay) body=%s", second.Code, second.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(second.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse duplicate response: %v", err)
	}
	if resp["action"] != "duplicate" {
		t.Fatalf("action=%v want duplicate body=%s", resp["action"], second.Body.String())
	}
	replay, ok := resp["replay"].(map[string]any)
	if !ok {
		t.Fatalf("missing replay body=%s", second.Body.String())
	}
	result, ok := replay["result"].(map[string]any)
	if !ok || result["txn"] != "txn_42" {
		t.Fatalf("replay did not carry the original result: %v", replay["result"])
	}
	if _, ok := resp["idempotency_key"]; ok {
		t.Fatalf("response echoed raw idempotency_key: %s", second.Body.String())
	}
	if resp["idempotency_key_hash"] != privacy.FingerprintString("refund:cust_1:invoice_9:5000") {
		t.Fatalf("idempotency_key_hash=%v", resp["idempotency_key_hash"])
	}
	if resp["receipt"] == nil {
		t.Fatalf("missing receipt body=%s", second.Body.String())
	}
	if strings.Contains(second.Body.String(), "refund:cust_1:invoice_9:5000") {
		t.Fatalf("response leaked raw idempotency key: %s", second.Body.String())
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
	if last.IdempotencyKey != "" {
		t.Fatalf("WAL stored raw idempotency_key=%q", last.IdempotencyKey)
	}
	if last.IdempotencyKeyHash != privacy.FingerprintString("refund:cust_1:invoice_9:5000") {
		t.Fatalf("idempotency_key_hash=%q", last.IdempotencyKeyHash)
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

	// The first send succeeds and commits, so the second attempt is a true duplicate
	// rather than an in-flight retry.
	resultBody := map[string]any{
		"project":         "tool-test",
		"session_id":      "shadow-dup",
		"step_id":         "email-1",
		"tool_name":       "send_email",
		"action_risk":     "customer_visible",
		"idempotency_key": "email:cust_1:subject_hash:body_hash",
		"result_class":    "success",
		"unix_millis":     int64(1_500),
	}
	resultRec := httptest.NewRecorder()
	h.HandleToolResult(resultRec, toolReq("/v1/tool/result", resultBody))
	if resultRec.Code != http.StatusOK {
		t.Fatalf("result status=%d body=%s", resultRec.Code, resultRec.Body.String())
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

func TestToolCheckEnforceWithoutReceiptOverrideAllowsBlock(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")
	h.EnforceWithoutReceipt = true
	if err := h.WAL.Write(wal.Record{Project: "_test", Provider: "_test", Model: "_seed", PromptHash: "seed"}); err != nil {
		t.Fatalf("seed wal: %v", err)
	}
	if err := h.WAL.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}

	body := map[string]any{
		"project":     "tool-test",
		"session_id":  "audit-override",
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
	if resp["fail_open"] == true {
		t.Fatalf("fail_open=true despite enforce_without_receipt body=%s", rec.Body.String())
	}
}

func TestActionCheckFailClosedReceiptRecoveredFromDeadLetter(t *testing.T) {
	dir := t.TempDir()
	w, err := wal.NewWriter(dir, "sync")
	if err != nil {
		t.Fatalf("new wal writer: %v", err)
	}
	// Dead Redis forces the action firewall to fail closed (block) on a dangerous action.
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { dead.Close() })

	cfg := loop.DefaultConfig()
	cfg.Action = "block"
	h := NewHandler(w, loop.NewStateStore(dead), cfg)
	h.ActionStore = loop.NewActionStore(dead)
	dl, err := wal.NewDeadLetter(dir)
	if err != nil {
		t.Fatalf("new dead-letter: %v", err)
	}
	h.ReceiptQueue = dl

	// Break the WAL so the block receipt cannot be written durably. Seed a write first
	// so the file handle is actually open — closing an unused writer would just reopen.
	if err := h.WAL.Write(wal.Record{Project: "_seed", Provider: "_seed", Model: "_seed", PromptHash: "seed"}); err != nil {
		t.Fatalf("seed wal: %v", err)
	}
	if err := h.WAL.Close(); err != nil {
		t.Fatalf("close wal: %v", err)
	}

	dangerous := map[string]any{
		"project":         "tool-test",
		"session_id":      "dlq",
		"tool_name":       "delete_resource",
		"action_risk":     "dangerous",
		"idempotency_key": "delete:res_1",
		"backup_id":       "bk_1",
		"args":            map[string]any{"id": "res_1"},
		"unix_millis":     int64(1_000),
	}
	rec := httptest.NewRecorder()
	h.HandleToolCheck(rec, toolReq("/v1/action/check", dangerous))

	// High-risk action must still be blocked despite the unwritable WAL (fail-closed)...
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429 (fail-closed) body=%s", rec.Code, rec.Body.String())
	}
	// ...and its receipt must be durably queued, not lost.
	if pending, _ := dl.Pending(); pending != 1 {
		t.Fatalf("dead-letter pending=%d want 1", pending)
	}

	// Simulate recovery: a healthy WAL writer comes back (e.g. after restart) and the
	// drainer replays the queued receipt into the audit log.
	w2, err := wal.NewWriter(dir, "sync")
	if err != nil {
		t.Fatalf("reopen wal: %v", err)
	}
	h.WAL = w2
	if recovered := h.DrainReceiptQueue(); recovered != 1 {
		t.Fatalf("recovered=%d want 1", recovered)
	}
	if pending, _ := dl.Pending(); pending != 0 {
		t.Fatalf("dead-letter pending after drain=%d want 0", pending)
	}

	// The recovered receipt is now durably in the WAL as a block decision.
	w2.Close()
	records := readWALRecords(t, dir)
	var found bool
	for _, r := range records {
		if r.DecisionStage == "pre_tool" && r.LoopAction == "block" && r.ToolSignature == "delete_resource" {
			found = true
		}
	}
	if !found {
		t.Fatalf("recovered block receipt not found in WAL after drain")
	}
}

func TestActionCheckRiskFloorPreventsClientDowngrade(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")
	// Operator classifies refund_customer as a write; the client cannot downgrade it.
	h.LoopCfg.ToolRiskFloor = map[string]string{"refund_customer": loop.ActionRiskWrite}

	mkBody := func(step string) map[string]any {
		return map[string]any{
			"project":         "tool-test",
			"session_id":      "floor",
			"step_id":         step,
			"tool_name":       "refund_customer",
			"action_risk":     "read", // client lies: claims read to dodge the firewall
			"idempotency_key": "refund:cust_1:invoice_9",
			"args":            map[string]any{"invoice": "inv_9"},
			"unix_millis":     int64(1_000),
		}
	}

	// First call: firewall engages (despite the "read" label) and records first-seen.
	first := httptest.NewRecorder()
	h.HandleToolCheck(first, toolReq("/v1/action/check", mkBody("r1")))
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d want 200 body=%s", first.Code, first.Body.String())
	}
	var firstResp map[string]any
	_ = json.Unmarshal(first.Body.Bytes(), &firstResp)
	if firstResp["action_risk"] != loop.ActionRiskWrite {
		t.Fatalf("receipt action_risk=%v want write (floored) body=%s", firstResp["action_risk"], first.Body.String())
	}

	// Second identical call: the client's "read" would have skipped dedup entirely and
	// returned a plain 200 allow. Because the floor engaged the firewall, the first claim
	// is still in flight, so the retry is held with a 409 instead of being waved through.
	second := httptest.NewRecorder()
	h.HandleToolCheck(second, toolReq("/v1/action/check", mkBody("r2")))
	if second.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d want 409 (in-flight) body=%s", second.Code, second.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(second.Body.Bytes(), &resp)
	if resp["action"] != "block" {
		t.Fatalf("action=%v want block body=%s", resp["action"], second.Body.String())
	}
}

func TestActionCheckIdempotencyMismatchReturns422(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")

	mkBody := func(amount int) map[string]any {
		return map[string]any{
			"project":         "tool-test",
			"session_id":      "mismatch",
			"tool_name":       "refund_customer",
			"action_risk":     "money_movement",
			"idempotency_key": "refund:cust_1:invoice_9",
			"amount_cents":    amount,
			"args":            map[string]any{"invoice": "inv_9"},
			"unix_millis":     int64(1_000),
		}
	}

	first := httptest.NewRecorder()
	h.HandleToolCheck(first, toolReq("/v1/action/check", mkBody(5000)))
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d want 200 body=%s", first.Code, first.Body.String())
	}

	// Same key, different amount: contradictory replay → 422, not 429.
	second := httptest.NewRecorder()
	h.HandleToolCheck(second, toolReq("/v1/action/check", mkBody(9999)))
	if second.Code != http.StatusUnprocessableEntity {
		t.Fatalf("mismatch status=%d want 422 body=%s", second.Code, second.Body.String())
	}
	if second.Header().Get("Retry-After") != "" {
		t.Fatalf("422 should not carry Retry-After, got %q", second.Header().Get("Retry-After"))
	}
	var resp map[string]any
	_ = json.Unmarshal(second.Body.Bytes(), &resp)
	if resp["action"] != "block" {
		t.Fatalf("action=%v want block body=%s", resp["action"], second.Body.String())
	}
}

func TestActionCheckFailClosedForDangerousWhenLedgerUnavailable(t *testing.T) {
	h, _ := newToolEventHandler(t, "block")
	// Force the action ledger to error by pointing it at a dead Redis.
	dead := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { dead.Close() })
	h.ActionStore = loop.NewActionStore(dead)

	dangerous := map[string]any{
		"project":         "tool-test",
		"session_id":      "outage",
		"tool_name":       "delete_resource",
		"action_risk":     "dangerous",
		"idempotency_key": "delete:res_1",
		"backup_id":       "bk_1",
		"args":            map[string]any{"id": "res_1"},
		"unix_millis":     int64(1_000),
	}
	recD := httptest.NewRecorder()
	h.HandleToolCheck(recD, toolReq("/v1/action/check", dangerous))
	if recD.Code != http.StatusTooManyRequests {
		t.Fatalf("dangerous status=%d want 429 (fail-closed) body=%s", recD.Code, recD.Body.String())
	}

	// A write action under the same outage fails OPEN so the agent isn't halted.
	write := map[string]any{
		"project":         "tool-test",
		"session_id":      "outage",
		"tool_name":       "send_email",
		"action_risk":     "write",
		"idempotency_key": "email:cust_1:welcome",
		"args":            map[string]any{"to": "a@b.com"},
		"unix_millis":     int64(2_000),
	}
	recW := httptest.NewRecorder()
	h.HandleToolCheck(recW, toolReq("/v1/action/check", write))
	if recW.Code != http.StatusOK {
		t.Fatalf("write status=%d want 200 (fail-open) body=%s", recW.Code, recW.Body.String())
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
