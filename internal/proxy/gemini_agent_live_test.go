package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/providers"
	"github.com/hubbleops/hubbleops/internal/receiptverify"
)

func TestLiveGeminiAgentActionFirewallDuplicateAndDangerous(t *testing.T) {
	key := liveGeminiKey(t)
	if os.Getenv("HUBBLEOPS_LIVE_GEMINI_AGENT") != "1" {
		t.Skip("set HUBBLEOPS_LIVE_GEMINI_AGENT=1 to run live Gemini agent action-firewall tests")
	}
	handler, walDir := newToolEventHandler(t, "block")

	refundSchema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"invoice_id": map[string]any{"type": "string"},
			"amount_cents": map[string]any{
				"type": "integer",
			},
		},
		"required": []string{"invoice_id", "amount_cents"},
	}
	refundPrompt := "You are a billing agent. The user asks for a refund. Call refund_customer with invoice_id invoice_9 and amount_cents 5000."
	firstRefund := liveGeminiAgentCall(t, key, "refund_customer", "Refund a customer invoice.", refundSchema, refundPrompt)
	assertGeminiArg(t, firstRefund, "invoice_id", "invoice_9")
	idempotencyKey := fmt.Sprintf("refund:%s:%v", firstRefund.Args["invoice_id"], firstRefund.Args["amount_cents"])

	first := actionCheck(t, handler, map[string]any{
		"project":         "live-gemini-agent",
		"session_id":      "billing-agent-session",
		"step_id":         "refund-1",
		"action_name":     firstRefund.Name,
		"action_risk":     "money_movement",
		"idempotency_key": idempotencyKey,
		"agent_id":        "gemini-billing-agent",
		"args":            firstRefund.Args,
		"unix_millis":     int64(1_000),
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first refund check status=%d body=%s", first.Code, first.Body.String())
	}

	duplicate := actionCheck(t, handler, map[string]any{
		"project":         "live-gemini-agent",
		"session_id":      "billing-agent-session",
		"step_id":         "refund-2",
		"action_name":     firstRefund.Name,
		"action_risk":     "money_movement",
		"idempotency_key": idempotencyKey,
		"agent_id":        "gemini-billing-agent",
		"args":            firstRefund.Args,
		"unix_millis":     int64(2_000),
	})
	if duplicate.Code != http.StatusTooManyRequests {
		t.Fatalf("duplicate refund status=%d want 429 body=%s", duplicate.Code, duplicate.Body.String())
	}
	var dupResp map[string]any
	if err := json.Unmarshal(duplicate.Body.Bytes(), &dupResp); err != nil {
		t.Fatalf("parse duplicate response: %v", err)
	}
	if dupResp["action"] != "block" || dupResp["idempotency_key_hash"] != privacy.FingerprintString(idempotencyKey) {
		t.Fatalf("duplicate response did not block duplicate key: %s", duplicate.Body.String())
	}

	dangerous := actionCheck(t, handler, map[string]any{
		"project":     "live-gemini-agent",
		"session_id":  "admin-agent-session",
		"step_id":     "delete-1",
		"action_name": "delete_account",
		"action_risk": "dangerous",
		"agent_id":    "simulated-admin-agent",
		"args":        map[string]any{"account_id": "acct_123"},
		"unix_millis": int64(3_000),
	})
	if dangerous.Code != http.StatusTooManyRequests {
		t.Fatalf("dangerous action status=%d want 429 body=%s", dangerous.Code, dangerous.Body.String())
	}

	handler.WAL.Close()
	records := readWALRecords(t, walDir)
	report := receiptverify.Verify(records)
	if !report.Verified {
		t.Fatalf("receipt verification failed: %+v", report)
	}
	if len(records) != 3 {
		t.Fatalf("wal records=%d want 3", len(records))
	}
	if records[1].LoopAction != "block" || records[2].LoopAction != "block" {
		t.Fatalf("expected duplicate and dangerous actions blocked, got actions %q and %q", records[1].LoopAction, records[2].LoopAction)
	}
}

type liveAgentCall struct {
	Name string
	Args map[string]any
}

func liveGeminiAgentCall(t *testing.T, key, functionName, description string, schema map[string]any, prompt string) liveAgentCall {
	t.Helper()
	payload := map[string]any{
		"contents": []map[string]any{{
			"role": "user",
			"parts": []map[string]string{{
				"text": prompt,
			}},
		}},
		"tools": []map[string]any{{
			"functionDeclarations": []map[string]any{{
				"name":        functionName,
				"description": description,
				"parameters":  schema,
			}},
		}},
		"toolConfig": map[string]any{
			"functionCallingConfig": map[string]any{
				"mode":                 "ANY",
				"allowedFunctionNames": []string{functionName},
			},
		},
		"generationConfig": map[string]any{
			"temperature":     0,
			"maxOutputTokens": 128,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal Gemini agent payload: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := "https://generativelanguage.googleapis.com/v1beta/models/" + url.PathEscape(liveGeminiModel()) + ":generateContent"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new Gemini agent request: %v", err)
	}
	req.Header.Set("x-goog-api-key", key)
	req.Header.Set("User-Agent", "hubbleops-live-agent-test/0")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Gemini agent request failed: %v", err)
	}
	defer resp.Body.Close()
	respBody := new(bytes.Buffer)
	if _, err := respBody.ReadFrom(resp.Body); err != nil {
		t.Fatalf("read Gemini agent response: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		skipIfGeminiQuota(t, resp.StatusCode, respBody.String())
		t.Fatalf("Gemini agent status=%d body=%s", resp.StatusCode, safeBody(respBody.String()))
	}

	calls := providers.Registry["/gemini"].ExtractToolCalls(respBody.Bytes())
	if len(calls) == 0 {
		t.Fatalf("Gemini did not return a function call for %s: %s", functionName, safeBody(respBody.String()))
	}
	if calls[0].Name != functionName {
		t.Fatalf("Gemini function=%q want %q body=%s", calls[0].Name, functionName, safeBody(respBody.String()))
	}
	var args map[string]any
	if err := json.Unmarshal([]byte(calls[0].Arguments), &args); err != nil {
		t.Fatalf("parse Gemini function args: %v args=%s", err, calls[0].Arguments)
	}
	return liveAgentCall{Name: calls[0].Name, Args: args}
}

func actionCheck(t *testing.T, h *Handler, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.HandleActionCheck(rec, toolReq("/v1/action/check", body))
	return rec
}

func assertGeminiArg(t *testing.T, call liveAgentCall, key, want string) {
	t.Helper()
	got, ok := call.Args[key]
	if !ok {
		t.Fatalf("Gemini call %s missing arg %s: %+v", call.Name, key, call.Args)
	}
	if fmt.Sprint(got) != want {
		t.Fatalf("Gemini arg %s=%v want %s", key, got, want)
	}
}
