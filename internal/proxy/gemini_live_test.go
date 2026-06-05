package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/witness-proxy/witness-proxy/internal/providers"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

const defaultLiveGeminiModel = "gemini-2.5-flash-lite"

func TestLiveGeminiProxyGenerateContent(t *testing.T) {
	key := liveGeminiKey(t)
	handler, walDir := newTestHandler(t)
	handler.NonStreamTimeout = 30 * time.Second

	body := `{
		"contents":[{"role":"user","parts":[{"text":"Reply with exactly: witness-ok"}]}],
		"generationConfig":{"temperature":0,"maxOutputTokens":8}
	}`
	model := liveGeminiModel()
	req := httptest.NewRequest("POST", "/gemini/v1beta/models/"+model+":generateContent", strings.NewReader(body))
	req.Header.Set("x-goog-api-key", key)
	req.Header.Set("X-Project", "live-gemini-generate")
	req.Header.Set("X-Session-ID", "live-gemini-generate-session")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		skipIfGeminiQuota(t, rec.Code, rec.Body.String())
		t.Fatalf("gemini generate status=%d body=%s", rec.Code, safeBody(rec.Body.String()))
	}

	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("gemini generate response is not JSON: %v body=%s", err, safeBody(rec.Body.String()))
	}
	if decoded["usageMetadata"] == nil {
		t.Fatalf("gemini generate response missing usageMetadata: %s", safeBody(rec.Body.String()))
	}

	handler.WAL.Close()
	records := readWALRecords(t, walDir)
	if len(records) != 1 {
		t.Fatalf("wal records=%d want 1", len(records))
	}
	rec0 := records[0]
	if rec0.Provider != "gemini" {
		t.Fatalf("wal provider=%q want gemini", rec0.Provider)
	}
	if rec0.StatusCode != http.StatusOK {
		t.Fatalf("wal status=%d want 200", rec0.StatusCode)
	}
	if rec0.InputTokens <= 0 || rec0.TotalTokens <= 0 {
		t.Fatalf("wal tokens not populated: input=%d output=%d total=%d", rec0.InputTokens, rec0.OutputTokens, rec0.TotalTokens)
	}
	if rec0.Model == "" {
		t.Fatalf("wal model is empty")
	}
	if rec0.Cost <= 0 {
		t.Fatalf("wal cost=%.8f want >0 for model %q; pricing table may be stale", rec0.Cost, rec0.Model)
	}
}

func TestLiveGeminiProxyStreamGenerateContent(t *testing.T) {
	key := liveGeminiKey(t)
	handler, walDir := newTestHandler(t)
	handler.StreamIdleTimeout = 30 * time.Second

	body := `{
		"contents":[{"role":"user","parts":[{"text":"Reply with exactly: stream-ok"}]}],
		"generationConfig":{"temperature":0,"maxOutputTokens":8}
	}`
	model := liveGeminiModel()
	req := httptest.NewRequest("POST", "/gemini/v1beta/models/"+model+":streamGenerateContent?alt=sse", strings.NewReader(body))
	req.Header.Set("x-goog-api-key", key)
	req.Header.Set("X-Project", "live-gemini-stream")
	req.Header.Set("X-Session-ID", "live-gemini-stream-session")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		skipIfGeminiQuota(t, rec.Code, rec.Body.String())
		t.Fatalf("gemini stream status=%d body=%s", rec.Code, safeBody(rec.Body.String()))
	}
	if !strings.Contains(rec.Body.String(), "data:") {
		t.Fatalf("gemini stream response missing SSE data: %s", safeBody(rec.Body.String()))
	}

	handler.WAL.Close()
	records := readWALRecords(t, walDir)
	if len(records) != 1 {
		t.Fatalf("wal records=%d want 1", len(records))
	}
	rec0 := records[0]
	if !rec0.Stream {
		t.Fatalf("wal stream=false want true")
	}
	if rec0.InputTokens <= 0 || rec0.TotalTokens <= 0 {
		t.Fatalf("stream wal tokens not populated: input=%d output=%d total=%d", rec0.InputTokens, rec0.OutputTokens, rec0.TotalTokens)
	}
	if rec0.Cost <= 0 {
		t.Fatalf("stream wal cost=%.8f want >0 for model %q; pricing table may be stale", rec0.Cost, rec0.Model)
	}
}

func TestLiveGeminiProxyFunctionCallExtraction(t *testing.T) {
	key := liveGeminiKey(t)
	handler, walDir := newTestHandler(t)
	handler.NonStreamTimeout = 30 * time.Second

	body := `{
		"contents":[{"role":"user","parts":[{"text":"Use the get_weather function for Boston."}]}],
		"tools":[{
			"functionDeclarations":[{
				"name":"get_weather",
				"description":"Get weather for a city.",
				"parameters":{
					"type":"object",
					"properties":{"city":{"type":"string"}},
					"required":["city"]
				}
			}]
		}],
		"toolConfig":{"functionCallingConfig":{"mode":"ANY","allowedFunctionNames":["get_weather"]}},
		"generationConfig":{"temperature":0,"maxOutputTokens":64}
	}`
	model := liveGeminiModel()
	req := httptest.NewRequest("POST", "/gemini/v1beta/models/"+model+":generateContent", strings.NewReader(body))
	req.Header.Set("x-goog-api-key", key)
	req.Header.Set("X-Project", "live-gemini-toolcall")
	req.Header.Set("X-Session-ID", "live-gemini-toolcall-session")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		skipIfGeminiQuota(t, rec.Code, rec.Body.String())
		t.Fatalf("gemini function call status=%d body=%s", rec.Code, safeBody(rec.Body.String()))
	}

	handler.WAL.Close()
	records := readWALRecords(t, walDir)
	if len(records) != 1 {
		t.Fatalf("wal records=%d want 1", len(records))
	}
	rec0 := records[0]
	if rec0.ToolSignature != "get_weather" {
		t.Fatalf("wal tool_signature=%q want get_weather; body=%s", rec0.ToolSignature, safeBody(rec.Body.String()))
	}
	if rec0.ArgsFingerprint == "" {
		t.Fatalf("wal args_fingerprint is empty for Gemini function call")
	}
}

func TestLiveGeminiProxyInvalidKeyWritesWAL(t *testing.T) {
	_ = liveGeminiKey(t)
	handler, walDir := newTestHandler(t)
	handler.NonStreamTimeout = 30 * time.Second

	body := `{"contents":[{"parts":[{"text":"hello"}]}]}`
	model := liveGeminiModel()
	req := httptest.NewRequest("POST", "/gemini/v1beta/models/"+model+":generateContent", strings.NewReader(body))
	req.Header.Set("x-goog-api-key", "invalid-test-key")
	req.Header.Set("X-Project", "live-gemini-invalid-key")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized && rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid key status=%d want 400/401/403 body=%s", rec.Code, safeBody(rec.Body.String()))
	}

	handler.WAL.Close()
	records := readWALRecords(t, walDir)
	if len(records) != 1 {
		t.Fatalf("wal records=%d want 1 even for invalid key", len(records))
	}
	if records[0].StatusCode != rec.Code {
		t.Fatalf("wal status=%d want response status %d", records[0].StatusCode, rec.Code)
	}
	if records[0].ResultClass != "permission_error" {
		t.Fatalf("wal result_class=%q want permission_error", records[0].ResultClass)
	}
	if records[0].ImmediateOutcome != "permission_error" {
		t.Fatalf("wal immediate_outcome=%q want permission_error", records[0].ImmediateOutcome)
	}
}

func TestLiveGeminiProxyMiniSoakConcurrentWAL(t *testing.T) {
	key := liveGeminiKey(t)
	if os.Getenv("WITNESS_LIVE_GEMINI_SOAK") != "1" {
		t.Skip("set WITNESS_LIVE_GEMINI_SOAK=1 to run the live Gemini mini-soak")
	}
	handler, walDir := newTestHandler(t)
	handler.NonStreamTimeout = 30 * time.Second

	const requests = 6
	var wg sync.WaitGroup
	statuses := make([]int, requests)
	bodies := make([]string, requests)
	for i := 0; i < requests; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := `{
				"contents":[{"role":"user","parts":[{"text":"Reply with exactly: soak-ok"}]}],
				"generationConfig":{"temperature":0,"maxOutputTokens":8}
			}`
			req := httptest.NewRequest("POST", "/gemini/v1beta/models/"+liveGeminiModel()+":generateContent", strings.NewReader(body))
			req.Header.Set("x-goog-api-key", key)
			req.Header.Set("X-Project", "live-gemini-soak")
			req.Header.Set("X-Session-ID", "live-gemini-soak-session")
			req.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			statuses[i] = rec.Code
			bodies[i] = rec.Body.String()
		}()
	}
	wg.Wait()

	for i, status := range statuses {
		if status == http.StatusTooManyRequests && strings.Contains(bodies[i], "RESOURCE_EXHAUSTED") {
			t.Skipf("Gemini quota/rate limit reached during mini-soak after request %d: %s", i, safeBody(bodies[i]))
		}
		if status != http.StatusOK {
			t.Fatalf("request %d status=%d body=%s", i, status, safeBody(bodies[i]))
		}
	}

	handler.WAL.Close()
	records := readWALRecords(t, walDir)
	if len(records) != requests {
		t.Fatalf("wal records=%d want %d", len(records), requests)
	}
	if brokenAt := wal.VerifyChain(records); brokenAt != -1 {
		t.Fatalf("wal chain broken at index %d", brokenAt)
	}
	for i, record := range records {
		if record.InputTokens <= 0 || record.TotalTokens <= 0 {
			t.Fatalf("record %d missing tokens: input=%d output=%d total=%d", i, record.InputTokens, record.OutputTokens, record.TotalTokens)
		}
		if record.Cost <= 0 {
			t.Fatalf("record %d cost=%.8f want >0 for model %q", i, record.Cost, record.Model)
		}
	}
}

func liveGeminiKey(t *testing.T) string {
	t.Helper()
	if os.Getenv("WITNESS_LIVE_GEMINI") != "1" {
		t.Skip("set WITNESS_LIVE_GEMINI=1 to run live Gemini tests")
	}
	loadDotEnvForLiveTest(t)
	key := firstNonEmptyLive(os.Getenv("GOOGLE_API_KEY"), os.Getenv("GEMINI_API_KEY"))
	if key == "" {
		t.Fatal("GOOGLE_API_KEY or GEMINI_API_KEY is required for live Gemini tests")
	}
	target, err := url.Parse("https://generativelanguage.googleapis.com")
	if err != nil {
		t.Fatalf("parse gemini target: %v", err)
	}
	origTarget := providers.Registry["/gemini"].Target
	providers.Registry["/gemini"].Target = target
	t.Cleanup(func() { providers.Registry["/gemini"].Target = origTarget })
	return key
}

func liveGeminiModel() string {
	if model := os.Getenv("WITNESS_LIVE_GEMINI_MODEL"); model != "" {
		return model
	}
	return defaultLiveGeminiModel
}

func loadDotEnvForLiveTest(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile("../../.env")
	if err != nil {
		return
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		name := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		if os.Getenv(name) == "" && value != "" {
			t.Setenv(name, value)
		}
	}
}

func firstNonEmptyLive(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func safeBody(body string) string {
	body = strings.ReplaceAll(body, "\n", " ")
	body = strings.ReplaceAll(body, "\r", " ")
	if len(body) > 1000 {
		return body[:1000] + "...<truncated>"
	}
	return body
}

func skipIfGeminiQuota(t *testing.T, status int, body string) {
	t.Helper()
	if status == http.StatusTooManyRequests && strings.Contains(body, "RESOURCE_EXHAUSTED") {
		t.Skipf("Gemini quota/rate limit reached for live test: %s", safeBody(body))
	}
}
