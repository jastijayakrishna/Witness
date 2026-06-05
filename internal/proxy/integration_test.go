package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/providers"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

// TestBatchJobNeverBlocked_Integration verifies that a 200-turn changing-args
// flat-cost batch job with action:block configured returns ZERO 429s.
// This is the proof test: legitimate work is never blocked.
func TestBatchJobNeverBlocked_Integration(t *testing.T) {
	// Setup: real Redis, real proxy handler, action:block
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer rdb.Close()
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skip("Redis not available:", err)
	}

	// Clean Redis state
	rdb.FlushDB(context.Background())

	// Create fake upstream that returns flat cost every time
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a fake OpenAI completion with fixed cost
		resp := map[string]any{
			"id":      "test",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4",
			"choices": []any{
				map[string]any{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "done",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     100,
				"completion_tokens": 10,
				"total_tokens":      110,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	// Swap OpenAI provider target to fake upstream
	provider := providers.Lookup("/openai/v1/chat/completions")
	if provider == nil {
		t.Fatal("OpenAI provider not found")
	}
	origTarget := provider.Target
	defer func() { provider.Target = origTarget }()
	fakeURL, _ := url.Parse(upstream.URL)
	provider.Target = fakeURL

	// Create handler with BLOCK action
	walWriter, _ := wal.NewWriter(t.TempDir(), "batch")
	loopStore := loop.NewStateStore(rdb)
	overrideStore := loop.NewOverrideStore(rdb)
	loopCfg := loop.Config{
		Action:                 "block",
		MaxRepeated:            3,
		VelocityAccelRatio:     1.5,
		VelocityWindowMs:       300_000,
		WarnConfidence:         0.40,
		BlockConfidence:        0.70,
		RequireSessionForBlock: true,
	}
	h := NewHandler(walWriter, loopStore, loopCfg)
	h.OverrideStore = overrideStore

	// Simulate 200-turn batch job: same tool, changing args (ticket 1, 2, 3...)
	project := "test-project"
	sessionID := "batch-session-123"

	var blockedCount int
	for i := 0; i < 200; i++ {
		reqBody := map[string]any{
			"model": "gpt-4",
			"messages": []any{
				map[string]any{
					"role":    "user",
					"content": fmt.Sprintf("Process ticket %d", i), // changing content
				},
			},
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", bytes.NewReader(bodyBytes))
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Project", project)
		req.Header.Set("X-Session-ID", sessionID)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code == 429 {
			blockedCount++
		}
	}

	// Assert: zero 429s
	if blockedCount > 0 {
		t.Errorf("Batch job was blocked %d times — should be 0", blockedCount)
	}
}

// TestRunawayWithSessionBlocks_Integration verifies that a runaway with session
// returns a 429 with a valid override token that works exactly once.
func TestRunawayWithSessionBlocks_Integration(t *testing.T) {
	// Setup
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer rdb.Close()
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skip("Redis not available:", err)
	}

	rdb.FlushDB(context.Background())

	// Create fake upstream with ACCELERATING cost
	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Geometric token growth: 100 → 200 → 400 → 800 (simulates context compounding)
		promptTokens := 100 << uint(callCount-1)
		if promptTokens > 10000 {
			promptTokens = 10000
		}
		resp := map[string]any{
			"id":      "test",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4",
			"choices": []any{
				map[string]any{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "error", // shrinking output
						"tool_calls": []any{
							map[string]any{
								"id":   "call_1",
								"type": "function",
								"function": map[string]any{
									"name":      "retry",
									"arguments": `{"reason":"failed"}`, // identical args
								},
							},
						},
					},
					"finish_reason": "tool_calls",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     promptTokens,
				"completion_tokens": 5, // shrinking
				"total_tokens":      promptTokens + 5,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	provider := providers.Lookup("/openai/v1/chat/completions")
	if provider == nil {
		t.Fatal("OpenAI provider not found")
	}
	origTarget := provider.Target
	defer func() { provider.Target = origTarget }()
	fakeURL, _ := url.Parse(upstream.URL)
	provider.Target = fakeURL

	walWriter, _ := wal.NewWriter(t.TempDir(), "batch")
	loopStore := loop.NewStateStore(rdb)
	overrideStore := loop.NewOverrideStore(rdb)
	loopCfg := loop.Config{
		Action:                 "block",
		MaxRepeated:            3,
		VelocityAccelRatio:     1.5,
		VelocityWindowMs:       300_000,
		WarnConfidence:         0.40,
		BlockConfidence:        0.70,
		RequireSessionForBlock: true,
	}
	h := NewHandler(walWriter, loopStore, loopCfg)
	h.OverrideStore = overrideStore

	project := "test-project"
	sessionID := "runaway-session-456"

	var overrideToken string
	var firstBlockTurn int

	// Run until we get a 429
	for i := 0; i < 50; i++ {
		reqBody := map[string]any{
			"model": "gpt-4",
			"messages": []any{
				map[string]any{
					"role":    "user",
					"content": "retry the failed operation", // identical prompt
				},
			},
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", bytes.NewReader(bodyBytes))
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Project", project)
		req.Header.Set("X-Session-ID", sessionID)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code == 429 {
			// Extract override token from error body
			var errBody map[string]any
			json.NewDecoder(rec.Body).Decode(&errBody)
			if e, ok := errBody["error"].(map[string]any); ok {
				if token, ok := e["override_token"].(string); ok {
					overrideToken = token
					firstBlockTurn = i + 1
					break
				}
			}
		}
	}

	// Assert: we got a block with an override token
	if overrideToken == "" {
		t.Fatal("Expected a 429 with override token, but never got one")
	}

	t.Logf("Runaway blocked at turn %d with override token: %s", firstBlockTurn, overrideToken)

	// Test: override token works exactly once
	reqBody := map[string]any{
		"model": "gpt-4",
		"messages": []any{
			map[string]any{"role": "user", "content": "retry with override"},
		},
	}
	bodyBytes, _ := json.Marshal(reqBody)

	// First use: should succeed
	req1 := httptest.NewRequest("POST", "/openai/v1/chat/completions", bytes.NewReader(bodyBytes))
	req1.Header.Set("Authorization", "Bearer test-key")
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Project", project)
	req1.Header.Set("X-Session-ID", sessionID)
	req1.Header.Set("X-Witness-Override", overrideToken)

	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)

	if rec1.Code != 200 {
		t.Errorf("Override token first use: expected 200, got %d", rec1.Code)
	}

	// Second use: should fail (token consumed)
	req2 := httptest.NewRequest("POST", "/openai/v1/chat/completions", bytes.NewReader(bodyBytes))
	req2.Header.Set("Authorization", "Bearer test-key")
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Project", project)
	req2.Header.Set("X-Session-ID", sessionID)
	req2.Header.Set("X-Witness-Override", overrideToken)

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)

	// Should get blocked again (override consumed + still looping)
	if rec2.Code != 429 {
		t.Errorf("Override token second use: expected 429 (consumed), got %d", rec2.Code)
	}
}

// TestFlatCostRunawayBlocks_Integration verifies that a flat-cost runaway
// (identical calls, no cost acceleration) is blocked by the pre-request gate
// via the sustained_repetition signal. This is the proof that the empty-obs
// pre-request check correctly evaluates loaded state for flat-cost runaways.
//
// Key invariant: when the pre-request gate blocks, the upstream is NOT called
// (no wasted money). We verify this by counting upstream calls.
func TestFlatCostRunawayBlocks_Integration(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer rdb.Close()
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skip("Redis not available:", err)
	}

	rdb.FlushDB(context.Background())

	// Fake upstream: flat cost, identical tool calls every time.
	// 100 input * $30/M = $0.003, 10 output * $60/M = $0.0006 → $0.0036/call
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		resp := map[string]any{
			"id":      "test",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4",
			"choices": []any{
				map[string]any{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "error",
						"tool_calls": []any{
							map[string]any{
								"id":   "call_1",
								"type": "function",
								"function": map[string]any{
									"name":      "search",
									"arguments": `{"query":"fix"}`, // identical every time
								},
							},
						},
					},
					"finish_reason": "tool_calls",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     100, // flat — no acceleration
				"completion_tokens": 10,
				"total_tokens":      110,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	provider := providers.Lookup("/openai/v1/chat/completions")
	if provider == nil {
		t.Fatal("OpenAI provider not found")
	}
	origTarget := provider.Target
	defer func() { provider.Target = origTarget }()
	fakeURL, _ := url.Parse(upstream.URL)
	provider.Target = fakeURL

	walWriter, _ := wal.NewWriter(t.TempDir(), "batch")
	loopStore := loop.NewStateStore(rdb)
	overrideStore := loop.NewOverrideStore(rdb)
	// Short velocity window so minSpan = 100ms (testable without long sleeps).
	loopCfg := loop.Config{
		Action:                 "block",
		MaxRepeated:            3,
		VelocityAccelRatio:     1.5,
		VelocityWindowMs:       1_000, // 1s → minSpan = 100ms
		WarnConfidence:         0.40,
		BlockConfidence:        0.70,
		RequireSessionForBlock: true,
	}
	h := NewHandler(walWriter, loopStore, loopCfg)
	h.OverrideStore = overrideStore

	project := "flat-runaway-project"
	sessionID := "flat-runaway-session"

	var firstBlockTurn int
	var errorType string
	totalRequests := 20

	for i := 0; i < totalRequests; i++ {
		reqBody := map[string]any{
			"model": "gpt-4",
			"messages": []any{
				map[string]any{
					"role":    "user",
					"content": "retry the failed search", // identical every time
				},
			},
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", bytes.NewReader(bodyBytes))
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Project", project)
		req.Header.Set("X-Session-ID", sessionID)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code == 429 {
			var errBody map[string]any
			json.NewDecoder(rec.Body).Decode(&errBody)
			if e, ok := errBody["error"].(map[string]any); ok {
				if typ, ok := e["type"].(string); ok {
					errorType = typ
				}
			}
			firstBlockTurn = i + 1
			break
		}

		// Small sleep so cost events span > minSpan (100ms) across 6+ calls
		time.Sleep(25 * time.Millisecond)
	}

	// Assert: we got a block
	if firstBlockTurn == 0 {
		t.Fatalf("Flat-cost runaway was never blocked in %d turns", totalRequests)
	}

	// Assert: block came from loop detector (not budget)
	if errorType != "loop_detected" {
		t.Errorf("Expected error type loop_detected, got %q", errorType)
	}

	// Assert: pre-request gate prevented the upstream call
	// upstreamCalls should be firstBlockTurn-1 (the blocked request never reached upstream)
	if upstreamCalls != firstBlockTurn-1 {
		t.Errorf("Upstream called %d times for %d turns — expected %d (gate should prevent upstream call on block)",
			upstreamCalls, firstBlockTurn, firstBlockTurn-1)
	}

	// Assert: block happened within a reasonable range
	// deepThreshold = 2*MaxRepeated = 6, so earliest block is turn 7
	if firstBlockTurn < 7 {
		t.Errorf("Block at turn %d is too early (need 6+ history turns)", firstBlockTurn)
	}

	t.Logf("Flat-cost runaway blocked at turn %d (upstream calls: %d)", firstBlockTurn, upstreamCalls)
}

// TestBudgetEnforcement_Integration verifies hard budget cap blocks requests.
func TestBudgetEnforcement_Integration(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	defer rdb.Close()
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Skip("Redis not available:", err)
	}

	rdb.FlushDB(context.Background())

	// Fake upstream with $0.36/call at gpt-4 pricing:
	// 10000 input * $30/M = $0.30, 1000 output * $60/M = $0.06 → $0.36 total
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"id":      "test",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4",
			"choices": []any{
				map[string]any{
					"index":         0,
					"message":       map[string]any{"role": "assistant", "content": "ok"},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     10000,
				"completion_tokens": 1000,
				"total_tokens":      11000,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer upstream.Close()

	provider := providers.Lookup("/openai/v1/chat/completions")
	origTarget := provider.Target
	defer func() { provider.Target = origTarget }()
	fakeURL, _ := url.Parse(upstream.URL)
	provider.Target = fakeURL

	walWriter, _ := wal.NewWriter(t.TempDir(), "batch")
	loopStore := loop.NewStateStore(rdb)
	// Hard cap $0.80 allows 2 requests ($0.72) and blocks the 3rd ($1.08).
	// Reserve $0.40 per request for atomic budget gating.
	budgetEnforcer := loop.NewBudgetEnforcer(rdb, 0, 0.80, 0.40)
	loopCfg := loop.DefaultConfig()

	h := NewHandler(walWriter, loopStore, loopCfg)
	h.BudgetEnforcer = budgetEnforcer

	project := "budget-test-project"

	// Make 3 requests: first 2 succeed, 3rd blocked by budget
	for i := 0; i < 3; i++ {
		reqBody := map[string]any{
			"model":    "gpt-4",
			"messages": []any{map[string]any{"role": "user", "content": fmt.Sprintf("request %d", i)}},
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", bytes.NewReader(bodyBytes))
		req.Header.Set("Authorization", "Bearer test-key")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Project", project)

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if i < 2 {
			// First 2 requests: should succeed
			if rec.Code != 200 {
				t.Errorf("Request %d: expected 200, got %d", i, rec.Code)
			}
		} else {
			// 3rd request: should be blocked by budget
			if rec.Code != 429 {
				t.Errorf("Request %d: expected 429 (budget exceeded), got %d", i, rec.Code)
			}
			// Check error type
			var errBody map[string]any
			json.NewDecoder(rec.Body).Decode(&errBody)
			if e, ok := errBody["error"].(map[string]any); ok {
				if typ, ok := e["type"].(string); ok && typ != "budget_exceeded" {
					t.Errorf("Expected error type budget_exceeded, got %s", typ)
				}
			}
		}
	}
}

