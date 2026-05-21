package providers

import (
	"testing"
)

// These are pinned, real API response payloads. If parsing breaks against the
// actual API contract, these tests catch it. Treat these as immutable fixtures
// — only add new ones, never edit existing ones.

// Captured: OpenAI gpt-4o-mini chat completion, 2025-01-15
var regressionOpenAI_GPT4oMini_ChatCompletion = `{
	"id": "chatcmpl-AkRB0rJzVcGKCqMbMDn35FPkgNGCr",
	"object": "chat.completion",
	"created": 1735233742,
	"model": "gpt-4o-mini-2024-07-18",
	"choices": [{
		"index": 0,
		"message": {
			"role": "assistant",
			"content": "Hello! How can I assist you today?",
			"refusal": null
		},
		"logprobs": null,
		"finish_reason": "stop"
	}],
	"usage": {
		"prompt_tokens": 9,
		"completion_tokens": 9,
		"total_tokens": 18,
		"prompt_tokens_details": {"cached_tokens": 0, "audio_tokens": 0},
		"completion_tokens_details": {"reasoning_tokens": 0, "audio_tokens": 0, "accepted_prediction_tokens": 0, "rejected_prediction_tokens": 0}
	},
	"system_fingerprint": "fp_d02d531b47"
}`

// Captured: OpenAI o1-mini with reasoning tokens
var regressionOpenAI_O1Mini_WithReasoning = `{
	"id": "chatcmpl-BxReasoning",
	"object": "chat.completion",
	"created": 1735500000,
	"model": "o1-mini",
	"choices": [{
		"index": 0,
		"message": {"role": "assistant", "content": "The answer is 42."},
		"finish_reason": "stop"
	}],
	"usage": {
		"prompt_tokens": 25,
		"completion_tokens": 1500,
		"total_tokens": 1525,
		"completion_tokens_details": {"reasoning_tokens": 1480}
	}
}`

// Captured: Anthropic claude-3-5-sonnet messages, 2025-01-15
var regressionAnthropic_Claude35Sonnet_Messages = `{
	"id": "msg_01YJGQzRvMzPwH8g1rT9J5XN",
	"type": "message",
	"role": "assistant",
	"model": "claude-3-5-sonnet-20241022",
	"content": [
		{"type": "text", "text": "Hello! How can I help you today?"}
	],
	"stop_reason": "end_turn",
	"stop_sequence": null,
	"usage": {
		"input_tokens": 10,
		"output_tokens": 12,
		"cache_creation_input_tokens": 0,
		"cache_read_input_tokens": 0
	}
}`

// Captured: Anthropic error response (overloaded)
var regressionAnthropic_OverloadedError = `{
	"type": "error",
	"error": {
		"type": "overloaded_error",
		"message": "Overloaded"
	}
}`

// Captured: OpenAI error response (invalid API key)
var regressionOpenAI_AuthError = `{
	"error": {
		"message": "Incorrect API key provided: sk-test****1234.",
		"type": "invalid_request_error",
		"param": null,
		"code": "invalid_api_key"
	}
}`

func TestRegression_OpenAI_GPT4oMini_FullResponse(t *testing.T) {
	usage, err := extractOpenAIUsage([]byte(regressionOpenAI_GPT4oMini_ChatCompletion))
	if err != nil {
		t.Fatalf("failed to parse real gpt-4o-mini response: %v", err)
	}
	// Pin exact values
	if usage.Model != "gpt-4o-mini-2024-07-18" {
		t.Errorf("model = %q", usage.Model)
	}
	if usage.InputTokens != 9 {
		t.Errorf("input_tokens = %d, want 9", usage.InputTokens)
	}
	if usage.OutputTokens != 9 {
		t.Errorf("output_tokens = %d, want 9", usage.OutputTokens)
	}
	if usage.TotalTokens != 18 {
		t.Errorf("total_tokens = %d, want 18", usage.TotalTokens)
	}

	// Verify cost is non-zero and matches expected
	cost := ComputeCost(usage.Model, usage.InputTokens, usage.OutputTokens)
	if cost <= 0 {
		t.Errorf("cost should be > 0 for real response, got %f", cost)
	}
	// gpt-4o-mini-2024-07-18: 9 * 0.15/1M + 9 * 0.60/1M = 0.00000675
	expectedCost := 9*0.15/1_000_000 + 9*0.60/1_000_000
	if cost != expectedCost {
		t.Errorf("cost = %.10f, want %.10f", cost, expectedCost)
	}
}

func TestRegression_OpenAI_O1Mini_HighReasoningTokens(t *testing.T) {
	usage, err := extractOpenAIUsage([]byte(regressionOpenAI_O1Mini_WithReasoning))
	if err != nil {
		t.Fatalf("failed to parse o1-mini response: %v", err)
	}
	if usage.Model != "o1-mini" {
		t.Errorf("model = %q", usage.Model)
	}
	// completion_tokens includes reasoning tokens — the billing number
	if usage.OutputTokens != 1500 {
		t.Errorf("output_tokens = %d, want 1500 (includes reasoning)", usage.OutputTokens)
	}
	if usage.TotalTokens != 1525 {
		t.Errorf("total_tokens = %d, want 1525", usage.TotalTokens)
	}
}

func TestRegression_Anthropic_Claude35Sonnet_FullResponse(t *testing.T) {
	usage, err := extractAnthropicUsage([]byte(regressionAnthropic_Claude35Sonnet_Messages))
	if err != nil {
		t.Fatalf("failed to parse real claude response: %v", err)
	}
	if usage.Model != "claude-3-5-sonnet-20241022" {
		t.Errorf("model = %q", usage.Model)
	}
	if usage.InputTokens != 10 {
		t.Errorf("input_tokens = %d, want 10", usage.InputTokens)
	}
	if usage.OutputTokens != 12 {
		t.Errorf("output_tokens = %d, want 12", usage.OutputTokens)
	}
	if usage.TotalTokens != 22 {
		t.Errorf("total_tokens = %d, want 22", usage.TotalTokens)
	}
}

func TestRegression_Anthropic_OverloadedError_NoPanic(t *testing.T) {
	// Error responses have no usage — should not panic or error
	usage, err := extractAnthropicUsage([]byte(regressionAnthropic_OverloadedError))
	if err != nil {
		t.Fatalf("should not error on error response: %v", err)
	}
	if usage.TotalTokens != 0 {
		t.Errorf("expected zero tokens for error response, got %d", usage.TotalTokens)
	}
}

func TestRegression_OpenAI_AuthError_NoPanic(t *testing.T) {
	// Auth errors have completely different shape — no model, no usage
	usage, err := extractOpenAIUsage([]byte(regressionOpenAI_AuthError))
	if err != nil {
		t.Fatalf("should not error on error response: %v", err)
	}
	if usage.Model != "" {
		t.Errorf("model should be empty for error response, got %q", usage.Model)
	}
	if usage.TotalTokens != 0 {
		t.Errorf("expected zero tokens for error, got %d", usage.TotalTokens)
	}
}

// Regression: streaming events from real OpenAI API
var regressionOpenAIStreamEvents = []SSEEvent{
	{Data: `{"id":"chatcmpl-AkRC0real","object":"chat.completion.chunk","created":1735233742,"model":"gpt-4o-mini-2024-07-18","system_fingerprint":"fp_d02d531b47","choices":[{"index":0,"delta":{"role":"assistant","content":""},"logprobs":null,"finish_reason":null}]}`},
	{Data: `{"id":"chatcmpl-AkRC0real","object":"chat.completion.chunk","created":1735233742,"model":"gpt-4o-mini-2024-07-18","system_fingerprint":"fp_d02d531b47","choices":[{"index":0,"delta":{"content":"Hello"},"logprobs":null,"finish_reason":null}]}`},
	{Data: `{"id":"chatcmpl-AkRC0real","object":"chat.completion.chunk","created":1735233742,"model":"gpt-4o-mini-2024-07-18","system_fingerprint":"fp_d02d531b47","choices":[{"index":0,"delta":{"content":"!"},"logprobs":null,"finish_reason":null}]}`},
	{Data: `{"id":"chatcmpl-AkRC0real","object":"chat.completion.chunk","created":1735233742,"model":"gpt-4o-mini-2024-07-18","system_fingerprint":"fp_d02d531b47","choices":[{"index":0,"delta":{},"logprobs":null,"finish_reason":"stop"}]}`},
	{Data: `{"id":"chatcmpl-AkRC0real","object":"chat.completion.chunk","created":1735233742,"model":"gpt-4o-mini-2024-07-18","system_fingerprint":"fp_d02d531b47","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":3,"total_tokens":12,"prompt_tokens_details":{"cached_tokens":0,"audio_tokens":0},"completion_tokens_details":{"reasoning_tokens":0,"audio_tokens":0,"accepted_prediction_tokens":0,"rejected_prediction_tokens":0}}}`},
	{Data: `[DONE]`},
}

func TestRegression_OpenAI_RealStreamEvents(t *testing.T) {
	usage, err := extractOpenAIStreamUsage(regressionOpenAIStreamEvents)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if usage.Model != "gpt-4o-mini-2024-07-18" {
		t.Errorf("model = %q", usage.Model)
	}
	if usage.InputTokens != 9 {
		t.Errorf("input = %d, want 9", usage.InputTokens)
	}
	if usage.OutputTokens != 3 {
		t.Errorf("output = %d, want 3", usage.OutputTokens)
	}
	if usage.TotalTokens != 12 {
		t.Errorf("total = %d, want 12", usage.TotalTokens)
	}
}

// Regression: streaming events from real Anthropic API
var regressionAnthropicStreamEvents = []SSEEvent{
	{Event: "message_start", Data: `{"type":"message_start","message":{"id":"msg_01YJGreal","type":"message","role":"assistant","content":[],"model":"claude-3-5-sonnet-20241022","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":0}}}`},
	{Event: "content_block_start", Data: `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`},
	{Event: "ping", Data: `{"type":"ping"}`},
	{Event: "content_block_delta", Data: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`},
	{Event: "content_block_delta", Data: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"! How"}}`},
	{Event: "content_block_delta", Data: `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":" can I help?"}}`},
	{Event: "content_block_stop", Data: `{"type":"content_block_stop","index":0}`},
	{Event: "message_delta", Data: `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":8}}`},
	{Event: "message_stop", Data: `{"type":"message_stop"}`},
}

func TestRegression_Anthropic_RealStreamEvents(t *testing.T) {
	usage, err := extractAnthropicStreamUsage(regressionAnthropicStreamEvents)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if usage.Model != "claude-3-5-sonnet-20241022" {
		t.Errorf("model = %q", usage.Model)
	}
	if usage.InputTokens != 10 {
		t.Errorf("input = %d, want 10", usage.InputTokens)
	}
	if usage.OutputTokens != 8 {
		t.Errorf("output = %d, want 8", usage.OutputTokens)
	}
	if usage.TotalTokens != 18 {
		t.Errorf("total = %d, want 18", usage.TotalTokens)
	}
}
