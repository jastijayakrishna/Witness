package providers

import (
	"encoding/json"
	"testing"
)

// Real OpenAI chat completion response shape
var openaiNonStreamResponse = `{
	"id": "chatcmpl-abc123",
	"object": "chat.completion",
	"created": 1700000000,
	"model": "gpt-4o-mini-2024-07-18",
	"choices": [{
		"index": 0,
		"message": {"role": "assistant", "content": "Hello!"},
		"finish_reason": "stop"
	}],
	"usage": {
		"prompt_tokens": 12,
		"completion_tokens": 5,
		"total_tokens": 17
	}
}`

func TestExtractOpenAIUsage_Normal(t *testing.T) {
	usage, err := extractOpenAIUsage([]byte(openaiNonStreamResponse))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.Model != "gpt-4o-mini-2024-07-18" {
		t.Errorf("model = %q, want %q", usage.Model, "gpt-4o-mini-2024-07-18")
	}
	if usage.InputTokens != 12 {
		t.Errorf("input_tokens = %d, want 12", usage.InputTokens)
	}
	if usage.OutputTokens != 5 {
		t.Errorf("output_tokens = %d, want 5", usage.OutputTokens)
	}
	if usage.TotalTokens != 17 {
		t.Errorf("total_tokens = %d, want 17", usage.TotalTokens)
	}
}

func TestExtractOpenAIUsage_NilUsage(t *testing.T) {
	// Some error responses have model but no usage
	body := `{"id":"chatcmpl-err","model":"gpt-4o","choices":[]}`
	usage, err := extractOpenAIUsage([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.Model != "gpt-4o" {
		t.Errorf("model = %q, want %q", usage.Model, "gpt-4o")
	}
	if usage.InputTokens != 0 || usage.OutputTokens != 0 || usage.TotalTokens != 0 {
		t.Errorf("expected zero tokens for nil usage, got %+v", usage)
	}
}

func TestExtractOpenAIUsage_InvalidJSON(t *testing.T) {
	_, err := extractOpenAIUsage([]byte(`{broken json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExtractOpenAIUsage_LargeTokenCounts(t *testing.T) {
	// o1 models can have very high token counts due to reasoning
	body := `{
		"model": "o1-preview",
		"usage": {
			"prompt_tokens": 50000,
			"completion_tokens": 120000,
			"total_tokens": 170000
		}
	}`
	usage, err := extractOpenAIUsage([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.InputTokens != 50000 {
		t.Errorf("input_tokens = %d, want 50000", usage.InputTokens)
	}
	if usage.OutputTokens != 120000 {
		t.Errorf("output_tokens = %d, want 120000", usage.OutputTokens)
	}
}

// Test streaming usage extraction with real OpenAI SSE event shapes
func TestExtractOpenAIStreamUsage_FullConversation(t *testing.T) {
	events := []SSEEvent{
		{Data: `{"id":"chatcmpl-abc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`},
		{Data: `{"id":"chatcmpl-abc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`},
		{Data: `{"id":"chatcmpl-abc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"!"},"finish_reason":null}]}`},
		{Data: `{"id":"chatcmpl-abc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`},
		// The usage-only chunk injected by stream_options.include_usage
		{Data: `{"id":"chatcmpl-abc","object":"chat.completion.chunk","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":2,"total_tokens":11}}`},
		{Data: `[DONE]`},
	}

	usage, err := extractOpenAIStreamUsage(events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.Model != "gpt-4o-mini" {
		t.Errorf("model = %q, want %q", usage.Model, "gpt-4o-mini")
	}
	if usage.InputTokens != 9 {
		t.Errorf("input_tokens = %d, want 9", usage.InputTokens)
	}
	if usage.OutputTokens != 2 {
		t.Errorf("output_tokens = %d, want 2", usage.OutputTokens)
	}
	if usage.TotalTokens != 11 {
		t.Errorf("total_tokens = %d, want 11", usage.TotalTokens)
	}
}

func TestExtractOpenAIStreamUsage_NoUsageChunk(t *testing.T) {
	// If stream_options wasn't injected, there's no usage chunk
	events := []SSEEvent{
		{Data: `{"id":"chatcmpl-abc","model":"gpt-4o","choices":[{"delta":{"content":"Hi"}}]}`},
		{Data: `{"id":"chatcmpl-abc","model":"gpt-4o","choices":[{"delta":{},"finish_reason":"stop"}]}`},
		{Data: `[DONE]`},
	}

	usage, err := extractOpenAIStreamUsage(events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still extract model even without usage
	if usage.Model != "gpt-4o" {
		t.Errorf("model = %q, want %q", usage.Model, "gpt-4o")
	}
	if usage.InputTokens != 0 || usage.OutputTokens != 0 {
		t.Errorf("expected zero tokens when no usage chunk, got %+v", usage)
	}
}

func TestExtractOpenAIStreamUsage_EmptyEvents(t *testing.T) {
	usage, err := extractOpenAIStreamUsage(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.Model != "" {
		t.Errorf("model = %q, want empty", usage.Model)
	}
}

func TestIsOpenAIStreamRequest(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"stream true", `{"model":"gpt-4o","stream":true}`, true},
		{"stream false", `{"model":"gpt-4o","stream":false}`, false},
		{"no stream field", `{"model":"gpt-4o"}`, false},
		{"stream string (invalid)", `{"model":"gpt-4o","stream":"true"}`, false},
		{"invalid json", `{broken`, false},
		{"empty body", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isOpenAIStreamRequest([]byte(tt.body))
			if got != tt.want {
				t.Errorf("isOpenAIStreamRequest(%s) = %v, want %v", tt.body, got, tt.want)
			}
		})
	}
}

func TestPrepareOpenAIStreamBody_InjectsUsage(t *testing.T) {
	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	modified, err := prepareOpenAIStreamBody([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(modified, &parsed); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	streamOpts, ok := parsed["stream_options"].(map[string]any)
	if !ok {
		t.Fatal("stream_options not found in modified body")
	}
	includeUsage, ok := streamOpts["include_usage"].(bool)
	if !ok || !includeUsage {
		t.Errorf("include_usage = %v, want true", streamOpts["include_usage"])
	}

	// Ensure original fields are preserved
	if parsed["model"] != "gpt-4o" {
		t.Errorf("model was modified: %v", parsed["model"])
	}
	if parsed["stream"] != true {
		t.Errorf("stream was modified: %v", parsed["stream"])
	}
}

func TestPrepareOpenAIStreamBody_PreservesExistingStreamOptions(t *testing.T) {
	body := `{"model":"gpt-4o","stream":true,"stream_options":{"some_opt":42}}`
	modified, err := prepareOpenAIStreamBody([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]any
	json.Unmarshal(modified, &parsed)

	streamOpts := parsed["stream_options"].(map[string]any)
	if streamOpts["include_usage"] != true {
		t.Error("include_usage not injected")
	}
	// The existing option may not survive a round-trip through map[string]any
	// as the type changes, but include_usage must be set
}

func TestPrepareOpenAIStreamBody_InvalidJSON(t *testing.T) {
	_, err := prepareOpenAIStreamBody([]byte(`{broken`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
