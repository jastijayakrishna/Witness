package providers

import (
	"testing"
)

func TestExtractGeminiUsage_Normal(t *testing.T) {
	body := `{
		"candidates": [{"content": {"parts": [{"text": "Hello!"}]}}],
		"usageMetadata": {
			"promptTokenCount": 10,
			"candidatesTokenCount": 5,
			"totalTokenCount": 15
		},
		"modelVersion": "gemini-2.0-flash"
	}`
	usage, err := extractGeminiUsage([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.Model != "gemini-2.0-flash" {
		t.Errorf("model = %q, want %q", usage.Model, "gemini-2.0-flash")
	}
	if usage.InputTokens != 10 {
		t.Errorf("input_tokens = %d, want 10", usage.InputTokens)
	}
	if usage.OutputTokens != 5 {
		t.Errorf("output_tokens = %d, want 5", usage.OutputTokens)
	}
	if usage.TotalTokens != 15 {
		t.Errorf("total_tokens = %d, want 15", usage.TotalTokens)
	}
}

func TestExtractGeminiUsage_NilUsageMetadata(t *testing.T) {
	body := `{
		"candidates": [{"content": {"parts": [{"text": "Hello!"}]}}],
		"modelVersion": "gemini-pro"
	}`
	usage, err := extractGeminiUsage([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.Model != "gemini-pro" {
		t.Errorf("model = %q, want %q", usage.Model, "gemini-pro")
	}
	if usage.InputTokens != 0 || usage.OutputTokens != 0 {
		t.Errorf("expected zero tokens, got in=%d out=%d", usage.InputTokens, usage.OutputTokens)
	}
}

func TestExtractGeminiStreamUsage(t *testing.T) {
	events := []SSEEvent{
		{Data: `{"candidates":[{"content":{"parts":[{"text":"Hi"}]}}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":1,"totalTokenCount":11},"modelVersion":"gemini-pro"}`},
		{Data: `{"candidates":[{"content":{"parts":[{"text":" there"}]}}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":3,"totalTokenCount":13},"modelVersion":"gemini-pro"}`},
	}
	usage, err := extractGeminiStreamUsage(events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.Model != "gemini-pro" {
		t.Errorf("model = %q, want %q", usage.Model, "gemini-pro")
	}
	// Last chunk has cumulative totals
	if usage.InputTokens != 10 {
		t.Errorf("input_tokens = %d, want 10", usage.InputTokens)
	}
	if usage.OutputTokens != 3 {
		t.Errorf("output_tokens = %d, want 3", usage.OutputTokens)
	}
}

func TestIsGeminiStreamPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"streaming endpoint", "/gemini/v1beta/models/gemini-pro:streamGenerateContent", true},
		{"non-streaming endpoint", "/gemini/v1beta/models/gemini-pro:generateContent", false},
		{"streaming with query params", "/gemini/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse", true},
		{"empty path", "", false},
		{"other provider", "/openai/v1/chat/completions", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGeminiStreamPath(tt.path)
			if got != tt.want {
				t.Errorf("isGeminiStreamPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsGeminiStreamRequest_AlwaysFalse(t *testing.T) {
	// Gemini streaming is path-based, not body-based. This should always return false.
	bodies := []string{
		`{"contents":[{"parts":[{"text":"hi"}]}]}`,
		`{}`,
		``,
	}
	for _, body := range bodies {
		if isGeminiStreamRequest([]byte(body)) {
			t.Errorf("isGeminiStreamRequest(%q) = true, want false (streaming is path-based)", body)
		}
	}
}

func TestExtractGeminiToolCalls(t *testing.T) {
	body := `{
		"candidates": [{
			"content": {
				"parts": [
					{"functionCall": {"name": "get_weather", "args": {"city": "London"}}}
				]
			}
		}]
	}`
	calls := extractGeminiToolCalls([]byte(body))
	if len(calls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(calls))
	}
	if calls[0].Name != "get_weather" {
		t.Errorf("name = %q, want get_weather", calls[0].Name)
	}
}
