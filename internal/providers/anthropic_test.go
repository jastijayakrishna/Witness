package providers

import "testing"

// Real Anthropic messages API response shape
var anthropicNonStreamResponse = `{
	"id": "msg_01XYZ",
	"type": "message",
	"role": "assistant",
	"model": "claude-3-5-sonnet-20241022",
	"content": [{"type": "text", "text": "Hello!"}],
	"stop_reason": "end_turn",
	"stop_sequence": null,
	"usage": {
		"input_tokens": 25,
		"output_tokens": 8
	}
}`

func TestExtractAnthropicUsage_Normal(t *testing.T) {
	usage, err := extractAnthropicUsage([]byte(anthropicNonStreamResponse))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.Model != "claude-3-5-sonnet-20241022" {
		t.Errorf("model = %q, want %q", usage.Model, "claude-3-5-sonnet-20241022")
	}
	if usage.InputTokens != 25 {
		t.Errorf("input_tokens = %d, want 25", usage.InputTokens)
	}
	if usage.OutputTokens != 8 {
		t.Errorf("output_tokens = %d, want 8", usage.OutputTokens)
	}
	if usage.TotalTokens != 33 {
		t.Errorf("total_tokens = %d, want 33 (25+8)", usage.TotalTokens)
	}
}

func TestExtractAnthropicUsage_NilUsage(t *testing.T) {
	body := `{"id":"msg_err","model":"claude-3-haiku-20240307","type":"error"}`
	usage, err := extractAnthropicUsage([]byte(body))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.Model != "claude-3-haiku-20240307" {
		t.Errorf("model = %q, want %q", usage.Model, "claude-3-haiku-20240307")
	}
	if usage.TotalTokens != 0 {
		t.Errorf("expected zero tokens, got %d", usage.TotalTokens)
	}
}

func TestExtractAnthropicUsage_InvalidJSON(t *testing.T) {
	_, err := extractAnthropicUsage([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// Real Anthropic streaming event sequence
func TestExtractAnthropicStreamUsage_FullConversation(t *testing.T) {
	events := []SSEEvent{
		{
			Event: "message_start",
			Data:  `{"type":"message_start","message":{"id":"msg_01","type":"message","role":"assistant","model":"claude-3-5-sonnet-20241022","content":[],"stop_reason":null,"usage":{"input_tokens":15,"output_tokens":0}}}`,
		},
		{
			Event: "content_block_start",
			Data:  `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		},
		{
			Event: "content_block_delta",
			Data:  `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}`,
		},
		{
			Event: "content_block_delta",
			Data:  `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"!"}}`,
		},
		{
			Event: "content_block_stop",
			Data:  `{"type":"content_block_stop","index":0}`,
		},
		{
			Event: "message_delta",
			Data:  `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":3}}`,
		},
		{
			Event: "message_stop",
			Data:  `{"type":"message_stop"}`,
		},
	}

	usage, err := extractAnthropicStreamUsage(events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.Model != "claude-3-5-sonnet-20241022" {
		t.Errorf("model = %q, want %q", usage.Model, "claude-3-5-sonnet-20241022")
	}
	if usage.InputTokens != 15 {
		t.Errorf("input_tokens = %d, want 15", usage.InputTokens)
	}
	if usage.OutputTokens != 3 {
		t.Errorf("output_tokens = %d, want 3", usage.OutputTokens)
	}
	if usage.TotalTokens != 18 {
		t.Errorf("total_tokens = %d, want 18", usage.TotalTokens)
	}
}

func TestExtractAnthropicStreamUsage_MultipleDeltas(t *testing.T) {
	// The last message_delta wins for output tokens
	events := []SSEEvent{
		{
			Event: "message_start",
			Data:  `{"type":"message_start","message":{"model":"claude-3-opus-20240229","usage":{"input_tokens":100,"output_tokens":0}}}`,
		},
		{
			Event: "message_delta",
			Data:  `{"type":"message_delta","usage":{"output_tokens":50}}`,
		},
		{
			Event: "message_delta",
			Data:  `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":200}}`,
		},
	}

	usage, err := extractAnthropicStreamUsage(events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.InputTokens != 100 {
		t.Errorf("input_tokens = %d, want 100", usage.InputTokens)
	}
	// Last delta should win
	if usage.OutputTokens != 200 {
		t.Errorf("output_tokens = %d, want 200 (last delta)", usage.OutputTokens)
	}
	if usage.TotalTokens != 300 {
		t.Errorf("total_tokens = %d, want 300", usage.TotalTokens)
	}
}

func TestExtractAnthropicStreamUsage_EmptyEvents(t *testing.T) {
	usage, err := extractAnthropicStreamUsage(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.TotalTokens != 0 {
		t.Errorf("expected zero tokens for empty events, got %d", usage.TotalTokens)
	}
}

func TestExtractAnthropicStreamUsage_MalformedEvents(t *testing.T) {
	// Should not panic or error — just return zero usage
	events := []SSEEvent{
		{Event: "message_start", Data: `{broken json`},
		{Event: "message_delta", Data: `also broken`},
		{Event: "content_block_delta", Data: ``},
	}

	usage, err := extractAnthropicStreamUsage(events)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if usage.TotalTokens != 0 {
		t.Errorf("expected zero tokens for malformed events, got %d", usage.TotalTokens)
	}
}

func TestIsAnthropicStreamRequest(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"stream true", `{"model":"claude-3-5-sonnet-20241022","stream":true}`, true},
		{"stream false", `{"model":"claude-3-5-sonnet-20241022","stream":false}`, false},
		{"no stream field", `{"model":"claude-3-5-sonnet-20241022"}`, false},
		{"invalid json", `{nope`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAnthropicStreamRequest([]byte(tt.body))
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}
