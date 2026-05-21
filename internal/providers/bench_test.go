package providers

import "testing"

var benchOpenAIBody = []byte(`{
	"id": "chatcmpl-bench",
	"object": "chat.completion",
	"created": 1700000000,
	"model": "gpt-4o-mini-2024-07-18",
	"choices": [{"index":0,"message":{"role":"assistant","content":"Hello! How can I help?"},"finish_reason":"stop"}],
	"usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}
}`)

var benchAnthropicBody = []byte(`{
	"id": "msg_bench",
	"type": "message",
	"model": "claude-3-5-sonnet-20241022",
	"content": [{"type":"text","text":"Hello!"}],
	"usage": {"input_tokens": 100, "output_tokens": 50}
}`)

var benchStreamEvents = []SSEEvent{
	{Data: `{"id":"c","model":"gpt-4o-mini","choices":[{"delta":{"role":"assistant"}}]}`},
	{Data: `{"id":"c","model":"gpt-4o-mini","choices":[{"delta":{"content":"Hello"}}]}`},
	{Data: `{"id":"c","model":"gpt-4o-mini","choices":[{"delta":{"content":"!"}}]}`},
	{Data: `{"id":"c","model":"gpt-4o-mini","choices":[{"delta":{},"finish_reason":"stop"}]}`},
	{Data: `{"id":"c","model":"gpt-4o-mini","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`},
	{Data: `[DONE]`},
}

var benchAnthropicStreamEvents = []SSEEvent{
	{Event: "message_start", Data: `{"type":"message_start","message":{"model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":20}}}`},
	{Event: "content_block_delta", Data: `{"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi"}}`},
	{Event: "message_delta", Data: `{"type":"message_delta","usage":{"output_tokens":5}}`},
}

func BenchmarkExtractOpenAIUsage(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		extractOpenAIUsage(benchOpenAIBody)
	}
}

func BenchmarkExtractAnthropicUsage(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		extractAnthropicUsage(benchAnthropicBody)
	}
}

func BenchmarkExtractOpenAIStreamUsage(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		extractOpenAIStreamUsage(benchStreamEvents)
	}
}

func BenchmarkExtractAnthropicStreamUsage(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		extractAnthropicStreamUsage(benchAnthropicStreamEvents)
	}
}

func BenchmarkComputeCost(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		ComputeCost("gpt-4o-mini", 1000, 500)
	}
}

func BenchmarkIsOpenAIStreamRequest(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	b.ReportAllocs()
	for b.Loop() {
		isOpenAIStreamRequest(body)
	}
}

func BenchmarkPrepareOpenAIStreamBody(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hello world"}]}`)
	b.ReportAllocs()
	for b.Loop() {
		prepareOpenAIStreamBody(body)
	}
}

func BenchmarkLookup(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		Lookup("/openai/v1/chat/completions")
	}
}
