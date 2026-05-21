package providers

import "testing"

// Fuzz tests for all JSON parsers. These ensure no panics on arbitrary input.
// Run with: go test -fuzz=FuzzExtractOpenAIUsage -fuzztime=30s ./internal/providers/

func FuzzExtractOpenAIUsage(f *testing.F) {
	// Seed with real-ish shapes
	f.Add([]byte(`{"model":"gpt-4o","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	f.Add([]byte(`{"model":"gpt-4o"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"usage":null}`))
	f.Add([]byte(`{"usage":{"prompt_tokens":-1}}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(``))
	f.Add([]byte(`{"model":"","usage":{"prompt_tokens":999999999,"completion_tokens":999999999,"total_tokens":1999999998}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic. Errors are fine.
		extractOpenAIUsage(data)
	})
}

func FuzzExtractAnthropicUsage(f *testing.F) {
	f.Add([]byte(`{"model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":10,"output_tokens":5}}`))
	f.Add([]byte(`{"type":"error","error":{"type":"overloaded_error"}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"model":"x","usage":{"input_tokens":-99,"output_tokens":0}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		extractAnthropicUsage(data)
	})
}

func FuzzIsOpenAIStreamRequest(f *testing.F) {
	f.Add([]byte(`{"stream":true}`))
	f.Add([]byte(`{"stream":false}`))
	f.Add([]byte(`{"stream":"true"}`))
	f.Add([]byte(`{"stream":1}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		isOpenAIStreamRequest(data)
	})
}

func FuzzIsAnthropicStreamRequest(f *testing.F) {
	f.Add([]byte(`{"stream":true}`))
	f.Add([]byte(`{"stream":false}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		isAnthropicStreamRequest(data)
	})
}

func FuzzPrepareOpenAIStreamBody(f *testing.F) {
	f.Add([]byte(`{"model":"gpt-4o","stream":true}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"stream_options":{"include_usage":false}}`))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		prepareOpenAIStreamBody(data)
	})
}

func FuzzExtractOpenAIStreamUsage(f *testing.F) {
	// Seed with a single event data payload
	f.Add([]byte(`{"model":"gpt-4o","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	f.Add([]byte(`[DONE]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`not json`))

	f.Fuzz(func(t *testing.T, data []byte) {
		events := []SSEEvent{
			{Data: string(data)},
			{Data: "[DONE]"},
		}
		extractOpenAIStreamUsage(events)
	})
}

func FuzzExtractAnthropicStreamUsage(f *testing.F) {
	f.Add(
		[]byte(`{"type":"message_start","message":{"model":"claude","usage":{"input_tokens":5}}}`),
		[]byte(`{"type":"message_delta","usage":{"output_tokens":3}}`),
	)

	f.Fuzz(func(t *testing.T, startData, deltaData []byte) {
		events := []SSEEvent{
			{Event: "message_start", Data: string(startData)},
			{Event: "message_delta", Data: string(deltaData)},
		}
		extractAnthropicStreamUsage(events)
	})
}
