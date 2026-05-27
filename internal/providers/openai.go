package providers

import (
	"encoding/json"
	"fmt"
	"net/url"
)

func init() {
	target, _ := url.Parse("https://api.openai.com")
	Register(&Provider{
		Name:                   "openai",
		PathPrefix:             "/openai",
		Target:                 target,
		ExtractUsage:           extractOpenAIUsage,
		ExtractStreamUsage:     extractOpenAIStreamUsage,
		IsStreamRequest:        isOpenAIStreamRequest,
		PrepareStreamBody:      prepareOpenAIStreamBody,
		ExtractToolCalls:       extractOpenAIToolCalls,
		ExtractStreamToolCalls: extractOpenAIStreamToolCalls,
	})
}

// openaiResponse is the subset of an OpenAI chat completion response we need.
type openaiResponse struct {
	Model string `json:"model"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func extractOpenAIUsage(body []byte) (Usage, error) {
	var resp openaiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Usage{}, fmt.Errorf("parse openai response: %w", err)
	}
	if resp.Usage == nil {
		return Usage{Model: resp.Model}, nil
	}
	return Usage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
		TotalTokens:  resp.Usage.TotalTokens,
		Model:        resp.Model,
	}, nil
}

// openaiStreamChunk is the subset of a streaming chunk we parse for usage.
type openaiStreamChunk struct {
	Model string `json:"model"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func extractOpenAIStreamUsage(events []SSEEvent) (Usage, error) {
	var usage Usage
	// Walk events in reverse to find the usage chunk (it's in the last data event).
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]
		if ev.Data == "" || ev.Data == "[DONE]" {
			continue
		}
		var chunk openaiStreamChunk
		if err := json.Unmarshal([]byte(ev.Data), &chunk); err != nil {
			continue
		}
		if chunk.Model != "" {
			usage.Model = chunk.Model
		}
		if chunk.Usage != nil {
			usage.InputTokens = chunk.Usage.PromptTokens
			usage.OutputTokens = chunk.Usage.CompletionTokens
			usage.TotalTokens = chunk.Usage.TotalTokens
			return usage, nil
		}
	}
	// Try to get the model from any event if we didn't find usage.
	for _, ev := range events {
		if ev.Data == "" || ev.Data == "[DONE]" {
			continue
		}
		var chunk openaiStreamChunk
		if err := json.Unmarshal([]byte(ev.Data), &chunk); err != nil {
			continue
		}
		if chunk.Model != "" {
			usage.Model = chunk.Model
			break
		}
	}
	return usage, nil
}

// extractOpenAIToolCalls parses tool_calls from a non-streaming OpenAI response.
// Path: choices[0].message.tool_calls[].function.{name, arguments}
func extractOpenAIToolCalls(body []byte) []ToolCall {
	var resp struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Choices) == 0 {
		return nil
	}
	var calls []ToolCall
	for _, tc := range resp.Choices[0].Message.ToolCalls {
		if tc.Function.Name != "" {
			calls = append(calls, ToolCall{
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			})
		}
	}
	return calls
}

// extractOpenAIStreamToolCalls parses tool_calls from accumulated stream events.
// In streaming, tool_call deltas arrive in chunks with index-based assembly.
// We extract from the accumulated usage-relevant events which include the first chunk.
func extractOpenAIStreamToolCalls(events []SSEEvent) []ToolCall {
	// OpenAI streams tool_calls as deltas across multiple chunks.
	// The first chunk for each tool_call has function.name; subsequent chunks
	// have function.arguments fragments. We accumulate by index.
	type partial struct {
		name string
		args string
	}
	partials := map[int]*partial{}

	for _, ev := range events {
		if ev.Data == "" || ev.Data == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					ToolCalls []struct {
						Index    int `json:"index"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if err := json.Unmarshal([]byte(ev.Data), &chunk); err != nil || len(chunk.Choices) == 0 {
			continue
		}
		for _, tc := range chunk.Choices[0].Delta.ToolCalls {
			p, ok := partials[tc.Index]
			if !ok {
				p = &partial{}
				partials[tc.Index] = p
			}
			if tc.Function.Name != "" {
				p.name = tc.Function.Name
			}
			p.args += tc.Function.Arguments
		}
	}

	if len(partials) == 0 {
		return nil
	}
	calls := make([]ToolCall, 0, len(partials))
	for i := 0; i < len(partials); i++ {
		if p, ok := partials[i]; ok && p.name != "" {
			calls = append(calls, ToolCall{Name: p.name, Arguments: p.args})
		}
	}
	return calls
}

func isOpenAIStreamRequest(body []byte) bool {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return false
	}
	stream, ok := req["stream"]
	if !ok {
		return false
	}
	b, ok := stream.(bool)
	return ok && b
}

// prepareOpenAIStreamBody injects stream_options.include_usage = true.
func prepareOpenAIStreamBody(body []byte) ([]byte, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse request body: %w", err)
	}

	// Inject stream_options with include_usage: true
	streamOpts, ok := req["stream_options"].(map[string]any)
	if !ok {
		streamOpts = map[string]any{}
	}
	streamOpts["include_usage"] = true
	req["stream_options"] = streamOpts

	out, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal modified request: %w", err)
	}
	return out, nil
}
