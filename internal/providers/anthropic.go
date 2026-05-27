package providers

import (
	"encoding/json"
	"fmt"
	"net/url"
)

func init() {
	target, _ := url.Parse("https://api.anthropic.com")
	Register(&Provider{
		Name:                   "anthropic",
		PathPrefix:             "/anthropic",
		Target:                 target,
		ExtractUsage:           extractAnthropicUsage,
		ExtractStreamUsage:     extractAnthropicStreamUsage,
		IsStreamRequest:        isAnthropicStreamRequest,
		PrepareStreamBody:      nil, // Anthropic doesn't need body modification for stream usage
		ExtractToolCalls:       extractAnthropicToolCalls,
		ExtractStreamToolCalls: extractAnthropicStreamToolCalls,
	})
}

type anthropicResponse struct {
	Model string `json:"model"`
	Usage *struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func extractAnthropicUsage(body []byte) (Usage, error) {
	var resp anthropicResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Usage{}, fmt.Errorf("parse anthropic response: %w", err)
	}
	if resp.Usage == nil {
		return Usage{Model: resp.Model}, nil
	}
	return Usage{
		InputTokens:  resp.Usage.InputTokens,
		OutputTokens: resp.Usage.OutputTokens,
		TotalTokens:  resp.Usage.InputTokens + resp.Usage.OutputTokens,
		Model:        resp.Model,
	}, nil
}

// Anthropic streaming:
// - event: message_start contains initial usage with input_tokens
// - event: message_delta (last one) contains usage.output_tokens

type anthropicStreamMessageStart struct {
	Type    string `json:"type"`
	Message *struct {
		Model string `json:"model"`
		Usage *struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	} `json:"message"`
}

type anthropicStreamMessageDelta struct {
	Type  string `json:"type"`
	Usage *struct {
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func extractAnthropicStreamUsage(events []SSEEvent) (Usage, error) {
	var usage Usage

	for _, ev := range events {
		if ev.Data == "" {
			continue
		}

		switch ev.Event {
		case "message_start":
			var msg anthropicStreamMessageStart
			if err := json.Unmarshal([]byte(ev.Data), &msg); err != nil {
				continue
			}
			if msg.Message != nil {
				usage.Model = msg.Message.Model
				if msg.Message.Usage != nil {
					usage.InputTokens = msg.Message.Usage.InputTokens
				}
			}

		case "message_delta":
			var delta anthropicStreamMessageDelta
			if err := json.Unmarshal([]byte(ev.Data), &delta); err != nil {
				continue
			}
			if delta.Usage != nil {
				usage.OutputTokens = delta.Usage.OutputTokens
			}
		}
	}

	usage.TotalTokens = usage.InputTokens + usage.OutputTokens
	return usage, nil
}

// extractAnthropicToolCalls parses tool_use blocks from a non-streaming Anthropic response.
// Path: content[].type=="tool_use" → {name, input}
func extractAnthropicToolCalls(body []byte) []ToolCall {
	var resp struct {
		Content []struct {
			Type  string          `json:"type"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil
	}
	var calls []ToolCall
	for _, block := range resp.Content {
		if block.Type == "tool_use" && block.Name != "" {
			calls = append(calls, ToolCall{
				Name:      block.Name,
				Arguments: string(block.Input),
			})
		}
	}
	return calls
}

// extractAnthropicStreamToolCalls parses tool_use from accumulated stream events.
// Anthropic streams tool_use as content_block_start (name) + content_block_delta (input json_delta).
func extractAnthropicStreamToolCalls(events []SSEEvent) []ToolCall {
	type partial struct {
		name string
		args string
	}
	var partials []partial

	for _, ev := range events {
		if ev.Data == "" {
			continue
		}
		switch ev.Event {
		case "content_block_start":
			var block struct {
				ContentBlock struct {
					Type string `json:"type"`
					Name string `json:"name"`
				} `json:"content_block"`
			}
			if err := json.Unmarshal([]byte(ev.Data), &block); err != nil {
				continue
			}
			if block.ContentBlock.Type == "tool_use" {
				partials = append(partials, partial{name: block.ContentBlock.Name})
			}
		case "content_block_delta":
			var delta struct {
				Delta struct {
					Type        string `json:"type"`
					PartialJSON string `json:"partial_json"`
				} `json:"delta"`
			}
			if err := json.Unmarshal([]byte(ev.Data), &delta); err != nil {
				continue
			}
			if delta.Delta.Type == "input_json_delta" && len(partials) > 0 {
				partials[len(partials)-1].args += delta.Delta.PartialJSON
			}
		}
	}

	if len(partials) == 0 {
		return nil
	}
	calls := make([]ToolCall, 0, len(partials))
	for _, p := range partials {
		if p.name != "" {
			calls = append(calls, ToolCall{Name: p.name, Arguments: p.args})
		}
	}
	return calls
}

func isAnthropicStreamRequest(body []byte) bool {
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
