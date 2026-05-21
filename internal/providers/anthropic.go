package providers

import (
	"encoding/json"
	"fmt"
	"net/url"
)

func init() {
	target, _ := url.Parse("https://api.anthropic.com")
	Register(&Provider{
		Name:               "anthropic",
		PathPrefix:         "/anthropic",
		Target:             target,
		ExtractUsage:       extractAnthropicUsage,
		ExtractStreamUsage: extractAnthropicStreamUsage,
		IsStreamRequest:    isAnthropicStreamRequest,
		PrepareStreamBody:  nil, // Anthropic doesn't need body modification for stream usage
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
