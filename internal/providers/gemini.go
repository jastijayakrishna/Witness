package providers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func init() {
	target, _ := url.Parse("https://generativelanguage.googleapis.com")
	Register(&Provider{
		Name:                   "gemini",
		PathPrefix:             "/gemini",
		Target:                 target,
		ExtractUsage:           extractGeminiUsage,
		ExtractStreamUsage:     extractGeminiStreamUsage,
		IsStreamRequest:        isGeminiStreamRequest,
		IsStreamPath:           isGeminiStreamPath,
		PrepareStreamBody:      nil, // Gemini doesn't need body modification
		ExtractToolCalls:       extractGeminiToolCalls,
		ExtractStreamToolCalls: extractGeminiStreamToolCalls,
	})
}

// geminiResponse is the subset of a Gemini API response we need.
type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text         string `json:"text"`
				FunctionCall *struct {
					Name string                 `json:"name"`
					Args map[string]interface{} `json:"args"`
				} `json:"functionCall"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata *struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
		TotalTokenCount      int `json:"totalTokenCount"`
	} `json:"usageMetadata"`
	ModelVersion string `json:"modelVersion"`
}

func extractGeminiUsage(body []byte) (Usage, error) {
	var resp geminiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return Usage{}, fmt.Errorf("parse gemini response: %w", err)
	}

	model := resp.ModelVersion
	if model == "" {
		model = "gemini-pro" // fallback
	}

	if resp.UsageMetadata == nil {
		return Usage{Model: model}, nil
	}

	return Usage{
		InputTokens:  resp.UsageMetadata.PromptTokenCount,
		OutputTokens: resp.UsageMetadata.CandidatesTokenCount,
		TotalTokens:  resp.UsageMetadata.TotalTokenCount,
		Model:        model,
	}, nil
}

// Gemini streaming format is SSE with data: prefix
// Each chunk has the same structure as non-streaming responses
func extractGeminiStreamUsage(events []SSEEvent) (Usage, error) {
	var usage Usage
	var totalInput, totalOutput int

	// Walk events to accumulate usage from all chunks
	for _, ev := range events {
		if ev.Data == "" {
			continue
		}

		var chunk geminiResponse
		if err := json.Unmarshal([]byte(ev.Data), &chunk); err != nil {
			continue
		}

		if chunk.ModelVersion != "" {
			usage.Model = chunk.ModelVersion
		}

		if chunk.UsageMetadata != nil {
			// In streaming, each chunk can have usage metadata
			// We take the last one which has the cumulative totals
			totalInput = chunk.UsageMetadata.PromptTokenCount
			totalOutput = chunk.UsageMetadata.CandidatesTokenCount
		}
	}

	usage.InputTokens = totalInput
	usage.OutputTokens = totalOutput
	usage.TotalTokens = totalInput + totalOutput

	return usage, nil
}

// extractGeminiToolCalls parses function calls from a non-streaming Gemini response.
// Path: candidates[0].content.parts[].functionCall.{name, args}
func extractGeminiToolCalls(body []byte) []ToolCall {
	var resp geminiResponse
	if err := json.Unmarshal(body, &resp); err != nil || len(resp.Candidates) == 0 {
		return nil
	}

	var calls []ToolCall
	for _, part := range resp.Candidates[0].Content.Parts {
		if part.FunctionCall != nil && part.FunctionCall.Name != "" {
			// Convert args map to JSON string
			argsJSON, _ := json.Marshal(part.FunctionCall.Args)
			calls = append(calls, ToolCall{
				Name:      part.FunctionCall.Name,
				Arguments: string(argsJSON),
			})
		}
	}
	return calls
}

// extractGeminiStreamToolCalls parses function calls from accumulated stream events.
func extractGeminiStreamToolCalls(events []SSEEvent) []ToolCall {
	var calls []ToolCall

	for _, ev := range events {
		if ev.Data == "" {
			continue
		}

		var chunk geminiResponse
		if err := json.Unmarshal([]byte(ev.Data), &chunk); err != nil {
			continue
		}

		if len(chunk.Candidates) == 0 {
			continue
		}

		for _, part := range chunk.Candidates[0].Content.Parts {
			if part.FunctionCall != nil && part.FunctionCall.Name != "" {
				argsJSON, _ := json.Marshal(part.FunctionCall.Args)
				calls = append(calls, ToolCall{
					Name:      part.FunctionCall.Name,
					Arguments: string(argsJSON),
				})
			}
		}
	}

	return calls
}

func isGeminiStreamRequest(body []byte) bool {
	// Gemini streaming is determined by the URL path (:streamGenerateContent),
	// not the request body. The body is identical for both modes.
	// See isGeminiStreamPath for the actual detection.
	return false
}

func isGeminiStreamPath(path string) bool {
	return strings.Contains(path, ":streamGenerateContent")
}
