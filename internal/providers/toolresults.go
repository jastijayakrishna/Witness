package providers

import "encoding/json"

// toolresults.go
//
// Extracts the most recent tool RESULT from a request body. Tool results live
// in the request (fed back as messages), not the response — the response
// carries the next tool CALL. Pairing "current call" (from response) with
// "latest result" (from request) gives the detector its no-progress signal:
// same tool, same args, same result repeating = a stuck agent.
//
// Every extractor is fail-safe: any parse error, missing field, or unexpected
// shape returns "". A malformed body must never panic or block a request.
//
// This file's init() runs after every provider's init() (Go runs init funcs in
// filename order within a package; "toolresults.go" sorts last), so the Registry
// is fully populated when we attach these.

func init() {
	if p := Registry["/openai"]; p != nil {
		p.ExtractLatestToolResult = extractOpenAILatestToolResult
	}
	if p := Registry["/anthropic"]; p != nil {
		p.ExtractLatestToolResult = extractAnthropicLatestToolResult
	}
	if p := Registry["/gemini"]; p != nil {
		p.ExtractLatestToolResult = extractGeminiLatestToolResult
	}
}

// rawContentToString renders a JSON content field as a stable string.
// A plain JSON string returns its value; anything else returns the raw bytes
// (stable for hashing). Empty/invalid returns "".
func rawContentToString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// ── OpenAI ──────────────────────────────────────────────────────────────
// Tool results are messages with role:"tool". content is usually a string.
//   {"messages":[..., {"role":"tool","tool_call_id":"...","content":"..."}]}
func extractOpenAILatestToolResult(reqBody []byte) string {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return ""
	}
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "tool" {
			return rawContentToString(req.Messages[i].Content)
		}
	}
	return ""
}

// ── Anthropic ───────────────────────────────────────────────────────────
// Tool results are content blocks (type:"tool_result") inside a user message.
// content may be a plain string (no tool_result) or an array of blocks.
//   {"messages":[..., {"role":"user","content":[
//       {"type":"tool_result","tool_use_id":"...","content":"..."}]}]}
func extractAnthropicLatestToolResult(reqBody []byte) string {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return ""
	}
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role != "user" {
			continue
		}
		// content is either a string (no tool_result) or an array of blocks.
		var blocks []struct {
			Type    string          `json:"type"`
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(req.Messages[i].Content, &blocks); err != nil {
			continue // plain-string content: no tool_result here
		}
		for j := len(blocks) - 1; j >= 0; j-- {
			if blocks[j].Type == "tool_result" {
				return rawContentToString(blocks[j].Content)
			}
		}
	}
	return ""
}

// ── Gemini ──────────────────────────────────────────────────────────────
// Tool results are functionResponse parts inside a content entry.
//   {"contents":[..., {"role":"user","parts":[
//       {"functionResponse":{"name":"...","response":{...}}}]}]}
func extractGeminiLatestToolResult(reqBody []byte) string {
	var req struct {
		Contents []struct {
			Parts []struct {
				FunctionResponse *struct {
					Name     string          `json:"name"`
					Response json.RawMessage `json:"response"`
				} `json:"functionResponse"`
			} `json:"parts"`
		} `json:"contents"`
	}
	if err := json.Unmarshal(reqBody, &req); err != nil {
		return ""
	}
	for i := len(req.Contents) - 1; i >= 0; i-- {
		parts := req.Contents[i].Parts
		for j := len(parts) - 1; j >= 0; j-- {
			if parts[j].FunctionResponse != nil {
				return string(parts[j].FunctionResponse.Response)
			}
		}
	}
	return ""
}
