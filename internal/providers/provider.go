package providers

import "net/url"

// Usage holds extracted token counts from an LLM API response.
type Usage struct {
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	TotalTokens  int    `json:"total_tokens"`
	Model        string `json:"model"`
}

// ToolCall represents a single tool invocation extracted from an LLM response.
type ToolCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Provider defines how to proxy to a specific LLM API.
type Provider struct {
	Name       string
	PathPrefix string
	Target     *url.URL
	// ExtractUsage parses a non-streaming response body and returns usage.
	ExtractUsage func(body []byte) (Usage, error)
	// ExtractStreamUsage parses accumulated SSE events and returns usage.
	ExtractStreamUsage func(events []SSEEvent) (Usage, error)
	// IsStreamRequest checks if the request body indicates streaming.
	IsStreamRequest func(body []byte) bool
	// IsStreamPath checks if the URL path indicates streaming (e.g. Gemini uses
	// :streamGenerateContent in the URL rather than a body field). Optional; nil
	// means path is never the streaming signal.
	IsStreamPath func(path string) bool
	// PrepareStreamBody modifies the request body to ensure usage is included in stream.
	PrepareStreamBody func(body []byte) ([]byte, error)
	// ExtractToolCalls parses tool invocations from a non-streaming response.
	ExtractToolCalls func(body []byte) []ToolCall
	// ExtractStreamToolCalls parses tool invocations from accumulated SSE events.
	ExtractStreamToolCalls func(events []SSEEvent) []ToolCall
	// ExtractLatestToolResult extracts the most recent tool result from a request body.
	// Tool results live in the request (fed back as messages), not the response.
	ExtractLatestToolResult func(reqBody []byte) string
}

// SSEEvent represents a single Server-Sent Event.
type SSEEvent struct {
	Event string
	Data  string
}

// Registry holds all registered providers keyed by path prefix.
var Registry = map[string]*Provider{}

// Register adds a provider to the registry.
func Register(p *Provider) {
	Registry[p.PathPrefix] = p
}

// Lookup finds a provider by path prefix.
func Lookup(path string) *Provider {
	for prefix, p := range Registry {
		if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
			return p
		}
	}
	return nil
}
