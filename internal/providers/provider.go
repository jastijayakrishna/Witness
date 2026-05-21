package providers

import "net/url"

// Usage holds extracted token counts from an LLM API response.
type Usage struct {
	InputTokens  int    `json:"input_tokens"`
	OutputTokens int    `json:"output_tokens"`
	TotalTokens  int    `json:"total_tokens"`
	Model        string `json:"model"`
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
	// PrepareStreamBody modifies the request body to ensure usage is included in stream.
	PrepareStreamBody func(body []byte) ([]byte, error)
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
