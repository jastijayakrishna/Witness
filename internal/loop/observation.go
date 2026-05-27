package loop

// ToolCall represents a single tool invocation extracted from an LLM response.
// Used by the proxy handler to build Observations for the detector.
type ToolCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}
