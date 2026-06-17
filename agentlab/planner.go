package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// planner is the brain of the agent. The lab runs the same loop against a
// scripted fake (offline tests) and live Gemini (the real stress run).
type planner interface {
	// UserMessage starts a new episode with a user ask.
	UserMessage(text string)
	// Next returns the model's next tool calls; empty means it is done talking.
	Next(ctx context.Context) ([]ToolCall, error)
	// ToolResult feeds a tool's outcome (or HubbleOps's block reason) back.
	ToolResult(call ToolCall, response map[string]any)
}

// ---------- fake planner (offline, deterministic) ----------

// fakePlanner replays a script: for each episode, a sequence of turns, each
// turn a batch of tool calls. It records the responses it was fed so tests can
// assert that block reasons actually reached the "model".
type fakePlanner struct {
	episodes [][][]ToolCall
	episode  int
	turn     int
	Fed      []map[string]any
}

func newFakePlanner(episodes [][][]ToolCall) *fakePlanner {
	return &fakePlanner{episodes: episodes, episode: -1}
}

func (f *fakePlanner) UserMessage(string) {
	f.episode++
	f.turn = 0
}

func (f *fakePlanner) Next(context.Context) ([]ToolCall, error) {
	if f.episode < 0 || f.episode >= len(f.episodes) {
		return nil, nil
	}
	turns := f.episodes[f.episode]
	if f.turn >= len(turns) {
		return nil, nil
	}
	calls := turns[f.turn]
	f.turn++
	return calls, nil
}

func (f *fakePlanner) ToolResult(_ ToolCall, response map[string]any) {
	f.Fed = append(f.Fed, response)
}

// ---------- Gemini planner (live) ----------

const defaultGeminiModel = "gemini-2.5-flash-lite"

type geminiPlanner struct {
	apiKey   string
	model    string
	system   string
	tools    []Tool
	contents []map[string]any
	calls    int
	budget   *int // shared across scenes: total generateContent calls allowed
}

func newGeminiPlanner(apiKey, system string, tools []Tool, budget *int) *geminiPlanner {
	model := os.Getenv("GEMINI_MODEL")
	if model == "" {
		model = os.Getenv("HUBBLEOPS_LIVE_GEMINI_MODEL")
	}
	if model == "" {
		model = defaultGeminiModel
	}
	return &geminiPlanner{apiKey: apiKey, model: model, system: system, tools: tools, budget: budget}
}

func (g *geminiPlanner) UserMessage(text string) {
	g.contents = append(g.contents, map[string]any{
		"role":  "user",
		"parts": []map[string]any{{"text": text}},
	})
}

func (g *geminiPlanner) ToolResult(call ToolCall, response map[string]any) {
	g.contents = append(g.contents, map[string]any{
		"role": "user",
		"parts": []map[string]any{{
			"functionResponse": map[string]any{
				"name":     call.Name,
				"response": map[string]any{"content": response},
			},
		}},
	})
}

// geminiGate paces requests to stay under the free tier's requests-per-minute
// limit, shared across all scenes in a run.
var geminiGate = struct {
	mu   sync.Mutex
	last time.Time
}{}

const geminiMinInterval = 6500 * time.Millisecond

var retryDelayPattern = regexp.MustCompile(`"retryDelay"\s*:\s*"(\d+)`)

func (g *geminiPlanner) Next(ctx context.Context) ([]ToolCall, error) {
	if *g.budget <= 0 {
		return nil, fmt.Errorf("gemini call budget exhausted")
	}
	*g.budget--
	g.calls++

	geminiGate.mu.Lock()
	if wait := geminiMinInterval - time.Since(geminiGate.last); wait > 0 {
		time.Sleep(wait)
	}
	geminiGate.last = time.Now()
	geminiGate.mu.Unlock()

	declarations := make([]map[string]any, 0, len(g.tools))
	for _, t := range g.tools {
		declarations = append(declarations, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"parameters":  t.Schema,
		})
	}
	payload := map[string]any{
		"systemInstruction": map[string]any{
			"parts": []map[string]any{{"text": g.system}},
		},
		"contents": g.contents,
		"tools":    []map[string]any{{"functionDeclarations": declarations}},
		"generationConfig": map[string]any{
			"temperature":     0,
			"maxOutputTokens": 512,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := "https://generativelanguage.googleapis.com/v1beta/models/" + url.PathEscape(g.model) + ":generateContent"
	var respBody []byte
	for attempt := 1; ; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			cancel()
			return nil, err
		}
		req.Header.Set("x-goog-api-key", g.apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "hubbleops-agentlab/0")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("gemini request: %w", err)
		}
		respBody, err = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		cancel()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt <= 4 {
			// Honor the API's suggested retry delay (free-tier RPM limit);
			// default to half a minute when it doesn't say.
			delay := 30 * time.Second
			if m := retryDelayPattern.FindStringSubmatch(string(respBody)); len(m) == 2 {
				if secs, parseErr := time.ParseDuration(m[1] + "s"); parseErr == nil && secs > 0 {
					delay = secs + time.Second
				}
			}
			fmt.Printf("    (gemini rate limited; waiting %s, attempt %d/4)\n", delay, attempt)
			time.Sleep(delay)
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("gemini status %d: %s", resp.StatusCode, truncate(string(respBody), 400))
		}
		break
	}

	// Append the model's own turn to history so function responses line up.
	var parsed struct {
		Candidates []struct {
			Content map[string]any `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("parse gemini response: %w", err)
	}
	if len(parsed.Candidates) == 0 || parsed.Candidates[0].Content == nil {
		return nil, nil
	}
	content := parsed.Candidates[0].Content
	if _, ok := content["role"]; !ok {
		content["role"] = "model"
	}
	g.contents = append(g.contents, content)

	return extractFunctionCalls(content), nil
}

func extractFunctionCalls(content map[string]any) []ToolCall {
	parts, _ := content["parts"].([]any)
	var calls []ToolCall
	for _, p := range parts {
		part, _ := p.(map[string]any)
		fc, _ := part["functionCall"].(map[string]any)
		if fc == nil {
			continue
		}
		name, _ := fc["name"].(string)
		args, _ := fc["args"].(map[string]any)
		if args == nil {
			args = map[string]any{}
		}
		calls = append(calls, ToolCall{Name: name, Args: args})
	}
	return calls
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "...<truncated>"
	}
	return s
}
