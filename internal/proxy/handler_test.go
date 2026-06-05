package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/providers"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

func newTestHandler(t *testing.T) (*Handler, string) {
	t.Helper()
	dir := t.TempDir()
	w, err := wal.NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("new wal writer: %v", err)
	}
	t.Cleanup(func() { w.Close() })

	h := NewHandler(w, nil, loop.DefaultConfig()) // nil LoopStore = detection disabled in tests
	return h, dir
}

func TestHandler_NonStreamOpenAI(t *testing.T) {
	// Fake upstream OpenAI server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify path stripping: should receive /v1/chat/completions, not /openai/v1/...
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("upstream got path %q, want /v1/chat/completions", r.URL.Path)
		}
		// Verify Authorization is forwarded
		if r.Header.Get("Authorization") != "Bearer sk-test" {
			t.Errorf("Authorization not forwarded")
		}
		// Verify X-Project is stripped
		if r.Header.Get("X-Project") != "" {
			t.Errorf("X-Project should be stripped before forwarding")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{
			"id": "chatcmpl-test",
			"model": "gpt-4o-mini",
			"choices": [{"message": {"content": "Hello!"}, "finish_reason": "stop"}],
			"usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13}
		}`)
	}))
	defer upstream.Close()

	// Point the OpenAI provider at our fake upstream
	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandler(t)

	// Make request
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("X-Project", "test-project")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if parsed["model"] != "gpt-4o-mini" {
		t.Errorf("response model = %v", parsed["model"])
	}

	// Verify WAL was written
	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(walRecords))
	}

	wr := walRecords[0]
	if wr.Project != "test-project" {
		t.Errorf("wal project = %q, want %q", wr.Project, "test-project")
	}
	if wr.Provider != "openai" {
		t.Errorf("wal provider = %q, want %q", wr.Provider, "openai")
	}
	if wr.Model != "gpt-4o-mini" {
		t.Errorf("wal model = %q, want %q", wr.Model, "gpt-4o-mini")
	}
	if wr.InputTokens != 10 {
		t.Errorf("wal input_tokens = %d, want 10", wr.InputTokens)
	}
	if wr.OutputTokens != 3 {
		t.Errorf("wal output_tokens = %d, want 3", wr.OutputTokens)
	}
	if wr.StatusCode != 200 {
		t.Errorf("wal status_code = %d, want 200", wr.StatusCode)
	}
	if wr.Stream {
		t.Error("wal stream should be false for non-streaming")
	}
	if wr.Cost <= 0 {
		t.Errorf("wal cost = %f, should be > 0", wr.Cost)
	}
}

func TestHandler_StreamOpenAI(t *testing.T) {
	// Fake upstream that returns SSE
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify stream_options was injected
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)
		streamOpts, ok := req["stream_options"].(map[string]any)
		if !ok || streamOpts["include_usage"] != true {
			t.Errorf("stream_options.include_usage not injected, body: %s", body)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)

		flusher := w.(http.Flusher)
		chunks := []string{
			"data: {\"id\":\"chatcmpl-s\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"role\":\"assistant\"},\"index\":0}]}\n\n",
			"data: {\"id\":\"chatcmpl-s\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"index\":0}]}\n\n",
			"data: {\"id\":\"chatcmpl-s\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{},\"index\":0,\"finish_reason\":\"stop\"}]}\n\n",
			// Usage-only chunk (should be captured but NOT forwarded)
			"data: {\"id\":\"chatcmpl-s\",\"model\":\"gpt-4o-mini\",\"choices\":[],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":1,\"total_tokens\":9}}\n\n",
			"data: [DONE]\n\n",
		}
		for _, chunk := range chunks {
			fmt.Fprint(w, chunk)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandler(t)

	body := `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("X-Project", "stream-test")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	respStr := string(respBody)

	// The usage-only chunk should NOT appear in the forwarded response
	if strings.Contains(respStr, `"prompt_tokens"`) {
		t.Error("usage-only chunk was forwarded to client — it should be filtered out")
	}

	// Content chunks should be forwarded
	if !strings.Contains(respStr, `"Hi"`) {
		t.Error("content chunk was not forwarded to client")
	}

	// [DONE] should be forwarded
	if !strings.Contains(respStr, "[DONE]") {
		t.Error("[DONE] was not forwarded to client")
	}

	// Verify WAL
	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(walRecords))
	}

	wr := walRecords[0]
	if wr.Project != "stream-test" {
		t.Errorf("wal project = %q", wr.Project)
	}
	if wr.InputTokens != 8 {
		t.Errorf("wal input_tokens = %d, want 8", wr.InputTokens)
	}
	if wr.OutputTokens != 1 {
		t.Errorf("wal output_tokens = %d, want 1", wr.OutputTokens)
	}
	if !wr.Stream {
		t.Error("wal stream should be true")
	}
}

func TestHandler_StreamOpenAI_ClientRequestedUsage(t *testing.T) {
	// When the client already set stream_options.include_usage = true,
	// we must NOT suppress the usage chunk — they need it for their own accounting.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)

		flusher := w.(http.Flusher)
		chunks := []string{
			"data: {\"id\":\"chatcmpl-s\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"Hi\"},\"index\":0}]}\n\n",
			"data: {\"id\":\"chatcmpl-s\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{},\"index\":0,\"finish_reason\":\"stop\"}]}\n\n",
			// Usage-only chunk — should be forwarded because client asked for it
			"data: {\"id\":\"chatcmpl-s\",\"model\":\"gpt-4o-mini\",\"choices\":[],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":1,\"total_tokens\":9}}\n\n",
			"data: [DONE]\n\n",
		}
		for _, chunk := range chunks {
			fmt.Fprint(w, chunk)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandler(t)

	// Client already set include_usage — proxy should NOT suppress the usage chunk
	body := `{"model":"gpt-4o-mini","stream":true,"stream_options":{"include_usage":true},"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("X-Project", "client-usage-test")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	respStr := string(respBody)

	// The usage chunk MUST be forwarded because the client asked for it
	if !strings.Contains(respStr, `"prompt_tokens"`) {
		t.Error("usage chunk was suppressed but client requested include_usage — should have been forwarded")
	}

	// Content should also be forwarded
	if !strings.Contains(respStr, `"Hi"`) {
		t.Error("content chunk was not forwarded")
	}

	// Verify WAL still captured usage correctly
	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(walRecords))
	}
	wr := walRecords[0]
	if wr.InputTokens != 8 {
		t.Errorf("wal input_tokens = %d, want 8", wr.InputTokens)
	}
	if wr.OutputTokens != 1 {
		t.Errorf("wal output_tokens = %d, want 1", wr.OutputTokens)
	}
}

func TestClientHasIncludeUsage(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{"no stream_options", `{"model":"gpt-4o","stream":true}`, false},
		{"include_usage true", `{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":true}}`, true},
		{"include_usage false", `{"model":"gpt-4o","stream":true,"stream_options":{"include_usage":false}}`, false},
		{"empty stream_options", `{"model":"gpt-4o","stream":true,"stream_options":{}}`, false},
		{"invalid json", `{broken`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientHasIncludeUsage([]byte(tt.body))
			if got != tt.want {
				t.Errorf("clientHasIncludeUsage = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandler_NonStreamAnthropic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("upstream got path %q, want /v1/messages", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{
			"id": "msg_test",
			"type": "message",
			"model": "claude-3-5-sonnet-20241022",
			"content": [{"type":"text","text":"Hello!"}],
			"usage": {"input_tokens": 20, "output_tokens": 6}
		}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/anthropic"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/anthropic"].Target = target
	defer func() { providers.Registry["/anthropic"].Target = origTarget }()

	handler, walDir := newTestHandler(t)

	body := `{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"hi"}],"max_tokens":100}`
	req := httptest.NewRequest("POST", "/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("x-api-key", "sk-ant-test")
	req.Header.Set("X-Project", "anthropic-test")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(walRecords))
	}

	wr := walRecords[0]
	if wr.Provider != "anthropic" {
		t.Errorf("wal provider = %q", wr.Provider)
	}
	if wr.Model != "claude-3-5-sonnet-20241022" {
		t.Errorf("wal model = %q", wr.Model)
	}
	if wr.InputTokens != 20 {
		t.Errorf("wal input_tokens = %d, want 20", wr.InputTokens)
	}
	if wr.OutputTokens != 6 {
		t.Errorf("wal output_tokens = %d, want 6", wr.OutputTokens)
	}
}

func TestHandler_StreamAnthropic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)

		events := []string{
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_s\",\"model\":\"claude-3-5-sonnet-20241022\",\"usage\":{\"input_tokens\":12,\"output_tokens\":0}}}\n\n",
			"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hey!\"}}\n\n",
			"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
			"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n",
			"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
		}
		for _, ev := range events {
			fmt.Fprint(w, ev)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/anthropic"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/anthropic"].Target = target
	defer func() { providers.Registry["/anthropic"].Target = origTarget }()

	handler, walDir := newTestHandler(t)

	body := `{"model":"claude-3-5-sonnet-20241022","stream":true,"messages":[{"role":"user","content":"hi"}],"max_tokens":100}`
	req := httptest.NewRequest("POST", "/anthropic/v1/messages", strings.NewReader(body))
	req.Header.Set("X-Project", "stream-anthropic")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}

	respBody, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(respBody), "Hey!") {
		t.Error("content delta not forwarded")
	}

	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(walRecords))
	}

	wr := walRecords[0]
	if wr.InputTokens != 12 {
		t.Errorf("input_tokens = %d, want 12", wr.InputTokens)
	}
	if wr.OutputTokens != 4 {
		t.Errorf("output_tokens = %d, want 4", wr.OutputTokens)
	}
	if !wr.Stream {
		t.Error("stream should be true")
	}
}

func TestHandler_UnknownProvider(t *testing.T) {
	handler, _ := newTestHandler(t)

	req := httptest.NewRequest("POST", "/google/v1/models", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestHandler_UpstreamError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(429)
		fmt.Fprint(w, `{"error":{"message":"Rate limit exceeded","type":"rate_limit_error"}}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Upstream errors should be passed through
	if rec.Code != 429 {
		t.Errorf("status = %d, want 429 (passthrough)", rec.Code)
	}
}

func TestHandler_QueryParamsForwarded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "api-version=2024-02-01" {
			t.Errorf("query = %q, want api-version=2024-02-01", r.URL.RawQuery)
		}
		w.WriteHeader(200)
		fmt.Fprint(w, `{"model":"gpt-4o","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions?api-version=2024-02-01", strings.NewReader(`{"model":"gpt-4o"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("status = %d", rec.Code)
	}
}

func TestCopyHeaders_SkipsHopByHop(t *testing.T) {
	src := http.Header{}
	src.Set("Authorization", "Bearer sk-test")
	src.Set("Content-Type", "application/json")
	src.Set("Connection", "keep-alive")
	src.Set("X-Project", "should-be-stripped")
	src.Set("Transfer-Encoding", "chunked")
	src.Set("X-Custom", "should-pass")

	dst := http.Header{}
	copyHeaders(src, dst)

	if dst.Get("Authorization") != "Bearer sk-test" {
		t.Error("Authorization not copied")
	}
	if dst.Get("Content-Type") != "application/json" {
		t.Error("Content-Type not copied")
	}
	if dst.Get("X-Custom") != "should-pass" {
		t.Error("X-Custom not copied")
	}
	if dst.Get("Connection") != "" {
		t.Error("Connection should be stripped")
	}
	if dst.Get("X-Project") != "" {
		t.Error("X-Project should be stripped")
	}
	if dst.Get("Transfer-Encoding") != "" {
		t.Error("Transfer-Encoding should be stripped")
	}
}

func TestHashPrompt_Deterministic(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}`)
	h1 := hashPrompt(body)
	h2 := hashPrompt(body)
	if h1 != h2 {
		t.Errorf("hash not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("hash length = %d, want 16", len(h1))
	}
}

func TestHashPrompt_DifferentBodiesProduceDifferentHashes(t *testing.T) {
	h1 := hashPrompt([]byte(`{"messages":[{"content":"hello"}]}`))
	h2 := hashPrompt([]byte(`{"messages":[{"content":"world"}]}`))
	if h1 == h2 {
		t.Error("different bodies produced same hash")
	}
}

func TestIsOpenAIUsageOnlyChunk(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{
			"usage with empty choices",
			`{"id":"c","model":"gpt-4o","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`,
			true,
		},
		{
			"content delta (not usage-only)",
			`{"id":"c","model":"gpt-4o","choices":[{"delta":{"content":"Hi"},"index":0}]}`,
			false,
		},
		{
			"stop with no usage",
			`{"id":"c","model":"gpt-4o","choices":[{"delta":{},"finish_reason":"stop"}]}`,
			false,
		},
		{
			"usage with null content in delta",
			`{"id":"c","model":"gpt-4o","choices":[{"delta":{"content":null}}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`,
			true, // null content means no actual content — still a usage-only chunk
		},
		{
			"usage with empty string content",
			`{"id":"c","choices":[{"delta":{"content":""}}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`,
			true,
		},
		{
			"invalid json",
			`{broken`,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isOpenAIUsageOnlyChunk(tt.data)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// --- loop detection integration tests ---

func newTestHandlerWithLoop(t *testing.T) (*Handler, string) {
	t.Helper()
	dir := t.TempDir()
	w, err := wal.NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("new wal writer: %v", err)
	}
	t.Cleanup(func() { w.Close() })

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	loopStore := loop.NewStateStore(rdb)

	cfg := loop.DefaultConfig()
	cfg.Action = "shadow" // shadow mode — observe only

	h := NewHandler(w, loopStore, cfg)
	return h, dir
}

func TestHandler_LoopDetection_PopulatesWALFields(t *testing.T) {
	// A single request with a tool call should populate loop fields in WAL
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{
			"id": "chatcmpl-loop1",
			"model": "gpt-4o-mini",
			"choices": [{
				"message": {
					"role": "assistant",
					"tool_calls": [{
						"id": "call_1",
						"type": "function",
						"function": {"name": "bash", "arguments": "{\"cmd\":\"ls\"}"}
					}]
				},
				"finish_reason": "tool_calls"
			}],
			"usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}
		}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandlerWithLoop(t)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"run ls"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("X-Project", "loop-test")
	req.Header.Set("X-Session-ID", "sess-1")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	records := readWALRecords(t, walDir)
	if len(records) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(records))
	}

	wr := records[0]
	// First turn should have no signals (not enough history to detect a loop)
	if wr.LoopSignalsFired != "" {
		t.Errorf("first turn should have no signals, got %q", wr.LoopSignalsFired)
	}
	if wr.LoopConfidence != 0 {
		t.Errorf("first turn confidence = %f, want 0", wr.LoopConfidence)
	}
	// In shadow mode, first turn (no signals) records "shadow" to indicate detector ran
	if wr.LoopAction != "" && wr.LoopAction != "none" && wr.LoopAction != "shadow" {
		t.Errorf("first turn action = %q, want empty, none, or shadow", wr.LoopAction)
	}
}

func TestHandler_LoopDetection_DetectsRepetition(t *testing.T) {
	// Send multiple identical tool-call requests to trigger identical_repeat
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{
			"id": "chatcmpl-rep",
			"model": "gpt-4o-mini",
			"choices": [{
				"message": {
					"role": "assistant",
					"tool_calls": [{
						"id": "call_r",
						"type": "function",
						"function": {"name": "bash", "arguments": "{\"cmd\":\"ls\"}"}
					}]
				},
				"finish_reason": "tool_calls"
			}],
			"usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}
		}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandlerWithLoop(t)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"run ls again"}]}`

	// Send 4 identical requests (MaxRepeated = 3, so 3+ fires identical_repeat)
	for i := 0; i < 4; i++ {
		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-test")
		req.Header.Set("X-Project", "repeat-test")
		req.Header.Set("X-Session-ID", "sess-repeat")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("request %d: status = %d", i, rec.Code)
		}
	}

	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	records := readWALRecords(t, walDir)
	if len(records) != 4 {
		t.Fatalf("expected 4 WAL records, got %d", len(records))
	}

	// The last record (4th turn) should have identical_repeat signal
	last := records[3]
	if !strings.Contains(last.LoopSignalsFired, "identical_repeat") {
		t.Errorf("4th turn signals = %q, want to contain 'identical_repeat'", last.LoopSignalsFired)
	}
	if last.LoopConfidence <= 0 {
		t.Errorf("4th turn confidence = %f, want > 0", last.LoopConfidence)
	}
}

func TestHandler_LoopDetection_FailsOpenOnRedisDown(t *testing.T) {
	// When Redis is unreachable, loop detection must fail open:
	// - request completes successfully
	// - WAL is written (with empty loop fields)
	// - no hang, no panic
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{
			"id": "chatcmpl-failopen",
			"model": "gpt-4o-mini",
			"choices": [{
				"message": {
					"role": "assistant",
					"tool_calls": [{
						"id": "call_fo",
						"type": "function",
						"function": {"name": "bash", "arguments": "{\"cmd\":\"ls\"}"}
					}]
				},
				"finish_reason": "tool_calls"
			}],
			"usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120}
		}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	// Create handler with a Redis that we then shut down
	dir := t.TempDir()
	w, err := wal.NewWriter(dir, "batch")
	if err != nil {
		t.Fatalf("new wal writer: %v", err)
	}
	t.Cleanup(func() { w.Close() })

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	loopStore := loop.NewStateStore(rdb)

	cfg := loop.DefaultConfig()
	cfg.Action = "shadow"
	handler := NewHandler(w, loopStore, cfg)

	// Kill Redis BEFORE sending the request
	mr.Close()

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"test"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("X-Project", "failopen-test")
	req.Header.Set("X-Session-ID", "sess-fail")

	start := time.Now()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	elapsed := time.Since(start)

	// Request MUST succeed
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (fail-open)", rec.Code)
	}

	// Must complete quickly — the 5ms timeout per call means at most ~10ms added.
	// Give 500ms headroom for slow CI but the point is it doesn't hang.
	if elapsed > 500*time.Millisecond {
		t.Errorf("request took %v — Redis failure should not block the hot path", elapsed)
	}

	// WAL should still be written (with empty loop fields)
	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	records := readWALRecords(t, dir)
	if len(records) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(records))
	}
	wr := records[0]
	if wr.LoopSignalsFired != "" {
		t.Errorf("failed-open should have no signals, got %q", wr.LoopSignalsFired)
	}
}

func TestHandler_LoopDetection_DisabledWithNilStore(t *testing.T) {
	// When LoopStore is nil, loop fields should be empty
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{
			"id": "chatcmpl-no-loop",
			"model": "gpt-4o-mini",
			"choices": [{"message": {"content": "Hi"}, "finish_reason": "stop"}],
			"usage": {"prompt_tokens": 10, "completion_tokens": 3, "total_tokens": 13}
		}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandler(t) // nil LoopStore

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer sk-test")
	req.Header.Set("X-Project", "disabled-test")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	records := readWALRecords(t, walDir)
	if len(records) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(records))
	}

	wr := records[0]
	if wr.LoopSignalsFired != "" {
		t.Errorf("disabled detector should not fire signals, got %q", wr.LoopSignalsFired)
	}
	if wr.LoopConfidence != 0 {
		t.Errorf("disabled detector confidence = %f, want 0", wr.LoopConfidence)
	}
	if wr.LoopAction != "" {
		t.Errorf("disabled detector action = %q, want empty", wr.LoopAction)
	}
}

// --- helpers ---

func readWALRecords(t *testing.T, dir string) []wal.Record {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read wal dir: %v", err)
	}

	var records []wal.Record
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Skip non-WAL files (e.g., wal-chain-head.json, wal-offset.json)
		if !strings.HasPrefix(entry.Name(), "wal-") || !strings.HasSuffix(entry.Name(), ".jsonl") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("read wal file: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var rec wal.Record
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("unmarshal wal record: %v\nline: %s", err, line)
			}
			records = append(records, rec)
		}
	}
	return records
}
