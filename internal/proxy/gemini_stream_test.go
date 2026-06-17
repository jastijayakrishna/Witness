package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/providers"
)

// TestHandler_StreamGemini verifies that requests to Gemini's streamGenerateContent
// endpoint are correctly detected as streaming, usage is extracted from SSE events,
// and the WAL records the request as a streaming request.
func TestHandler_StreamGemini(t *testing.T) {
	// Fake upstream Gemini server that returns SSE
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Gemini streaming endpoint should receive the path without /gemini prefix
		expectedPath := "/v1beta/models/gemini-pro:streamGenerateContent"
		if r.URL.Path != expectedPath {
			t.Errorf("upstream got path %q, want %q", r.URL.Path, expectedPath)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)

		flusher := w.(http.Flusher)
		// Gemini SSE format: each chunk is a complete geminiResponse with usage metadata
		chunks := []string{
			// First chunk: initial content with usage metadata
			`data: {"candidates":[{"content":{"parts":[{"text":"Hello"}]}}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":1,"totalTokenCount":11},"modelVersion":"gemini-pro"}

`,
			// Second chunk: more content
			`data: {"candidates":[{"content":{"parts":[{"text":" there!"}]}}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":3,"totalTokenCount":13},"modelVersion":"gemini-pro"}

`,
		}
		for _, chunk := range chunks {
			fmt.Fprint(w, chunk)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	// Point the Gemini provider at our fake upstream
	origTarget := providers.Registry["/gemini"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/gemini"].Target = target
	defer func() { providers.Registry["/gemini"].Target = origTarget }()

	handler, walDir := newTestHandler(t)

	// Gemini request body - identical for streaming and non-streaming
	body := `{"contents":[{"parts":[{"text":"hi"}]}]}`

	// The KEY: URL path contains :streamGenerateContent
	req := httptest.NewRequest("POST", "/gemini/v1beta/models/gemini-pro:streamGenerateContent", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("X-Project", "gemini-stream-test")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	respBody, _ := io.ReadAll(resp.Body)
	respStr := string(respBody)

	// Content chunks should be forwarded
	if !strings.Contains(respStr, `"Hello"`) {
		t.Error("content chunk was not forwarded to client")
	}

	// Verify WAL
	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(walRecords))
	}

	wr := walRecords[0]
	if wr.Project != "gemini-stream-test" {
		t.Errorf("wal project = %q", wr.Project)
	}

	// This is the critical assertion: the request should be marked as streaming
	if !wr.Stream {
		t.Error("wal Stream = false, want true (Gemini streamGenerateContent should be detected as streaming)")
	}

	// Usage should be extracted from the SSE events (last chunk has cumulative usage)
	if wr.InputTokens != 10 {
		t.Errorf("wal input_tokens = %d, want 10", wr.InputTokens)
	}
	if wr.OutputTokens != 3 {
		t.Errorf("wal output_tokens = %d, want 3", wr.OutputTokens)
	}
	if wr.Model != "gemini-pro" {
		t.Errorf("wal model = %q, want gemini-pro", wr.Model)
	}
}

// TestHandler_NonStreamGemini verifies that requests to Gemini's generateContent
// (non-streaming) endpoint are correctly handled as non-streaming.
func TestHandler_NonStreamGemini(t *testing.T) {
	// Fake upstream Gemini server (non-streaming)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := "/v1beta/models/gemini-pro:generateContent"
		if r.URL.Path != expectedPath {
			t.Errorf("upstream got path %q, want %q", r.URL.Path, expectedPath)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{
			"candidates": [{"content": {"parts": [{"text": "Hello!"}]}}],
			"usageMetadata": {
				"promptTokenCount": 10,
				"candidatesTokenCount": 2,
				"totalTokenCount": 12
			},
			"modelVersion": "gemini-pro"
		}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/gemini"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/gemini"].Target = target
	defer func() { providers.Registry["/gemini"].Target = origTarget }()

	handler, walDir := newTestHandler(t)

	// Same body format as streaming
	body := `{"contents":[{"parts":[{"text":"hi"}]}]}`

	// The KEY: URL path contains :generateContent (non-streaming)
	req := httptest.NewRequest("POST", "/gemini/v1beta/models/gemini-pro:generateContent", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("X-Project", "gemini-nonstream-test")
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	resp := rec.Result()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Verify WAL
	handler.WAL.Close()
	time.Sleep(10 * time.Millisecond)

	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(walRecords))
	}

	wr := walRecords[0]
	if wr.Project != "gemini-nonstream-test" {
		t.Errorf("wal project = %q", wr.Project)
	}

	// Should NOT be marked as streaming
	if wr.Stream {
		t.Error("wal Stream = true, want false (Gemini generateContent should be detected as non-streaming)")
	}

	// Usage should be extracted
	if wr.InputTokens != 10 {
		t.Errorf("wal input_tokens = %d, want 10", wr.InputTokens)
	}
	if wr.OutputTokens != 2 {
		t.Errorf("wal output_tokens = %d, want 2", wr.OutputTokens)
	}
}
