package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/witness-proxy/witness-proxy/internal/providers"
)

// --- Fault Injection Tests ---
// These test what happens when things go wrong at the network level.

func TestFault_UpstreamClosesConnectionMidResponse(t *testing.T) {
	// Upstream writes partial response then kills the connection
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			// Fallback: just close without full response
			w.Header().Set("Content-Length", "10000")
			w.WriteHeader(200)
			fmt.Fprint(w, `{"partial":`)
			return
		}
		conn, buf, _ := hijacker.Hijack()
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"partial\":")
		buf.Flush()
		conn.Close()
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))

	rec := httptest.NewRecorder()
	// Should not panic
	handler.ServeHTTP(rec, req)

	// We accept either a 502 (if the transport caught it) or a partial 200
	// The important thing is no panic.
	t.Logf("status after upstream disconnect: %d", rec.Code)
}

func TestFault_UpstreamReturnsGarbage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		// Not valid JSON — usage extraction should fail gracefully
		fmt.Fprint(w, `THIS IS NOT JSON AT ALL \x00\xff`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Garbage body should still be passed through (the client needs the error)
	if rec.Code != 200 {
		t.Errorf("expected 200 passthrough, got %d", rec.Code)
	}
}

func TestFault_UpstreamTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than client context
		time.Sleep(5 * time.Second)
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body)).WithContext(ctx)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should get 502 (upstream failed due to context cancellation)
	if rec.Code != 502 {
		t.Errorf("expected 502 on timeout, got %d", rec.Code)
	}
}

func TestFault_StreamUpstreamClosesEarly(t *testing.T) {
	// Upstream sends some SSE events then kills connection mid-stream
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)

		// Send one content chunk
		fmt.Fprint(w, "data: {\"id\":\"c\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n")
		flusher.Flush()
		// Connection closes without [DONE] or usage chunk
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandler(t)

	body := `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-Project", "fault-stream")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should not panic. Content should be forwarded.
	respBody, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(respBody), "Hi") {
		t.Error("partial content should still be forwarded")
	}

	// WAL should still be written (with zero usage since no usage chunk arrived)
	handler.WAL.Close()
	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected WAL record even for broken stream, got %d", len(walRecords))
	}
	if walRecords[0].InputTokens != 0 {
		t.Logf("note: input_tokens = %d (expected 0 for broken stream)", walRecords[0].InputTokens)
	}
}

func TestFault_StreamMalformedSSELines(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)

		lines := []string{
			// Normal event
			"data: {\"id\":\"c\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"A\"}}]}\n\n",
			// Garbage line (not event: or data:)
			"GARBAGE LINE\n",
			// Incomplete data line followed by empty line
			"data: {\"broken json\n\n",
			// Normal DONE
			"data: [DONE]\n\n",
		}
		for _, line := range lines {
			fmt.Fprint(w, line)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)

	body := `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()

	// Must not panic
	handler.ServeHTTP(rec, req)

	respBody, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(respBody), "DONE") {
		t.Error("[DONE] should still be forwarded despite malformed events")
	}
}

func TestFault_StreamNonSSEContentType(t *testing.T) {
	// Upstream returns JSON error instead of SSE (e.g., auth failure on stream request)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":{"message":"Invalid API key","type":"authentication_error"}}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should passthrough the JSON error, not try to parse as SSE
	if rec.Code != 401 {
		t.Errorf("expected 401 passthrough, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "authentication_error") {
		t.Error("error body should be passed through")
	}
}

func TestFault_UpstreamReturns500(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		fmt.Fprint(w, `{"error":{"message":"Internal server error","type":"server_error"}}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandler(t)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 500 {
		t.Errorf("expected 500 passthrough, got %d", rec.Code)
	}

	// WAL should still be written for 500s (we need to track failures)
	handler.WAL.Close()
	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected WAL record for 500 response, got %d", len(walRecords))
	}
	if walRecords[0].StatusCode != 500 {
		t.Errorf("WAL status_code = %d, want 500", walRecords[0].StatusCode)
	}
}

func TestFault_EmptyRequestBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":{"message":"Invalid request"}}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)

	// Empty body — stream detection should return false (not panic)
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(""))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should get the upstream's 400
	if rec.Code != 400 {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestFault_HugeRequestBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprintf(w, `{"model":"gpt-4o","usage":{"prompt_tokens":%d,"completion_tokens":1,"total_tokens":%d}}`, len(body)/4, len(body)/4+1)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)

	// 1MB request body
	bigContent := strings.Repeat("x", 1_000_000)
	body := fmt.Sprintf(`{"model":"gpt-4o","messages":[{"role":"user","content":"%s"}]}`, bigContent)
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
