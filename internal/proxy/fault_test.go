package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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

	// Should get 504 (upstream timed out)
	if rec.Code != 504 {
		t.Errorf("expected 504 on timeout, got %d", rec.Code)
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

// --- Upstream Timeout Tests ---
// These verify that hung upstreams are terminated and don't leak goroutines.

func TestFault_NonStreamBodyHang_Returns504(t *testing.T) {
	// Upstream sends headers then blocks forever on the body.
	// Without a timeout, the proxy goroutine would hang indefinitely.
	done := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "99999") // promise a big body
		w.WriteHeader(200)
		// Write a partial body then hang
		fmt.Fprint(w, `{"partial":`)
		select {
		case <-r.Context().Done():
			// proxy cancelled us — expected
		case <-done:
			// test cleanup
		}
	}))
	defer upstream.Close()
	defer close(done)

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)
	handler.NonStreamTimeout = 200 * time.Millisecond // short timeout for test

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(rec, req)
	elapsed := time.Since(start)

	if rec.Code != 504 {
		t.Errorf("expected 504 on body-read timeout, got %d", rec.Code)
	}
	if elapsed > 3*time.Second {
		t.Errorf("handler took %v — timeout did not fire promptly", elapsed)
	}
}

func TestFault_StreamIdleTimeout_TerminatesStream(t *testing.T) {
	// Upstream sends headers + one SSE event, then goes silent.
	// The idle timer should fire and terminate the stream.
	var upstreamCancelled sync.WaitGroup
	upstreamCancelled.Add(1)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)

		// Send one event
		fmt.Fprint(w, "data: {\"id\":\"c\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n")
		flusher.Flush()

		// Now go silent — wait for proxy to kill us
		select {
		case <-r.Context().Done():
			upstreamCancelled.Done()
		case <-time.After(10 * time.Second):
			upstreamCancelled.Done()
			// safety net
		}
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandler(t)
	handler.StreamIdleTimeout = 200 * time.Millisecond // short idle timeout for test

	body := `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-Project", "idle-timeout-test")
	rec := httptest.NewRecorder()

	start := time.Now()
	handler.ServeHTTP(rec, req)
	elapsed := time.Since(start)

	// The stream should have been terminated by the idle timer, not hung forever
	if elapsed > 3*time.Second {
		t.Errorf("handler took %v — idle timeout did not fire promptly", elapsed)
	}

	// The partial content should have been forwarded before the timeout
	respBody, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(respBody), "Hi") {
		t.Error("partial content should be forwarded before idle timeout fires")
	}

	// WAL should still be written with whatever usage we had (zero in this case)
	handler.WAL.Close()
	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected WAL record after idle timeout, got %d", len(walRecords))
	}
	if walRecords[0].Project != "idle-timeout-test" {
		t.Errorf("WAL project = %q, want idle-timeout-test", walRecords[0].Project)
	}

	// Upstream should have been cancelled (connection closed)
	upstreamCancelled.Wait()
}

func TestFault_StreamIdleTimeout_ResetsOnActivity(t *testing.T) {
	// Upstream sends events slower than the idle timeout but never stops.
	// The idle timer should keep resetting and the stream should complete normally.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)

		// Send 5 events, each within the idle timeout
		for i := 0; i < 5; i++ {
			time.Sleep(50 * time.Millisecond) // well within 300ms idle timeout
			fmt.Fprintf(w, "data: {\"id\":\"c\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"%d\"}}]}\n\n", i)
			flusher.Flush()
		}
		// Send usage + DONE
		fmt.Fprint(w, "data: {\"id\":\"c\",\"model\":\"gpt-4o-mini\",\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"total_tokens\":15},\"choices\":[]}\n\n")
		flusher.Flush()
		fmt.Fprint(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandler(t)
	handler.StreamIdleTimeout = 300 * time.Millisecond // total stream > 250ms, but each gap < 300ms

	body := `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Stream should complete normally — idle timer should NOT have fired
	respBody, _ := io.ReadAll(rec.Result().Body)
	if !strings.Contains(string(respBody), "DONE") {
		t.Error("stream should complete normally when events arrive within idle timeout")
	}

	// WAL should have the usage from the completed stream
	handler.WAL.Close()
	walRecords := readWALRecords(t, walDir)
	if len(walRecords) != 1 {
		t.Fatalf("expected 1 WAL record, got %d", len(walRecords))
	}
	if walRecords[0].InputTokens != 10 {
		t.Errorf("WAL input_tokens = %d, want 10", walRecords[0].InputTokens)
	}
	if walRecords[0].OutputTokens != 5 {
		t.Errorf("WAL output_tokens = %d, want 5", walRecords[0].OutputTokens)
	}
}

// --- Load Shedding Tests ---
// These verify concurrency limits, backpressure, and response body caps.

func TestFault_LoadShedding_Returns503WhenFull(t *testing.T) {
	// When all inflight slots are occupied, new requests get 503 + Retry-After.
	done := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-done:
		}
	}))

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)
	handler.Inflight = make(chan struct{}, 1) // capacity of 1

	// Fill the single slot with a blocking request
	entered := make(chan struct{})
	goroutineDone := make(chan struct{})
	go func() {
		defer close(goroutineDone)
		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
		rec := httptest.NewRecorder()
		close(entered)
		handler.ServeHTTP(rec, req)
	}()
	<-entered
	// Give the goroutine a moment to acquire the semaphore
	time.Sleep(50 * time.Millisecond)

	// Now send a second request — should be shed immediately
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 503 {
		t.Errorf("expected 503 when at capacity, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "5" {
		t.Errorf("expected Retry-After: 5, got %q", rec.Header().Get("Retry-After"))
	}

	// Clean up: unblock the upstream, wait for the goroutine, close WAL, close server
	close(done)
	<-goroutineDone
	handler.WAL.Close()
	upstream.Close()
}

func TestFault_LoadShedding_InflightReleasedOnCompletion(t *testing.T) {
	// After a request completes, its inflight slot is released so the next
	// request can proceed (no permanent slot leak).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"id":"c","model":"gpt-4o","usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8},"choices":[{"message":{"content":"hi"}}]}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)
	handler.Inflight = make(chan struct{}, 1) // capacity of 1

	// First request: should succeed and release its slot
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req1 := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != 200 {
		t.Fatalf("first request failed with %d", rec1.Code)
	}

	// Second request: should also succeed (slot was released)
	req2 := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != 200 {
		t.Errorf("second request should succeed after first completes, got %d", rec2.Code)
	}
}

func TestFault_ResponseBodyCap_Returns502(t *testing.T) {
	// When upstream returns a response body larger than the cap, the proxy
	// should return 502 instead of buffering an unbounded body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		// Write a body larger than the cap
		w.Write(bytes.Repeat([]byte("x"), 1024))
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)
	handler.MaxResponseBody = 512 // tiny cap for testing

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 502 {
		t.Errorf("expected 502 for oversized response, got %d", rec.Code)
	}
}

func TestFault_ResponseBodyCap_StreamFallback(t *testing.T) {
	// When a streaming request gets a non-SSE response that exceeds the body
	// cap, it should also be rejected with 502.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json") // not SSE
		w.WriteHeader(400)
		w.Write(bytes.Repeat([]byte("e"), 2048))
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, _ := newTestHandler(t)
	handler.MaxResponseBody = 512

	body := `{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != 502 {
		t.Errorf("expected 502 for oversized non-SSE response in stream path, got %d", rec.Code)
	}
}
