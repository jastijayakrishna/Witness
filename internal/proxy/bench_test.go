package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/witness-proxy/witness-proxy/internal/providers"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

func BenchmarkHandler_NonStream(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		fmt.Fprint(w, `{"id":"chatcmpl-b","model":"gpt-4o-mini","choices":[{"message":{"content":"Hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	dir := b.TempDir()
	walWriter, _ := wal.NewWriter(dir)
	defer walWriter.Close()
	handler := NewHandler(walWriter)

	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-bench")
		req.Header.Set("X-Project", "bench")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkHandler_Stream(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		flusher := w.(http.Flusher)
		fmt.Fprint(w, "data: {\"id\":\"c\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n")
		fmt.Fprint(w, "data: {\"id\":\"c\",\"model\":\"gpt-4o-mini\",\"choices\":[],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":1,\"total_tokens\":6}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	dir := b.TempDir()
	walWriter, _ := wal.NewWriter(dir)
	defer walWriter.Close()
	handler := NewHandler(walWriter)

	body := `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sk-bench")
		req.Header.Set("X-Project", "bench")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
	}
}

func BenchmarkResolveProject_XProject(b *testing.B) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-Project", "my-project")
	req.Header.Set("Authorization", "Bearer sk-abc")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ResolveProject(req)
	}
}

func BenchmarkResolveProject_SHA256Fallback(b *testing.B) {
	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Authorization", "Bearer sk-very-long-api-key-1234567890")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		ResolveProject(req)
	}
}

func BenchmarkHashPrompt(b *testing.B) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"Write me a long essay about the history of computing and its impact on society."}]}`)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		hashPrompt(body)
	}
}

func BenchmarkCopyHeaders(b *testing.B) {
	src := http.Header{}
	src.Set("Authorization", "Bearer sk-test")
	src.Set("Content-Type", "application/json")
	src.Set("Accept", "application/json")
	src.Set("User-Agent", "OpenAI-SDK/1.0")
	src.Set("X-Custom-Header", "value")
	src.Set("X-Project", "my-project")
	src.Set("Connection", "keep-alive")

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		dst := http.Header{}
		copyHeaders(src, dst)
	}
}
