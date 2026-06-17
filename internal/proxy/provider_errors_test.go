package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/providers"
)

func TestClassifyProviderResponse(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   string
	}{
		{name: "success", status: http.StatusOK, body: `{}`, want: ""},
		{name: "quota", status: http.StatusTooManyRequests, body: `{"error":{"status":"RESOURCE_EXHAUSTED"}}`, want: loop.ResultRateLimited},
		{name: "invalid key", status: http.StatusForbidden, body: `{"error":{"message":"API key not valid"}}`, want: loop.ResultPermissionError},
		{name: "schema", status: http.StatusBadRequest, body: `{"error":{"status":"INVALID_ARGUMENT"}}`, want: loop.ResultSchemaError},
		{name: "timeout", status: http.StatusGatewayTimeout, body: `deadline exceeded`, want: loop.ResultTimeout},
		{name: "not found", status: http.StatusNotFound, body: `{}`, want: loop.ResultNotFound},
		{name: "unknown", status: http.StatusInternalServerError, body: `server exploded`, want: loop.ResultUnknownError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyProviderResponse(tt.status, []byte(tt.body))
			if got != tt.want {
				t.Fatalf("class=%q want %q", got, tt.want)
			}
		})
	}
}

func TestHandler_ProviderQuotaErrorClassifiedInWAL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":{"status":"RESOURCE_EXHAUSTED","message":"quota exceeded"}}`)
	}))
	defer upstream.Close()

	origTarget := providers.Registry["/openai"].Target
	target, _ := url.Parse(upstream.URL)
	providers.Registry["/openai"].Target = target
	defer func() { providers.Registry["/openai"].Target = origTarget }()

	handler, walDir := newTestHandler(t)
	body := `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("X-Project", "quota-project")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want 429", rec.Code)
	}

	handler.WAL.Close()
	records := readWALRecords(t, walDir)
	if len(records) != 1 {
		t.Fatalf("records=%d want 1", len(records))
	}
	if records[0].ResultClass != loop.ResultRateLimited {
		t.Fatalf("result_class=%q want %q", records[0].ResultClass, loop.ResultRateLimited)
	}
	if records[0].ImmediateOutcome != loop.ResultRateLimited {
		t.Fatalf("immediate_outcome=%q want %q", records[0].ImmediateOutcome, loop.ResultRateLimited)
	}
}
