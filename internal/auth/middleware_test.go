package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeStore struct {
	keys map[string]KeyRecord
	err  error
}

func (s fakeStore) LookupAPIKey(_ context.Context, rawKey string) (KeyRecord, error) {
	if s.err != nil {
		return KeyRecord{}, s.err
	}
	rec, ok := s.keys[rawKey]
	if !ok {
		return KeyRecord{}, ErrInvalidKey
	}
	return rec, nil
}

func authHandler(opts Options) http.Handler {
	return Middleware(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		project, _ := ProjectFromContext(r.Context())
		w.Header().Set("X-Test-Project", project)
		w.WriteHeader(http.StatusOK)
	}))
}

func TestMiddlewareRejectsMissingKey(t *testing.T) {
	h := authHandler(testOptions())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/action/check", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareRejectsProtectedStateRoutesWithoutKey(t *testing.T) {
	h := authHandler(testOptions())
	for _, path := range []string{
		"/v1/action/check",
		"/v1/action/result",
		"/v1/tool/check",
		"/v1/tool/result",
		"/openai/v1/chat/completions",
		"/anthropic/v1/messages",
		"/gemini/v1beta/models/gemini-2.5-flash-lite:generateContent",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s status=%d want 401 body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestMiddlewareRejectsInvalidKey(t *testing.T) {
	h := authHandler(testOptions())
	req := httptest.NewRequest(http.MethodPost, "/v1/action/check", nil)
	req.Header.Set(HeaderAPIKey, "bad")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareAcceptsValidKey(t *testing.T) {
	h := authHandler(testOptions())
	req := httptest.NewRequest(http.MethodPost, "/v1/action/check", nil)
	req.Header.Set(HeaderAPIKey, "good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Test-Project"); got != "proj-a" {
		t.Fatalf("context project=%q want proj-a", got)
	}
}

func TestMiddlewareRejectsDisabledKey(t *testing.T) {
	opts := testOptions()
	opts.Store = fakeStore{keys: map[string]KeyRecord{"disabled": {Project: "proj-a", Disabled: true}}}
	h := authHandler(opts)
	req := httptest.NewRequest(http.MethodPost, "/v1/action/check", nil)
	req.Header.Set(HeaderAPIKey, "disabled")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareRejectsExpiredKey(t *testing.T) {
	expired := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	opts := testOptions()
	opts.Store = fakeStore{keys: map[string]KeyRecord{"expired": {Project: "proj-a", ExpiresAt: &expired}}}
	h := authHandler(opts)
	req := httptest.NewRequest(http.MethodPost, "/v1/action/check", nil)
	req.Header.Set(HeaderAPIKey, "expired")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareRejectsProjectMismatch(t *testing.T) {
	h := authHandler(testOptions())
	req := httptest.NewRequest(http.MethodPost, "/v1/action/check", nil)
	req.Header.Set(HeaderAPIKey, "good")
	req.Header.Set(HeaderProject, "proj-b")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareAllowsHealthEndpoints(t *testing.T) {
	h := authHandler(testOptions())
	for _, path := range []string{"/healthz", "/livez", "/readyz"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d want 200", path, rec.Code)
		}
	}
}

func TestMiddlewareProtectsMetricsByDefault(t *testing.T) {
	h := authHandler(testOptions())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareAllowsMetricsWhenPublic(t *testing.T) {
	opts := testOptions()
	opts.MetricsPublic = true
	h := authHandler(opts)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareProtectsProxyRoutes(t *testing.T) {
	h := authHandler(testOptions())
	req := httptest.NewRequest(http.MethodPost, "/openai/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareDevBypassOnlyInDev(t *testing.T) {
	opts := testOptions()
	opts.Store = nil
	opts.DevBypass = true
	opts.Environment = "prod"
	h := authHandler(opts)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/action/check", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("prod bypass status=%d want 503", rec.Code)
	}

	opts.Environment = "dev"
	h = authHandler(opts)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/action/check", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("dev bypass status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
}

// TestMiddlewareBindsKeyIdentity: the authenticated API key — not any client-supplied
// header — is the agent's identity. The middleware must expose a stable, per-key ID so
// downstream session scoping and attribution hang off something the agent cannot forge.
func TestMiddlewareBindsKeyIdentity(t *testing.T) {
	opts := testOptions()
	opts.Store = fakeStore{keys: map[string]KeyRecord{
		"good":  {Project: "proj-a"},
		"other": {Project: "proj-a"},
	}}
	h := Middleware(opts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyID, _ := KeyIDFromContext(r.Context())
		w.Header().Set("X-Test-Key-ID", keyID)
		w.WriteHeader(http.StatusOK)
	}))

	send := func(rawKey string) string {
		req := httptest.NewRequest(http.MethodPost, "/v1/action/check", nil)
		req.Header.Set(HeaderAPIKey, rawKey)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		return rec.Header().Get("X-Test-Key-ID")
	}

	first := send("good")
	if first == "" {
		t.Fatalf("authenticated request must carry a key identity")
	}
	if again := send("good"); again != first {
		t.Fatalf("key identity must be stable: %q vs %q", first, again)
	}
	if other := send("other"); other == first || other == "" {
		t.Fatalf("distinct keys must get distinct identities: %q vs %q", first, other)
	}
	if first == "good" || strings.Contains(first, "good") {
		t.Fatalf("key identity %q must not leak the raw API key", first)
	}
}

func TestMiddlewareFailsClosedWhenStoreErrors(t *testing.T) {
	opts := testOptions()
	opts.Store = fakeStore{err: errors.New("db down")}
	h := authHandler(opts)
	req := httptest.NewRequest(http.MethodPost, "/v1/action/check", nil)
	req.Header.Set(HeaderAPIKey, "good")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 body=%s", rec.Code, rec.Body.String())
	}
}

func testOptions() Options {
	return Options{
		Enabled:     true,
		Environment: "prod",
		Now:         func() time.Time { return time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC) },
		Store: fakeStore{keys: map[string]KeyRecord{
			"good": {Project: "proj-a"},
		}},
	}
}
