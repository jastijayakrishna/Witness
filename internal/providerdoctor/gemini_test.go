package providerdoctor

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunGemini_Success(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1beta/models":
			fmt.Fprint(w, `{"models":[{"name":"models/gemini-2.5-flash-lite"}]}`)
		case r.URL.Path == "/v1beta/models/gemini-2.5-flash-lite:generateContent":
			fmt.Fprint(w, `{"modelVersion":"gemini-2.5-flash-lite","usageMetadata":{"totalTokenCount":12}}`)
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer upstream.Close()

	report := RunGemini(context.Background(), Config{
		APIKey:  "test-key",
		Model:   "gemini-2.5-flash-lite",
		BaseURL: upstream.URL,
	})
	if !report.OK() {
		t.Fatalf("report should be OK: %+v", report.Checks)
	}
	assertCheck(t, report, "models_list", true, "models_visible=1")
	assertCheck(t, report, "model_available", true, "visible")
	assertCheck(t, report, "pricing_known", true, "cost can be computed")
	assertCheck(t, report, "quota_generate_content", true, "total_tokens=12")
}

func TestRunGemini_QuotaFailureClassified(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1beta/models" {
			fmt.Fprint(w, `{"models":[{"name":"models/gemini-2.5-flash-lite"}]}`)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":{"status":"RESOURCE_EXHAUSTED","message":"quota exceeded"}}`)
	}))
	defer upstream.Close()

	report := RunGemini(context.Background(), Config{
		APIKey:  "test-key",
		Model:   "gemini-2.5-flash-lite",
		BaseURL: upstream.URL,
	})
	if report.OK() {
		t.Fatalf("report should fail on quota: %+v", report.Checks)
	}
	assertCheck(t, report, "quota_generate_content", false, "rate_limited")
}

func TestRunGemini_DeprecatedModelFails(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1beta/models":
			fmt.Fprint(w, `{"models":[{"name":"models/gemini-2.0-flash"}]}`)
		default:
			fmt.Fprint(w, `{"modelVersion":"gemini-2.0-flash","usageMetadata":{"totalTokenCount":10}}`)
		}
	}))
	defer upstream.Close()

	report := RunGemini(context.Background(), Config{
		APIKey:  "test-key",
		Model:   "gemini-2.0-flash",
		BaseURL: upstream.URL,
	})
	if report.OK() {
		t.Fatalf("deprecated model should fail report: %+v", report.Checks)
	}
	assertCheck(t, report, "model_status", false, "shut down June 1, 2026")
}

func assertCheck(t *testing.T, report Report, name string, ok bool, detailContains string) {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name != name {
			continue
		}
		if check.OK != ok {
			t.Fatalf("%s ok=%v want %v detail=%q", name, check.OK, ok, check.Detail)
		}
		if detailContains != "" && !strings.Contains(check.Detail, detailContains) {
			t.Fatalf("%s detail=%q want contains %q", name, check.Detail, detailContains)
		}
		return
	}
	t.Fatalf("missing check %s in %+v", name, report.Checks)
}
