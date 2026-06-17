package doctor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRunDoctorHappyPath(t *testing.T) {
	var sawAPIKey bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-HubbleOps-API-Key") == "test-key" {
			sawAPIKey = true
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/livez":
			_, _ = w.Write([]byte(`{"status":"alive"}`))
		case "/readyz":
			_, _ = w.Write([]byte(`{"status":"healthy","postgres":"ok","redis":"ok","wal":"ok"}`))
		case "/v1/action/check", "/v1/action/result":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"action":           "allow",
				"would_action":     "none",
				"confidence":       0,
				"reason":           "ok",
				"detector_version": "test",
				"receipt": map[string]any{
					"signature": "hubbleopsreceipt_v1.test",
					"key_id":    "test-key-id",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	report := Run(context.Background(), Config{
		BaseURL: srv.URL,
		Project: "proj",
		APIKey:  "test-key",
		Timeout: time.Second,
	})
	if !report.OK() {
		t.Fatalf("report not ok: %+v", report)
	}
	if len(report.Checks) != 10 {
		t.Fatalf("checks=%d want 10", len(report.Checks))
	}
	if !sawAPIKey {
		t.Fatalf("doctor did not send API key header")
	}
}

func TestRunDoctorRejectsInvalidBaseURL(t *testing.T) {
	report := Run(context.Background(), Config{BaseURL: "localhost:8080"})
	if report.OK() {
		t.Fatalf("report unexpectedly ok: %+v", report)
	}
	if len(report.Checks) != 1 || report.Checks[0].Name != "base_url" {
		t.Fatalf("checks=%+v want only base_url failure", report.Checks)
	}
}

func TestRunDoctorRejectsRemoteHTTP(t *testing.T) {
	report := Run(context.Background(), Config{BaseURL: "http://hubbleops.example.com"})
	if report.OK() {
		t.Fatalf("report unexpectedly ok: %+v", report)
	}
	if len(report.Checks) != 1 || report.Checks[0].Name != "base_url" {
		t.Fatalf("checks=%+v want only base_url failure", report.Checks)
	}
}

func TestRunDoctorFailsWhenToolCheckBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/livez":
			_, _ = w.Write([]byte(`{"status":"alive"}`))
		case "/readyz":
			_, _ = w.Write([]byte(`{"status":"healthy","postgres":"ok","redis":"ok","wal":"ok"}`))
		case "/v1/action/check":
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"action":"block","reason":"loop"}`))
		case "/v1/action/result":
			_, _ = w.Write([]byte(`{"action":"allow","reason":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	report := Run(context.Background(), Config{BaseURL: srv.URL, Timeout: time.Second})
	if report.OK() {
		t.Fatalf("report unexpectedly ok: %+v", report)
	}
}

func TestRunDoctorFailsWhenReadyzMissingComponentStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/livez":
			_, _ = w.Write([]byte(`{"status":"alive"}`))
		case "/readyz":
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
		case "/v1/action/check", "/v1/action/result":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"action": "allow",
				"receipt": map[string]any{
					"signature": "hubbleopsreceipt_v1.test",
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	report := Run(context.Background(), Config{BaseURL: srv.URL, Timeout: time.Second})
	if report.OK() {
		t.Fatalf("report unexpectedly ok: %+v", report)
	}
	var sawPostgresFailure bool
	for _, check := range report.Checks {
		if check.Name == "postgres_reachable" && !check.OK {
			sawPostgresFailure = true
		}
	}
	if !sawPostgresFailure {
		t.Fatalf("checks=%+v did not include postgres component failure", report.Checks)
	}
}
