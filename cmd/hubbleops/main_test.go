package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestSubmitDecisionReviewPostsReview(t *testing.T) {
	var gotPath, gotProject, gotAPIKey string
	var gotBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotProject = r.Header.Get("X-Project")
		gotAPIKey = r.Header.Get("X-HubbleOps-API-Key")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision_id":"dec_1","label":"true_positive","reviewer_source":"api","reviewer_role":"sre","notes_fingerprint":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","notes_stored_raw":false,"repeated_review_behavior":"append_history","reviewed_at":"2026-06-06T00:00:00Z"}`))
	}))
	defer srv.Close()

	result, err := submitDecisionReview(context.Background(), reviewDecisionConfig{
		BaseURL:    srv.URL,
		Project:    "proj-a",
		APIKey:     "hubbleops_live_test",
		DecisionID: "dec_1",
		Label:      "true_positive",
		Role:       "sre",
		Notes:      "looks correct",
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("submit review: %v", err)
	}
	if gotPath != "/v1/decisions/dec_1/review" {
		t.Fatalf("path=%q", gotPath)
	}
	if gotProject != "proj-a" || gotAPIKey != "hubbleops_live_test" {
		t.Fatalf("headers project=%q api_key=%q", gotProject, gotAPIKey)
	}
	if gotBody["label"] != "true_positive" || gotBody["reviewer_role"] != "sre" || gotBody["notes"] != "looks correct" {
		t.Fatalf("body=%v", gotBody)
	}
	if result.DecisionID != "dec_1" || result.RepeatedReviewBehavior != "append_history" {
		t.Fatalf("result=%+v", result)
	}
}

func TestSubmitDecisionReviewRequiresDecisionAndLabel(t *testing.T) {
	_, err := submitDecisionReview(context.Background(), reviewDecisionConfig{BaseURL: "http://127.0.0.1", Label: "true_positive", Timeout: time.Second})
	if err == nil {
		t.Fatalf("missing decision succeeded")
	}
	_, err = submitDecisionReview(context.Background(), reviewDecisionConfig{BaseURL: "http://127.0.0.1", DecisionID: "dec_1", Timeout: time.Second})
	if err == nil {
		t.Fatalf("missing label succeeded")
	}
}

func TestParseExportSince(t *testing.T) {
	got, err := parseExportSince("2026-01-01")
	if err != nil {
		t.Fatalf("parse since: %v", err)
	}
	if got.Format(time.RFC3339) != "2026-01-01T00:00:00Z" {
		t.Fatalf("since=%s", got.Format(time.RFC3339))
	}
	if _, err := parseExportSince("01-01-2026"); err == nil {
		t.Fatalf("invalid date parsed")
	}
}

func TestCreateExportOutputUsesRestrictedFileMode(t *testing.T) {
	path := t.TempDir() + string(os.PathSeparator) + "outcomes.jsonl"
	w, closeFn, err := createExportOutput(path)
	if err != nil {
		t.Fatalf("create output: %v", err)
	}
	if _, err := w.Write([]byte("{}\n")); err != nil {
		t.Fatalf("write output: %v", err)
	}
	if err := closeFn(); err != nil {
		t.Fatalf("close output: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		got := info.Mode().Perm()
		t.Fatalf("mode=%#o want 0600", got)
	}
}
