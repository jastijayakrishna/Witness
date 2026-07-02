package approval

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/action"
	"github.com/hubbleops/hubbleops/internal/privacy"
)

func TestFileStoreRequestReviewAndPrivacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	store := NewFileStore(path)
	rawEmail := "customer@example.com"
	req := Request{
		Project:           "acme/" + rawEmail,
		SessionID:         "sess:" + rawEmail,
		DecisionID:        "dec_abc123",
		ReceiptID:         "dec_abc123",
		Action:            "github.pull_request",
		TargetFingerprint: rawEmail,
		RequiredApprovers: []string{"owner@example.com", "@sre/team"},
		Reason:            "review " + rawEmail,
		RiskScore:         80,
		RequestedBy:       "agent:" + rawEmail,
		Source:            "preflight",
		RequestedAt:       time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC),
	}
	rec, created, err := store.Request(context.Background(), req)
	if err != nil {
		t.Fatalf("request approval: %v", err)
	}
	if !created || rec.Status != StatusPending {
		t.Fatalf("created=%t rec=%+v", created, rec)
	}
	again, created, err := store.Request(context.Background(), req)
	if err != nil {
		t.Fatalf("request approval again: %v", err)
	}
	if created || again.ApprovalID != rec.ApprovalID {
		t.Fatalf("approval request was not idempotent: created=%t again=%+v", created, again)
	}

	reviewed, err := store.Review(context.Background(), ReviewInput{
		ApprovalID: rec.ApprovalID,
		Reviewer:   rawEmail,
		Source:     "api",
		Decision:   "approved",
		Comment:    "approved for " + rawEmail,
	})
	if err != nil {
		t.Fatalf("review approval: %v", err)
	}
	if reviewed.Status != StatusApproved || reviewed.ReviewerSource != "api" || reviewed.ReviewedAt.IsZero() {
		t.Fatalf("reviewed=%+v", reviewed)
	}
	if reviewed.ReviewerFingerprint != privacy.FingerprintString(rawEmail) {
		t.Fatalf("reviewer fingerprint=%q", reviewed.ReviewerFingerprint)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read approvals: %v", err)
	}
	if strings.Contains(string(data), rawEmail) || strings.Contains(string(data), "approved for") {
		t.Fatalf("approval store leaked raw sensitive text: %s", string(data))
	}
	if !strings.Contains(string(data), "review_comment_hash") {
		t.Fatalf("review comment hash missing: %s", string(data))
	}
}

func TestReviewRequiresReviewerSourceAndDecision(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	rec, _, err := store.Request(context.Background(), Request{
		Project:    "acme",
		SessionID:  "sess",
		DecisionID: "dec_123",
		ReceiptID:  "dec_123",
		Action:     "deploy.release",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := store.Review(context.Background(), ReviewInput{ApprovalID: rec.ApprovalID, Decision: "approved"}); err != ErrInvalidReview {
		t.Fatalf("err=%v want ErrInvalidReview", err)
	}
}

func TestFileStoreCorruptJSONReturnsCleanError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approvals.json")
	if err := os.WriteFile(path, []byte(`{"approvals":`), 0600); err != nil {
		t.Fatalf("write corrupt store: %v", err)
	}
	_, _, err := NewFileStore(path).Request(context.Background(), Request{
		Project:    "acme",
		SessionID:  "sess",
		DecisionID: "dec_123",
		ReceiptID:  "dec_123",
		Action:     "deploy.release",
	})
	if err == nil {
		t.Fatalf("expected corrupt approval store error")
	}
}

func TestReviewIsIdempotentAfterFirstDecision(t *testing.T) {
	store := NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	rec, _, err := store.Request(context.Background(), Request{
		Project:    "acme",
		SessionID:  "sess",
		DecisionID: "dec_123",
		ReceiptID:  "dec_123",
		Action:     "deploy.release",
	})
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	first, err := store.Review(context.Background(), ReviewInput{
		ApprovalID: rec.ApprovalID,
		Reviewer:   "sre",
		Source:     "api",
		Decision:   "approved",
	})
	if err != nil {
		t.Fatalf("first review: %v", err)
	}
	second, err := store.Review(context.Background(), ReviewInput{
		ApprovalID: rec.ApprovalID,
		Reviewer:   "security",
		Source:     "api",
		Decision:   "rejected",
	})
	if err != nil {
		t.Fatalf("second review: %v", err)
	}
	if second.Status != StatusApproved || second.Reviewer != first.Reviewer || !second.ReviewedAt.Equal(first.ReviewedAt) {
		t.Fatalf("review was not idempotent: first=%+v second=%+v", first, second)
	}
}

func TestApplyDecisionWritesRejectedApprovalEvidence(t *testing.T) {
	decision := action.Decision{
		Decision:          action.DecisionRequireApproval,
		Reason:            "risky engineering action requires review",
		RiskScore:         80,
		RiskClass:         action.RiskHigh,
		RequiredApprovers: []string{"owner"},
		Evidence:          []string{"github_linked_ticket=missing"},
	}
	rec := Record{
		ApprovalID:          "appr_123",
		Status:              StatusRejected,
		ReviewerFingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		ReviewerSource:      "api",
	}
	got := ApplyDecision(decision, rec)
	if got.Decision != action.DecisionBlock || got.RiskScore < 90 || len(got.RequiredApprovers) != 0 {
		t.Fatalf("decision=%+v", got)
	}
	if !strings.Contains(strings.Join(got.Evidence, " "), "approval_status=rejected") {
		t.Fatalf("evidence=%v", got.Evidence)
	}
}

func TestApplyDecisionWritesApprovalEvidence(t *testing.T) {
	decision := action.Decision{
		Decision:          action.DecisionRequireApproval,
		Reason:            "risky engineering action requires review",
		RiskScore:         80,
		RiskClass:         action.RiskHigh,
		RequiredApprovers: []string{"owner"},
		Evidence:          []string{"github_linked_ticket=missing"},
	}
	rec := Record{
		ApprovalID:          "appr_123",
		Status:              StatusApproved,
		ReviewerFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ReviewerSource:      "api",
	}
	got := ApplyDecision(decision, rec)
	if got.Decision != action.DecisionAllow || len(got.RequiredApprovers) != 0 {
		t.Fatalf("decision=%+v", got)
	}
	if len(got.Approvals) != 1 || got.Approvals[0] != rec.ReviewerFingerprint {
		t.Fatalf("approvals=%v", got.Approvals)
	}
	if !strings.Contains(strings.Join(got.Evidence, " "), "approval_status=approved") {
		t.Fatalf("evidence=%v", got.Evidence)
	}
}

func TestSlackNotifierSendsPrivacySafePayload(t *testing.T) {
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode slack body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := SlackNotifier{WebhookURL: srv.URL, Client: srv.Client()}.NotifyApprovalRequested(context.Background(), Record{
		ApprovalID:        "appr_123",
		DecisionID:        "dec_123",
		Action:            "github.pull_request",
		RiskScore:         80,
		RequiredApprovers: []string{fingerprintMarker("owner@example.com")},
	})
	if err != nil {
		t.Fatalf("notify: %v", err)
	}
	payload := body["text"]
	if strings.Contains(payload, "owner@example.com") {
		t.Fatalf("slack payload leaked raw approver: %s", payload)
	}
	if !strings.Contains(payload, "appr_123") || !strings.Contains(payload, "dec_123") {
		t.Fatalf("slack payload missing approval context: %s", payload)
	}
}
