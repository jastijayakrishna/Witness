package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/auth"
	"github.com/hubbleops/hubbleops/internal/storage"
)

func TestDecisionReviewValidReviewAccepted(t *testing.T) {
	store := newFakeDecisionReviewStore()
	h := &Handler{DecisionReviewStore: store}
	reviewsBefore := metricValue(t, "hubbleops_decision_reviews_total", map[string]string{"label": "true_positive"})

	rec := httptest.NewRecorder()
	h.HandleDecisionReview(rec, reviewReq("dec_1", "proj-a", map[string]any{
		"label":         "true_positive",
		"reviewer_role": "sre",
		"notes":         "correct block for duplicate refund",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(store.reviews) != 1 {
		t.Fatalf("reviews=%d want 1", len(store.reviews))
	}
	got := store.reviews[0]
	if got.Project != "proj-a" || got.DecisionID != "dec_1" || got.Label != "true_positive" || got.ReviewerSource != "api" || got.ReviewerRole != "sre" {
		t.Fatalf("review=%+v", got)
	}
	if got.NotesFingerprint == "" || !strings.HasPrefix(got.NotesFingerprint, "sha256:") {
		t.Fatalf("notes fingerprint=%q", got.NotesFingerprint)
	}
	if got.NotesRaw != "" {
		t.Fatalf("raw notes stored by default: %q", got.NotesRaw)
	}
	if delta := metricValue(t, "hubbleops_decision_reviews_total", map[string]string{"label": "true_positive"}) - reviewsBefore; delta != 1 {
		t.Fatalf("decision review metric delta=%f want 1", delta)
	}
	if got := metricValue(t, "hubbleops_unreviewed_decisions_total", nil); got != 1 {
		t.Fatalf("unreviewed decisions metric=%f want 1", got)
	}
}

func TestDecisionReviewRejectsInvalidLabel(t *testing.T) {
	store := newFakeDecisionReviewStore()
	h := &Handler{DecisionReviewStore: store}

	rec := httptest.NewRecorder()
	h.HandleDecisionReview(rec, reviewReq("dec_1", "proj-a", map[string]any{
		"label":         "kind_of_ok",
		"reviewer_role": "sre",
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}
	if len(store.reviews) != 0 {
		t.Fatalf("invalid review was stored")
	}
}

func TestDecisionReviewRejectsUnknownDecision(t *testing.T) {
	store := newFakeDecisionReviewStore()
	h := &Handler{DecisionReviewStore: store}

	rec := httptest.NewRecorder()
	h.HandleDecisionReview(rec, reviewReq("missing", "proj-a", map[string]any{
		"label":         "true_positive",
		"reviewer_role": "sre",
	}))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%s", rec.Code, rec.Body.String())
	}
}

func TestDecisionReviewRejectsProjectMismatch(t *testing.T) {
	store := newFakeDecisionReviewStore()
	h := &Handler{DecisionReviewStore: store}

	rec := httptest.NewRecorder()
	h.HandleDecisionReview(rec, reviewReq("dec_other", "proj-a", map[string]any{
		"label":         "false_positive",
		"reviewer_role": "security",
	}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 body=%s", rec.Code, rec.Body.String())
	}
	if len(store.reviews) != 0 {
		t.Fatalf("mismatched project review was stored")
	}
}

func TestDecisionReviewDoesNotStoreRawNotesByDefault(t *testing.T) {
	store := newFakeDecisionReviewStore()
	h := &Handler{DecisionReviewStore: store}
	rawNote := "customer email user@example.com had card ending 4242"

	rec := httptest.NewRecorder()
	h.HandleDecisionReview(rec, reviewReq("dec_1", "proj-a", map[string]any{
		"label":         "needs_review",
		"reviewer_role": "developer",
		"notes":         rawNote,
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	got := store.reviews[0]
	if got.NotesRaw != "" {
		t.Fatalf("raw notes stored by default: %q", got.NotesRaw)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), rawNote) || strings.Contains(string(encoded), "user@example.com") {
		t.Fatalf("review leaked raw note: %s", encoded)
	}
}

func TestDecisionReviewStoresRawNotesOnlyWhenEnabled(t *testing.T) {
	store := newFakeDecisionReviewStore()
	h := &Handler{DecisionReviewStore: store, ReviewRawNotes: true, RawCaptureEnabled: true}
	rawNote := "local sanitized review note"

	rec := httptest.NewRecorder()
	h.HandleDecisionReview(rec, reviewReq("dec_1", "proj-a", map[string]any{
		"label":         "needs_review",
		"reviewer_role": "founder",
		"notes":         rawNote,
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	got := store.reviews[0]
	if got.NotesRaw != rawNote {
		t.Fatalf("notes_raw=%q want raw note", got.NotesRaw)
	}
	if got.NotesFingerprint == "" {
		t.Fatalf("notes fingerprint missing")
	}
}

func TestDecisionReviewRejectsRawNotesWhenRawCaptureDisabled(t *testing.T) {
	store := newFakeDecisionReviewStore()
	h := &Handler{DecisionReviewStore: store, ReviewRawNotes: true}

	rec := httptest.NewRecorder()
	h.HandleDecisionReview(rec, reviewReq("dec_1", "proj-a", map[string]any{
		"label":         "needs_review",
		"reviewer_role": "founder",
		"notes":         "local sanitized review note",
	}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}
	if len(store.reviews) != 0 {
		t.Fatalf("raw notes should not be stored when raw capture is disabled")
	}
}

func TestDecisionReviewRedactsKnownSecretsFromRawNotes(t *testing.T) {
	store := newFakeDecisionReviewStore()
	h := &Handler{DecisionReviewStore: store, ReviewRawNotes: true, RawCaptureEnabled: true}

	rec := httptest.NewRecorder()
	h.HandleDecisionReview(rec, reviewReq("dec_1", "proj-a", map[string]any{
		"label":         "needs_review",
		"reviewer_role": "founder",
		"notes":         "customer email customer@example.com token=secret-token",
	}))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	got := store.reviews[0]
	if strings.Contains(got.NotesRaw, "customer@example.com") || strings.Contains(got.NotesRaw, "secret-token") {
		t.Fatalf("raw notes leaked known secret: %q", got.NotesRaw)
	}
	if !strings.Contains(got.NotesRaw, "sha256:") {
		t.Fatalf("redacted raw notes should retain fingerprints: %q", got.NotesRaw)
	}
}

func TestDecisionReviewRepeatedReviewAppendsHistory(t *testing.T) {
	store := newFakeDecisionReviewStore()
	h := &Handler{DecisionReviewStore: store}

	for _, label := range []string{"needs_review", "false_positive"} {
		rec := httptest.NewRecorder()
		h.HandleDecisionReview(rec, reviewReq("dec_1", "proj-a", map[string]any{
			"label":         label,
			"reviewer_role": "sre",
		}))
		if rec.Code != http.StatusOK {
			t.Fatalf("label=%s status=%d body=%s", label, rec.Code, rec.Body.String())
		}
	}
	if len(store.reviews) != 2 {
		t.Fatalf("reviews=%d want 2 append-only history", len(store.reviews))
	}
	if store.reviews[0].Label != "needs_review" || store.reviews[1].Label != "false_positive" {
		t.Fatalf("review history=%+v", store.reviews)
	}
}

func reviewReq(decisionID, project string, body map[string]any) *http.Request {
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/decisions/"+decisionID+"/review", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Project", project)
	return req.WithContext(auth.WithProject(req.Context(), project))
}

type fakeDecisionReviewStore struct {
	outcomes map[string]storage.ActionDecisionOutcome
	reviews  []storage.ActionDecisionReview
}

func newFakeDecisionReviewStore() *fakeDecisionReviewStore {
	return &fakeDecisionReviewStore{outcomes: map[string]storage.ActionDecisionOutcome{
		"dec_1": {
			Project:       "proj-a",
			SessionID:     "session-a",
			DecisionID:    "dec_1",
			ActionName:    "refund_customer",
			ActionType:    "action_check",
			ActionRisk:    "write",
			HubbleOpsAction: "block",
		},
		"dec_other": {
			Project:       "proj-b",
			SessionID:     "session-b",
			DecisionID:    "dec_other",
			ActionName:    "send_email",
			ActionType:    "action_check",
			ActionRisk:    "write",
			HubbleOpsAction: "warn",
		},
	}}
}

func (s *fakeDecisionReviewStore) GetActionDecisionOutcomeByDecisionID(_ context.Context, decisionID string) (storage.ActionDecisionOutcome, error) {
	outcome, ok := s.outcomes[decisionID]
	if !ok {
		return storage.ActionDecisionOutcome{}, storage.ErrNotFound
	}
	return outcome, nil
}

func (s *fakeDecisionReviewStore) AddActionDecisionReview(_ context.Context, review storage.ActionDecisionReview) (storage.ActionDecisionReview, error) {
	review.ID = int64(len(s.reviews) + 1)
	if review.ReviewedAt.IsZero() {
		review.ReviewedAt = time.Now().UTC()
	}
	s.reviews = append(s.reviews, review)
	return review, nil
}

func (s *fakeDecisionReviewStore) CountUnreviewedDecisions(_ context.Context) (int, error) {
	reviewed := map[string]struct{}{}
	for _, review := range s.reviews {
		reviewed[review.Project+"|"+review.DecisionID] = struct{}{}
	}
	count := 0
	for _, outcome := range s.outcomes {
		if _, ok := reviewed[outcome.Project+"|"+outcome.DecisionID]; !ok {
			count++
		}
	}
	return count, nil
}
