package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hubbleops/hubbleops/internal/moatmetrics"
	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/storage"
)

const maxDecisionReviewBodySize = 32 << 10

type DecisionReviewStore interface {
	GetActionDecisionOutcomeByDecisionID(ctx context.Context, decisionID string) (storage.ActionDecisionOutcome, error)
	AddActionDecisionReview(ctx context.Context, review storage.ActionDecisionReview) (storage.ActionDecisionReview, error)
}

type decisionReviewRequest struct {
	Label        string `json:"label"`
	ReviewerRole string `json:"reviewer_role"`
	Notes        string `json:"notes,omitempty"`
}

type decisionReviewResponse struct {
	DecisionID             string    `json:"decision_id"`
	Label                  string    `json:"label"`
	ReviewerSource         string    `json:"reviewer_source"`
	ReviewerRole           string    `json:"reviewer_role"`
	NotesFingerprint       string    `json:"notes_fingerprint,omitempty"`
	NotesStoredRaw         bool      `json:"notes_stored_raw"`
	RepeatedReviewBehavior string    `json:"repeated_review_behavior"`
	ReviewedAt             time.Time `json:"reviewed_at"`
}

func (h *Handler) HandleDecisionReview(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DecisionReviewStore == nil {
		writeDecisionReviewError(w, http.StatusServiceUnavailable, "decision review store unavailable")
		return
	}
	decisionID, err := decisionIDFromReviewPath(r.URL.Path)
	if err != nil {
		writeDecisionReviewError(w, http.StatusBadRequest, err.Error())
		return
	}

	var req decisionReviewRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxDecisionReviewBodySize+1)).Decode(&req); err != nil {
		writeDecisionReviewError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	req.ReviewerRole = normalizeReviewerRole(req.ReviewerRole)
	if !isAllowedReviewLabel(req.Label) {
		writeDecisionReviewError(w, http.StatusBadRequest, "invalid review label")
		return
	}
	if !isAllowedReviewerRole(req.ReviewerRole) {
		writeDecisionReviewError(w, http.StatusBadRequest, "invalid reviewer_role")
		return
	}

	outcome, err := h.DecisionReviewStore.GetActionDecisionOutcomeByDecisionID(r.Context(), decisionID)
	if errors.Is(err, storage.ErrNotFound) {
		writeDecisionReviewError(w, http.StatusNotFound, "decision not found")
		return
	}
	if err != nil {
		writeDecisionReviewError(w, http.StatusServiceUnavailable, "decision lookup failed")
		return
	}

	project := ResolveProject(r)
	if project == "" || project == defaultProject {
		writeDecisionReviewError(w, http.StatusUnauthorized, "project authentication required")
		return
	}
	if outcome.Project != project {
		writeDecisionReviewError(w, http.StatusForbidden, "decision belongs to a different project")
		return
	}

	notes := strings.TrimSpace(req.Notes)
	review := storage.ActionDecisionReview{
		Project:          outcome.Project,
		DecisionID:       outcome.DecisionID,
		Label:            req.Label,
		ReviewerSource:   "api",
		ReviewerRole:     req.ReviewerRole,
		NotesFingerprint: privacy.FingerprintString(notes),
		ReviewedAt:       time.Now().UTC(),
	}
	if h.ReviewRawNotes && notes != "" {
		if err := privacy.RejectRawCaptureIfDisabled(privacy.CaptureModeRaw, h.RawCaptureEnabled); err != nil {
			writeDecisionReviewError(w, http.StatusBadRequest, "raw review notes require raw capture to be enabled")
			return
		}
		if redacted, ok := privacy.RedactKnownSecrets(notes).(string); ok {
			review.NotesRaw = redacted
		}
	}

	review, err = h.DecisionReviewStore.AddActionDecisionReview(r.Context(), review)
	if err != nil {
		writeDecisionReviewError(w, http.StatusBadRequest, "review rejected")
		return
	}
	moatmetrics.RecordDecisionReview(review.Label)
	h.refreshUnreviewedDecisionMetric(r.Context())

	writeDecisionReviewJSON(w, http.StatusOK, decisionReviewResponse{
		DecisionID:             review.DecisionID,
		Label:                  review.Label,
		ReviewerSource:         review.ReviewerSource,
		ReviewerRole:           review.ReviewerRole,
		NotesFingerprint:       review.NotesFingerprint,
		NotesStoredRaw:         review.NotesRaw != "",
		RepeatedReviewBehavior: "append_history",
		ReviewedAt:             review.ReviewedAt,
	})
}

func decisionIDFromReviewPath(path string) (string, error) {
	const prefix = "/v1/decisions/"
	const suffix = "/review"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return "", fmt.Errorf("invalid review path")
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	encoded = strings.Trim(encoded, "/")
	if encoded == "" {
		return "", fmt.Errorf("decision_id is required")
	}
	decisionID, err := url.PathUnescape(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid decision_id")
	}
	decisionID = strings.TrimSpace(decisionID)
	if decisionID == "" {
		return "", fmt.Errorf("decision_id is required")
	}
	return decisionID, nil
}

func normalizeReviewerRole(role string) string {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return "unknown"
	}
	return role
}

func isAllowedReviewLabel(label string) bool {
	switch label {
	case "true_positive", "false_positive", "benign_retry", "needs_review", "unsafe_but_allowed", "missed_runaway":
		return true
	default:
		return false
	}
}

func isAllowedReviewerRole(role string) bool {
	switch role {
	case "developer", "sre", "security", "founder", "unknown":
		return true
	default:
		return false
	}
}

func writeDecisionReviewError(w http.ResponseWriter, status int, message string) {
	writeDecisionReviewJSON(w, status, map[string]any{"error": message})
}

func writeDecisionReviewJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
