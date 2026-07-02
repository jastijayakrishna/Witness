package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/hubbleops/hubbleops/internal/approval"
)

func (s *server) handleRequestApproval(w http.ResponseWriter, r *http.Request) {
	if s.approvals == nil {
		writeError(w, http.StatusServiceUnavailable, "approval store is not configured")
		return
	}
	var in approval.Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	rec, created, err := s.approvals.Request(r.Context(), in)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, rec)
}

func (s *server) handleGetApproval(w http.ResponseWriter, r *http.Request) {
	if s.approvals == nil {
		writeError(w, http.StatusServiceUnavailable, "approval store is not configured")
		return
	}
	rec, err := s.approvals.Get(r.Context(), chi.URLParam(r, "approval_id"))
	if errors.Is(err, approval.ErrNotFound) {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *server) handleReviewApproval(w http.ResponseWriter, r *http.Request) {
	if s.approvals == nil {
		writeError(w, http.StatusServiceUnavailable, "approval store is not configured")
		return
	}
	var in approval.ReviewInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	in.ApprovalID = chi.URLParam(r, "approval_id")
	// When auth is enabled, the reviewer is the authenticated principal — never a name
	// from the request body — and it must be one of the action's required approvers.
	if s.authEnabled() {
		p, _ := principalFrom(r.Context())
		existing, err := s.approvals.Get(r.Context(), in.ApprovalID)
		if errors.Is(err, approval.ErrNotFound) {
			writeError(w, http.StatusNotFound, "approval not found")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !authorizedApprover(p, existing.RequiredApprovers) {
			writeError(w, http.StatusForbidden, "principal is not an authorized approver for this action")
			return
		}
		in.Reviewer = p.Identity
		in.Source = "gate-auth"
	}
	rec, err := s.approvals.Review(r.Context(), in)
	if errors.Is(err, approval.ErrInvalidReview) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if errors.Is(err, approval.ErrNotFound) {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Flip the PR's GitHub check to reflect the decision (approved -> success). The approval
	// is already recorded; a re-issue failure is surfaced so the operator can retry.
	if err := s.reissueCheckRun(r.Context(), rec); err != nil {
		writeError(w, http.StatusBadGateway, "approval recorded but failed to update GitHub check: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}
