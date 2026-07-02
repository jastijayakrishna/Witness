package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/hubbleops/hubbleops/internal/action"
	"github.com/hubbleops/hubbleops/internal/actionreceipt"
	"github.com/hubbleops/hubbleops/internal/approval"
	"github.com/hubbleops/hubbleops/internal/config"
	"github.com/hubbleops/hubbleops/internal/gate"
	"github.com/hubbleops/hubbleops/internal/githubapp"
	"github.com/hubbleops/hubbleops/internal/policy"
	"github.com/hubbleops/hubbleops/internal/preflight"
	pregithub "github.com/hubbleops/hubbleops/internal/preflight/github"
	premigration "github.com/hubbleops/hubbleops/internal/preflight/migration"
	preterraform "github.com/hubbleops/hubbleops/internal/preflight/terraform"
	"github.com/hubbleops/hubbleops/internal/privacy"
)

// maxScannedFiles caps how many changed files the PR gate fetches and analyzes, so a
// pathological PR cannot turn one webhook into thousands of content fetches.
const maxScannedFiles = 50

type githubClient interface {
	InstallationToken(ctx context.Context, installationID int64) (string, error)
	ListPullRequestFiles(ctx context.Context, token, owner, repo string, number int) ([]pregithub.ChangedFile, error)
	GetCodeOwners(ctx context.Context, token, owner, repo, ref string) (string, error)
	GetFileContent(ctx context.Context, token, owner, repo, path, ref string) (string, error)
	GetTerraformPlan(ctx context.Context, token, owner, repo string, number int, headSHA string) (string, bool, error)
	CreateCheckRun(ctx context.Context, token string, run githubapp.CheckRun) (int64, error)
	PatchCheckRun(ctx context.Context, token string, run githubapp.CheckRun) error
}

type server struct {
	policy        *policy.Policy
	receiptOpts   actionreceipt.Options
	receiptWriter *actionreceipt.Writer
	receiptConfig config.ReceiptConfig
	approvals     *approval.Service
	github        githubClient
	auth          *gateAuth
	webhookSecret string
	checkName     string
}

func (s *server) routes() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	r.Post("/v1/preflight", s.requireAuth(s.handlePreflight))
	r.Post("/v1/approvals/request", s.requireAuth(s.handleRequestApproval))
	r.Get("/v1/approvals/{approval_id}", s.requireAuth(s.handleGetApproval))
	r.Post("/v1/approvals/{approval_id}/review", s.requireAuth(s.handleReviewApproval))
	r.Get("/v1/receipts/{decision_id}", s.requireAuth(s.handleGetReceipt))
	r.Post("/github/webhook", s.handleGitHubWebhook)
	return r
}

func (s *server) close() error {
	if s == nil || s.receiptWriter == nil {
		return nil
	}
	return s.receiptWriter.Close()
}

type preflightRequest struct {
	action.Request
	Findings []preflight.Finding `json:"findings,omitempty"`
}

type preflightResponse struct {
	action.Decision
	Findings        []preflight.Finding `json:"findings,omitempty"`
	ApprovalRequest *approval.Record    `json:"approval_request,omitempty"`
}

func (s *server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	var in preflightRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req := in.Request
	if err := validateActionRequest(req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Environment = normalizeEnvironment(req.Environment)
	req.CaptureMode = privacy.CaptureModeFingerprint
	decision := gate.Decide(req, in.Findings, s.policy)
	written, approvalRequest, err := s.writeDecisionReceipt(r.Context(), req, decision, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "write preflight receipt: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, preflightResponse{
		Decision:        action.SanitizeForOutput(written),
		Findings:        preflight.SanitizeFindingsForOutput(in.Findings),
		ApprovalRequest: approvalRequest,
	})
}

func (s *server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := readLimited(r, 1<<20)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Fail closed: an unconfigured webhook secret means we cannot authenticate GitHub, so
	// we must not process the payload (an empty secret otherwise accepts any caller).
	if strings.TrimSpace(s.webhookSecret) == "" {
		writeError(w, http.StatusServiceUnavailable, "github webhook secret is not configured")
		return
	}
	if !githubapp.VerifyWebhook(s.webhookSecret, body, r.Header.Get("X-Hub-Signature-256")) {
		writeError(w, http.StatusUnauthorized, "invalid GitHub webhook signature")
		return
	}
	if r.Header.Get("X-GitHub-Event") != "pull_request" {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored"})
		return
	}
	var payload pullRequestPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid pull_request payload")
		return
	}
	if !shouldProcessPullRequestAction(payload.Action) {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "ignored"})
		return
	}
	if s.github == nil {
		writeError(w, http.StatusServiceUnavailable, "github app client is not configured")
		return
	}
	result, err := s.evaluatePullRequest(r.Context(), payload)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *server) evaluatePullRequest(ctx context.Context, payload pullRequestPayload) (preflightResponse, error) {
	owner := firstNonEmpty(payload.Repository.Owner.Login, strings.Split(payload.Repository.FullName, "/")[0])
	repo := firstNonEmpty(payload.Repository.Name, repoName(payload.Repository.FullName))
	number := payload.PullRequest.Number
	if number == 0 {
		number = payload.Number
	}
	token, err := s.github.InstallationToken(ctx, payload.Installation.ID)
	if err != nil {
		return preflightResponse{}, err
	}
	files, err := s.github.ListPullRequestFiles(ctx, token, owner, repo, number)
	if err != nil {
		return preflightResponse{}, err
	}
	codeowners, err := s.github.GetCodeOwners(ctx, token, owner, repo, payload.PullRequest.Base.Ref)
	if err != nil {
		return preflightResponse{}, err
	}
	pr := pregithub.PullRequest{
		Owner:        owner,
		Repo:         repo,
		Number:       number,
		Title:        payload.PullRequest.Title,
		Body:         payload.PullRequest.Body,
		HeadRef:      payload.PullRequest.Head.Ref,
		BaseRef:      payload.PullRequest.Base.Ref,
		Author:       payload.PullRequest.User.Login,
		ChangedFiles: files,
		CodeOwners:   codeowners,
	}
	req := githubActionRequest(payload, pr)
	findings := pregithub.Scan(pr)
	contentFindings, err := s.scanChangedFileContents(ctx, token, owner, repo, payload.PullRequest.Head.SHA, files)
	if err != nil {
		return preflightResponse{}, err
	}
	findings = append(findings, contentFindings...)
	findings = append(findings, s.scanTerraformPlan(ctx, token, owner, repo, number, payload.PullRequest.Head.SHA, files)...)
	decision := gate.Decide(req, findings, s.policy)
	githubCheck := &approval.GitHubCheck{
		InstallationID: payload.Installation.ID,
		Owner:          owner,
		Repo:           repo,
		HeadSHA:        payload.PullRequest.Head.SHA,
		CheckName:      firstNonEmpty(s.checkName, "HubbleOps Action Firewall"),
	}
	written, approvalRequest, err := s.writeDecisionReceipt(ctx, req, decision, githubCheck)
	if err != nil {
		return preflightResponse{}, fmt.Errorf("write preflight receipt: %w", err)
	}
	checkRunID, err := s.github.CreateCheckRun(ctx, token, githubapp.CheckRun{
		Owner:      owner,
		Repo:       repo,
		HeadSHA:    payload.PullRequest.Head.SHA,
		Name:       firstNonEmpty(s.checkName, "HubbleOps Action Firewall"),
		Conclusion: githubapp.Conclusion(written.Decision),
		Title:      "HubbleOps: " + written.Decision,
		Summary:    githubapp.Summary(written.Decision, written.Reason, written.RiskScore, written.ReceiptID),
	})
	if err != nil {
		return preflightResponse{}, err
	}
	if approvalRequest != nil && checkRunID > 0 && s.approvals != nil {
		updated, err := s.approvals.SetGitHubCheckRunID(ctx, approvalRequest.ApprovalID, checkRunID)
		if err != nil {
			return preflightResponse{}, fmt.Errorf("record github check_run_id: %w", err)
		}
		approvalRequest = &updated
	}
	return preflightResponse{
		Decision:        action.SanitizeForOutput(written),
		Findings:        preflight.SanitizeFindingsForOutput(findings),
		ApprovalRequest: approvalRequest,
	}, nil
}

// scanChangedFileContents runs the content detectors on changed migration files so the PR
// gate sees what a file *does*, not just where it lives.
func (s *server) scanChangedFileContents(ctx context.Context, token, owner, repo, ref string, files []pregithub.ChangedFile) ([]preflight.Finding, error) {
	var findings []preflight.Finding
	scanned := 0
	for _, file := range files {
		if strings.EqualFold(strings.TrimSpace(file.Status), "removed") {
			continue
		}
		if !strings.EqualFold(filepath.Ext(file.Filename), ".sql") {
			continue
		}
		if scanned >= maxScannedFiles {
			break
		}
		scanned++
		content, err := s.github.GetFileContent(ctx, token, owner, repo, file.Filename, ref)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", file.Filename, err)
		}
		if strings.TrimSpace(content) == "" {
			continue
		}
		findings = append(findings, premigration.ScanContent(file.Filename, content)...)
	}
	return findings, nil
}

func (s *server) scanTerraformPlan(ctx context.Context, token, owner, repo string, number int, headSHA string, files []pregithub.ChangedFile) []preflight.Finding {
	if !touchesTerraform(files) {
		return nil
	}
	plan, ok, err := s.github.GetTerraformPlan(ctx, token, owner, repo, number, headSHA)
	if err != nil {
		return []preflight.Finding{terraformPlanUnavailableFinding("unavailable")}
	}
	if !ok || strings.TrimSpace(plan) == "" {
		return []preflight.Finding{terraformPlanUnavailableFinding("missing")}
	}
	var protected []string
	if s.policy != nil {
		protected = s.policy.ProtectedResources
	}
	findings, err := preterraform.Scan(strings.NewReader(plan), preterraform.Options{ProtectedResources: protected})
	if err != nil {
		return []preflight.Finding{terraformPlanUnavailableFinding("parse_error")}
	}
	return findings
}

func touchesTerraform(files []pregithub.ChangedFile) bool {
	for _, file := range files {
		if strings.EqualFold(strings.TrimSpace(file.Status), "removed") {
			continue
		}
		path := filepath.ToSlash(strings.ToLower(strings.TrimSpace(file.Filename)))
		ext := filepath.Ext(path)
		switch {
		case path == "terragrunt.hcl" || strings.HasSuffix(path, "/terragrunt.hcl"):
			return true
		case ext == ".tf" || ext == ".tfvars":
			return true
		case strings.HasSuffix(path, ".tf.json"):
			return true
		case path == "terraform" || strings.HasPrefix(path, "terraform/") || strings.Contains(path, "/terraform/"):
			return true
		}
	}
	return false
}

func terraformPlanUnavailableFinding(status string) preflight.Finding {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		status = "missing"
	}
	return preflight.Finding{
		Source:    preflight.SourceTerraform,
		Kind:      preflight.KindTerraformPlanMissing,
		Action:    "terraform.plan",
		Target:    "terraform_plan",
		RiskScore: 75,
		RiskClass: action.RiskClass(75),
		Evidence: []string{
			"source=terraform",
			"terraform_touched=true",
			"terraform_plan=" + status,
		},
		ChangeTags: []string{"terraform:plan_" + status},
	}
}

// reissueCheckRun updates the PR's GitHub check after an approval is decided. It first
// writes the post-approval receipt, then patches the original check run so branch
// protection sees the transition from action_required to success/failure.
func (s *server) reissueCheckRun(ctx context.Context, rec approval.Record) error {
	if s.github == nil || rec.GitHub == nil {
		return nil
	}
	if rec.GitHub.CheckRunID <= 0 {
		return fmt.Errorf("github check_run_id is missing for approval %s", rec.ApprovalID)
	}
	var conclusion string
	switch rec.Status {
	case approval.StatusApproved:
		conclusion = "success"
	case approval.StatusRejected:
		conclusion = "failure"
	default:
		return nil
	}
	written, _, err := s.writeDecisionReceipt(ctx, approvalActionRequest(rec), approvalBaseDecision(rec), nil)
	if err != nil {
		return fmt.Errorf("write post-approval receipt: %w", err)
	}
	token, err := s.github.InstallationToken(ctx, rec.GitHub.InstallationID)
	if err != nil {
		return err
	}
	summary := githubapp.Summary(written.Decision, written.Reason, written.RiskScore, written.ReceiptID)
	if written.ReceiptID != "" {
		summary += "\n\npost_approval_receipt_id=" + written.ReceiptID
	}
	return s.github.PatchCheckRun(ctx, token, githubapp.CheckRun{
		ID:         rec.GitHub.CheckRunID,
		Owner:      rec.GitHub.Owner,
		Repo:       rec.GitHub.Repo,
		HeadSHA:    rec.GitHub.HeadSHA,
		Name:       firstNonEmpty(rec.GitHub.CheckName, s.checkName, "HubbleOps Action Firewall"),
		Conclusion: conclusion,
		Title:      "HubbleOps: " + written.Decision,
		Summary:    summary,
	})
}

func approvalActionRequest(rec approval.Record) action.Request {
	return action.Request{
		Project:        rec.Project,
		SessionID:      rec.SessionID,
		Actor:          rec.RequestedBy,
		HumanDelegator: rec.ReviewerFingerprint,
		Action:         rec.Action,
		Target:         rec.TargetFingerprint,
		Environment:    "github",
		PolicyVersion:  action.PolicyVersion,
		CaptureMode:    privacy.CaptureModeFingerprint,
	}
}

func approvalBaseDecision(rec approval.Record) action.Decision {
	return action.Decision{
		Decision:          action.DecisionRequireApproval,
		Reason:            rec.Reason,
		RiskScore:         rec.RiskScore,
		RiskClass:         action.RiskClass(rec.RiskScore),
		RequiredApprovers: rec.RequiredApprovers,
		ReceiptID:         rec.DecisionID,
		DecisionID:        rec.DecisionID,
		PolicyVersion:     action.PolicyVersion,
		RequiresReceipt:   true,
		TargetFingerprint: rec.TargetFingerprint,
	}
}

func (s *server) writeDecisionReceipt(ctx context.Context, req action.Request, decision action.Decision, githubCheck *approval.GitHubCheck) (action.Decision, *approval.Record, error) {
	var approvalRequest *approval.Record
	if s.approvals != nil {
		rec, err := s.approvals.GetByDecision(ctx, decision.DecisionID)
		if err == nil {
			if rec.Status == approval.StatusPending {
				approvalRequest = &rec
			} else {
				decision = approval.ApplyDecision(decision, rec)
				decision = withApprovalEvidenceHashes(decision)
			}
		} else if !errors.Is(err, approval.ErrNotFound) {
			return action.Decision{}, nil, err
		}
	}
	var (
		written action.Decision
		err     error
	)
	if s.receiptWriter != nil {
		written, err = s.receiptWriter.Write(req, decision)
	} else {
		written, err = actionreceipt.Write(req, decision, s.receiptOpts)
	}
	if err != nil {
		if s.receiptConfig.EnforceWithoutReceipt {
			decision.ReceiptAttempted = true
			decision.ReceiptError = err.Error()
			return decision, nil, nil
		}
		return action.Decision{}, nil, err
	}
	if s.receiptConfig.RequireForBlock && written.Decision == action.DecisionBlock && strings.TrimSpace(written.ReceiptError) != "" {
		return action.Decision{}, nil, fmt.Errorf("block receipt required but receipt is unsafe: %s", written.ReceiptError)
	}
	if s.approvals != nil && written.Decision == action.DecisionRequireApproval {
		rec, _, err := s.approvals.Request(ctx, approval.Request{
			Project:           req.Project,
			SessionID:         req.SessionID,
			DecisionID:        written.DecisionID,
			ReceiptID:         written.ReceiptID,
			Action:            req.Action,
			TargetFingerprint: written.TargetFingerprint,
			RequiredApprovers: written.RequiredApprovers,
			Reason:            written.Reason,
			RiskScore:         written.RiskScore,
			RequestedBy:       req.Actor,
			Source:            "preflight",
			GitHub:            githubCheck,
		})
		if err != nil {
			return action.Decision{}, nil, err
		}
		approvalRequest = &rec
	}
	return written, approvalRequest, nil
}

func withApprovalEvidenceHashes(decision action.Decision) action.Decision {
	seen := map[string]struct{}{}
	for _, hash := range decision.EvidenceHashes {
		if strings.TrimSpace(hash) != "" {
			seen[hash] = struct{}{}
		}
	}
	for _, item := range decision.Evidence {
		fp := privacy.FingerprintString(item)
		if fp == "" {
			continue
		}
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		decision.EvidenceHashes = append(decision.EvidenceHashes, fp)
	}
	sort.Strings(decision.EvidenceHashes)
	return decision
}

func githubActionRequest(payload pullRequestPayload, pr pregithub.PullRequest) action.Request {
	target := strings.Trim(pr.Owner+"/"+pr.Repo, "/")
	if pr.Number > 0 {
		target = fmt.Sprintf("%s#%d", target, pr.Number)
	}
	actor := "github:" + firstNonEmpty(payload.Sender.Login, pr.Author, "unknown")
	sha := payload.PullRequest.Head.SHA
	return action.Request{
		Project:        strings.Trim(pr.Owner+"/"+pr.Repo, "/"),
		SessionID:      fmt.Sprintf("github:pr:%d:%s", pr.Number, firstNonEmpty(sha, "unknown")),
		Actor:          actor,
		HumanDelegator: firstNonEmpty(pr.Author, payload.Sender.Login),
		Action:         pregithub.ActionPullRequest,
		Target:         target,
		Intent:         pr.Title + "\n" + pr.Body,
		Environment:    normalizeEnvironment(firstNonEmpty(pr.BaseRef, "pull_request")),
		Evidence: []string{
			"github_event=pull_request",
			"github_repo_fingerprint=" + privacy.FingerprintString(pr.Owner+"/"+pr.Repo),
			fmt.Sprintf("github_pr_number=%d", pr.Number),
			"github_head_sha_fingerprint=" + privacy.FingerprintString(sha),
			"github_linked_ticket=" + linkedTicketLabel(pr),
		},
		IdempotencyKey: fmt.Sprintf("github:%s/%s:pr:%d:%s", pr.Owner, pr.Repo, pr.Number, firstNonEmpty(sha, "unknown")),
		PolicyVersion:  action.PolicyVersion,
		CaptureMode:    privacy.CaptureModeFingerprint,
	}
}

func validateActionRequest(req action.Request) error {
	if strings.TrimSpace(req.Project) == "" {
		return fmt.Errorf("project is required")
	}
	if strings.TrimSpace(req.SessionID) == "" {
		return fmt.Errorf("session_id is required")
	}
	if strings.TrimSpace(req.Actor) == "" {
		return fmt.Errorf("actor is required")
	}
	if strings.TrimSpace(req.Action) == "" {
		return fmt.Errorf("action is required")
	}
	return nil
}

func shouldProcessPullRequestAction(action string) bool {
	switch action {
	case "opened", "reopened", "synchronize", "edited", "ready_for_review":
		return true
	default:
		return false
	}
}

func linkedTicketLabel(pr pregithub.PullRequest) string {
	if pregithub.HasLinkedTicket(pr.Title, pr.Body, pr.HeadRef) {
		return "present"
	}
	return "missing"
}

func normalizeEnvironment(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "prod":
		return "production"
	case "dev":
		return "development"
	case "":
		return "unknown"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func repoName(fullName string) string {
	_, repo, ok := strings.Cut(fullName, "/")
	if !ok {
		return fullName
	}
	return repo
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
