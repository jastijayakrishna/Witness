package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hubbleops/hubbleops/internal/action"
	"github.com/hubbleops/hubbleops/internal/actionreceipt"
	"github.com/hubbleops/hubbleops/internal/approval"
	"github.com/hubbleops/hubbleops/internal/policy"
	pregithub "github.com/hubbleops/hubbleops/internal/preflight/github"
)

func authedServer(t *testing.T) *server {
	t.Helper()
	return &server{
		receiptOpts: actionreceipt.Options{WALDir: t.TempDir(), ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
		approvals:   approval.NewService(approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json")), nil),
		auth: newGateAuth(map[string]principal{
			"owner-tok":    {Identity: "owner"},
			"intruder-tok": {Identity: "intruder"},
		}),
	}
}

const requireApprovalBody = `{
	"project":"acme",
	"session_id":"sess-authz",
	"actor":"agent:claude-code",
	"action":"github.pull_request",
	"target":"acme/checkout#842",
	"environment":"main",
	"findings":[{
		"source":"github","kind":"github_missing_ticket","action":"github.missing_ticket",
		"target":"acme/checkout#842","risk_score":80,"risk_class":"high",
		"evidence":["github_linked_ticket=missing"]
	}]
}`

func TestGateRejectsUnauthenticatedWhenAuthEnabled(t *testing.T) {
	srv := authedServer(t)

	req := httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(requireApprovalBody))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-credential status=%d want 401: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(requireApprovalBody))
	req.Header.Set("X-HubbleOps-API-Key", "owner-tok")
	rec = httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated status=%d want 200: %s", rec.Code, rec.Body.String())
	}
}

func TestApprovalReviewRequiresAuthorizedApprover(t *testing.T) {
	srv := authedServer(t)

	// Create the pending approval (required approver is "owner").
	req := httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(requireApprovalBody))
	req.Header.Set("X-HubbleOps-API-Key", "owner-tok")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preflight status=%d: %s", rec.Code, rec.Body.String())
	}
	var first preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if first.ApprovalRequest == nil {
		t.Fatalf("expected approval request, got %+v", first.Decision)
	}
	approvalID := first.ApprovalRequest.ApprovalID

	// A principal not in required_approvers must be forbidden — even with a valid token.
	review := func(token, body string) int {
		r := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+approvalID+"/review", strings.NewReader(body))
		r.Header.Set("X-HubbleOps-API-Key", token)
		w := httptest.NewRecorder()
		srv.routes().ServeHTTP(w, r)
		return w.Code
	}
	if code := review("intruder-tok", `{"decision":"approved"}`); code != http.StatusForbidden {
		t.Fatalf("intruder review status=%d want 403", code)
	}

	// The authorized approver succeeds; the recorded reviewer is the authenticated
	// principal ("owner"), not anything supplied in the body.
	if code := review("owner-tok", `{"reviewer":"spoofed","decision":"approved"}`); code != http.StatusOK {
		t.Fatalf("approver review status=%d want 200", code)
	}
	rec2 := httptest.NewRecorder()
	getReq := httptest.NewRequest(http.MethodGet, "/v1/approvals/"+approvalID, nil)
	getReq.Header.Set("X-HubbleOps-API-Key", "owner-tok")
	srv.routes().ServeHTTP(rec2, getReq)
	var got approval.Record
	if err := json.Unmarshal(rec2.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode approval: %v", err)
	}
	if got.Status != approval.StatusApproved {
		t.Fatalf("approval status=%q want approved", got.Status)
	}
	if got.Reviewer != "owner" {
		t.Fatalf("recorded reviewer=%q want authenticated principal 'owner' (body must not set reviewer)", got.Reviewer)
	}
}

func TestGitHubWebhookScansMigrationFileContent(t *testing.T) {
	fake := &fakeGitHubClient{
		files:        []pregithub.ChangedFile{{Filename: "migrations/003_drop.sql", Status: "added"}},
		fileContents: map[string]string{"migrations/003_drop.sql": "DELETE FROM users WHERE 1=1;\n"},
	}
	srv := &server{
		receiptOpts:   actionreceipt.Options{WALDir: t.TempDir(), ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
		github:        fake,
		webhookSecret: "webhook-secret",
		checkName:     "HubbleOps Action Firewall",
	}
	payload := `{
		"action":"opened","number":7,"installation":{"id":1},
		"repository":{"full_name":"acme/checkout","name":"checkout","owner":{"login":"acme"}},
		"pull_request":{"number":7,"title":"OPS-7 schema change","body":"OPS-7","user":{"login":"krish"},"head":{"ref":"f","sha":"deadbeef"},"base":{"ref":"main"}},
		"sender":{"login":"krish"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/github/webhook", strings.NewReader(payload))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", webhookSignature("webhook-secret", []byte(payload)))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	// The tautological DELETE inside the PR's migration file must drive a BLOCK -> failure
	// check, proving the PR gate analyzes file CONTENTS, not just paths.
	if fake.check.Conclusion != "failure" {
		t.Fatalf("check conclusion=%q want failure (PR gate must read file contents)", fake.check.Conclusion)
	}
	var resp preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Decision.Decision != action.DecisionBlock {
		t.Fatalf("decision=%q want block", resp.Decision.Decision)
	}
}

func TestGitHubWebhookScansTerraformPlanArtifact(t *testing.T) {
	fake := &fakeGitHubClient{
		files: []pregithub.ChangedFile{{Filename: "terraform/prod/main.tf", Status: "modified"}},
		terraformPlan: `{
			"resource_changes":[{
				"address":"aws_db_instance.prod",
				"type":"aws_db_instance",
				"name":"prod",
				"change":{"actions":["delete"],"before":{"id":"db-prod"},"after":null}
			}]
		}`,
		terraformPlanFound: true,
	}
	srv := &server{
		receiptOpts:   actionreceipt.Options{WALDir: t.TempDir(), ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
		github:        fake,
		webhookSecret: "webhook-secret",
		checkName:     "HubbleOps Action Firewall",
	}
	payload := `{
		"action":"opened","number":8,"installation":{"id":1},
		"repository":{"full_name":"acme/checkout","name":"checkout","owner":{"login":"acme"}},
		"pull_request":{"number":8,"title":"OPS-8 terraform prod rds","body":"OPS-8","user":{"login":"krish"},"head":{"ref":"f","sha":"feedface"},"base":{"ref":"main"}},
		"sender":{"login":"krish"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/github/webhook", strings.NewReader(payload))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", webhookSignature("webhook-secret", []byte(payload)))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fake.check.Conclusion != "failure" {
		t.Fatalf("check conclusion=%q want failure for prod RDS destroy", fake.check.Conclusion)
	}
	var resp preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Decision.Decision != action.DecisionBlock {
		t.Fatalf("decision=%q want block", resp.Decision.Decision)
	}
}

func TestGitHubWebhookTerraformTouchedWithoutPlanRequiresApproval(t *testing.T) {
	fake := &fakeGitHubClient{
		files: []pregithub.ChangedFile{{Filename: "terraform/prod/main.tf", Status: "modified"}},
	}
	srv := &server{
		receiptOpts:   actionreceipt.Options{WALDir: t.TempDir(), ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
		github:        fake,
		webhookSecret: "webhook-secret",
		checkName:     "HubbleOps Action Firewall",
	}
	payload := `{
		"action":"opened","number":9,"installation":{"id":1},
		"repository":{"full_name":"acme/checkout","name":"checkout","owner":{"login":"acme"}},
		"pull_request":{"number":9,"title":"OPS-9 terraform safe-looking","body":"OPS-9","user":{"login":"krish"},"head":{"ref":"f","sha":"cafebabe"},"base":{"ref":"main"}},
		"sender":{"login":"krish"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/github/webhook", strings.NewReader(payload))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", webhookSignature("webhook-secret", []byte(payload)))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if fake.check.Conclusion != "action_required" {
		t.Fatalf("check conclusion=%q want action_required when Terraform plan is missing", fake.check.Conclusion)
	}
	var resp preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Decision.Decision != action.DecisionRequireApproval {
		t.Fatalf("decision=%q want require_approval", resp.Decision.Decision)
	}
	foundMissingPlan := false
	for _, finding := range resp.Findings {
		if finding.Kind != "terraform_plan_missing" {
			continue
		}
		for _, tag := range finding.ChangeTags {
			if tag == "terraform:plan_missing" {
				foundMissingPlan = true
			}
		}
	}
	if !foundMissingPlan {
		t.Fatalf("response missing fail-closed terraform finding: %+v", resp.Findings)
	}
}

func TestApprovalReviewReissuesCheckRunOnApproval(t *testing.T) {
	walDir := t.TempDir()
	fake := &fakeGitHubClient{
		files: []pregithub.ChangedFile{{Filename: "src/app.go", Status: "modified"}},
	}
	srv := &server{
		policy: &policy.Policy{Rules: []policy.Rule{{
			ID: "needs-ticket", If: policy.Conditions{Action: pregithub.ActionMissingTicket},
			Decision: action.DecisionRequireApproval, RiskScore: 80, Reason: "needs a linked ticket",
		}}},
		receiptOpts:   actionreceipt.Options{WALDir: walDir, ReceiptSecret: "rs", ReceiptKeyID: "test"},
		approvals:     approval.NewService(approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json")), nil),
		github:        fake,
		webhookSecret: "wh",
		checkName:     "HubbleOps Action Firewall",
	}
	payload := `{
		"action":"opened","number":5,"installation":{"id":42},
		"repository":{"full_name":"acme/checkout","name":"checkout","owner":{"login":"acme"}},
		"pull_request":{"number":5,"title":"no ticket","body":"none","user":{"login":"krish"},"head":{"ref":"f","sha":"abc123"},"base":{"ref":"main"}},
		"sender":{"login":"krish"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/github/webhook", strings.NewReader(payload))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", webhookSignature("wh", []byte(payload)))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("webhook status=%d: %s", rec.Code, rec.Body.String())
	}
	if fake.check.Conclusion != "action_required" {
		t.Fatalf("initial check=%q want action_required", fake.check.Conclusion)
	}
	var resp preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.ApprovalRequest == nil {
		t.Fatalf("no approval request: %v %+v", err, resp)
	}

	// Approve it; the gate must write the post-approval receipt and patch the original
	// check run to success for the PR head SHA.
	reviewReq := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+resp.ApprovalRequest.ApprovalID+"/review", strings.NewReader(`{"reviewer":"owner","source":"api","decision":"approved"}`))
	reviewRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(reviewRec, reviewReq)
	if reviewRec.Code != http.StatusOK {
		t.Fatalf("review status=%d: %s", reviewRec.Code, reviewRec.Body.String())
	}
	if fake.patch.Conclusion != "success" {
		t.Fatalf("after approval patch=%q want success", fake.patch.Conclusion)
	}
	if fake.patch.ID != fake.checkRunID {
		t.Fatalf("patched check id=%d want %d", fake.patch.ID, fake.checkRunID)
	}
	if fake.patch.HeadSHA != "abc123" {
		t.Fatalf("patched check head sha=%q want abc123", fake.patch.HeadSHA)
	}
	if !strings.Contains(fake.patch.Summary, "post_approval_receipt_id=") {
		t.Fatalf("patched check summary missing post-approval receipt id: %s", fake.patch.Summary)
	}
	records := readGateRecords(t, walDir)
	if len(records) != 2 {
		t.Fatalf("records=%d want initial require_approval + post-approval allow", len(records))
	}
	if records[0].Decision != action.DecisionRequireApproval || records[1].Decision != action.DecisionAllow {
		t.Fatalf("receipt decisions=%q,%q want require_approval,allow", records[0].Decision, records[1].Decision)
	}
	if records[1].ReceiptSignature == "" || !strings.Contains(records[1].DecisionEvidence, "approval_status=approved") {
		t.Fatalf("post-approval receipt missing signature/evidence: %+v", records[1])
	}
}

func TestGitHubWebhookRejectsWhenSecretUnset(t *testing.T) {
	// A configured github client means that, without a fail-closed secret guard, an
	// unsigned webhook would be accepted and processed (200). The 503 must come from the
	// missing-secret guard, not from a missing client.
	srv := &server{
		github:      &fakeGitHubClient{},
		receiptOpts: actionreceipt.Options{WALDir: t.TempDir(), ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
	}
	payload := `{
		"action":"opened","number":1,"installation":{"id":1},
		"repository":{"full_name":"acme/x","name":"x","owner":{"login":"acme"}},
		"pull_request":{"number":1,"title":"t","body":"b","user":{"login":"u"},"head":{"ref":"f","sha":"s"},"base":{"ref":"main"}},
		"sender":{"login":"u"}
	}`
	req := httptest.NewRequest(http.MethodPost, "/github/webhook", strings.NewReader(payload))
	req.Header.Set("X-GitHub-Event", "pull_request")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("webhook-with-no-secret status=%d want 503: %s", rec.Code, rec.Body.String())
	}
}

// guard: action.Decision must not be the only sanitizer path; confirm an authenticated
// preflight still allows a clean action through (regression for the auth wrapper).
func TestAuthenticatedAllowStillPasses(t *testing.T) {
	srv := authedServer(t)
	body := `{"project":"acme","session_id":"s","actor":"agent:x","action":"github.pull_request","target":"acme/x#1","environment":"main"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer owner-tok")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200: %s", rec.Code, rec.Body.String())
	}
	var resp preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Decision.Decision != action.DecisionAllow {
		t.Fatalf("decision=%q want allow", resp.Decision.Decision)
	}
}
