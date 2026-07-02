package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hubbleops/hubbleops/internal/action"
	"github.com/hubbleops/hubbleops/internal/actionreceipt"
	"github.com/hubbleops/hubbleops/internal/approval"
	"github.com/hubbleops/hubbleops/internal/githubapp"
	"github.com/hubbleops/hubbleops/internal/policy"
	pregithub "github.com/hubbleops/hubbleops/internal/preflight/github"
	"github.com/hubbleops/hubbleops/internal/receiptverify"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func TestPreflightEndpointWritesSignedReceipt(t *testing.T) {
	walDir := t.TempDir()
	srv := &server{
		receiptOpts: actionreceipt.Options{WALDir: walDir, ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
	}
	body := `{
		"project":"acme",
		"session_id":"sess-1",
		"actor":"agent:claude-code",
		"action":"github.pull_request",
		"target":"acme/checkout#842",
		"environment":"main",
		"intent":"OPS-842 safe change"
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Decision.Decision != action.DecisionAllow || !response.Decision.ReceiptAttempted {
		t.Fatalf("response decision=%+v", response.Decision)
	}
	records := readGateRecords(t, walDir)
	report := receiptverify.VerifyWithOptions(records, receiptverify.Options{
		ReceiptSecret:     "receipt-secret",
		RequireSignatures: true,
	})
	if !report.Verified {
		t.Fatalf("receipt report not verified: %+v", report)
	}
}

func TestPreflightEndpointSanitizesRawResponseCanaries(t *testing.T) {
	walDir := t.TempDir()
	srv := &server{
		receiptOpts: actionreceipt.Options{WALDir: walDir, ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
	}
	body := `{
		"project":"customer@example.com",
		"session_id":"sess-sk_live_hubbleops_secret",
		"actor":"agent:customer@example.com",
		"human_delegator":"raw_customer_name_AcmePrivate",
		"action":"github.pull_request",
		"target":"customer@example.com",
		"environment":"main",
		"intent":"password=correct-horse-battery-staple",
		"findings":[{
			"source":"github",
			"kind":"github_missing_ticket",
			"action":"github.missing_ticket",
			"target":"customer@example.com",
			"risk_score":80,
			"risk_class":"high",
			"evidence":["raw_note=sk_live_hubbleops_secret","card=4242 4242 4242 4242"]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	response := rec.Body.String()
	for _, forbidden := range []string{
		"customer@example.com",
		"sk_live_hubbleops_secret",
		"raw_customer_name_AcmePrivate",
		"4242 4242 4242 4242",
		"password=correct-horse-battery-staple",
	} {
		if strings.Contains(response, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, response)
		}
	}
	records := readGateRecords(t, walDir)
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal records: %v", err)
	}
	for _, forbidden := range []string{
		"customer@example.com",
		"sk_live_hubbleops_secret",
		"raw_customer_name_AcmePrivate",
		"4242 4242 4242 4242",
		"password=correct-horse-battery-staple",
	} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("wal leaked %q: %s", forbidden, string(data))
		}
	}
}

func TestGitHubWebhookCreatesCheckRunAndReceipt(t *testing.T) {
	walDir := t.TempDir()
	fake := &fakeGitHubClient{
		files: []pregithub.ChangedFile{{Filename: "migrations/001.sql", Status: "modified"}},
		codeowners: `
/migrations/ @db-owner
`,
	}
	srv := &server{
		policy: &policy.Policy{
			Rules: []policy.Rule{{
				ID:        "review-pr-missing-ticket",
				If:        policy.Conditions{Action: pregithub.ActionMissingTicket},
				Decision:  action.DecisionRequireApproval,
				RiskScore: 80,
				Reason:    "pull request needs a linked ticket",
			}},
		},
		receiptOpts:   actionreceipt.Options{WALDir: walDir, ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
		github:        fake,
		webhookSecret: "webhook-secret",
		checkName:     "HubbleOps Action Firewall",
	}
	payload := `{
		"action":"opened",
		"number":842,
		"installation":{"id":99},
		"repository":{"full_name":"acme/checkout","name":"checkout","owner":{"login":"acme"}},
		"pull_request":{
			"number":842,
			"title":"change database",
			"body":"no ticket here",
			"user":{"login":"krish"},
			"head":{"ref":"feature/db-change","sha":"abc123"},
			"base":{"ref":"main"}
		},
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
		t.Fatalf("check conclusion=%q want action_required", fake.check.Conclusion)
	}
	if fake.check.HeadSHA != "abc123" {
		t.Fatalf("check head sha=%q", fake.check.HeadSHA)
	}
	records := readGateRecords(t, walDir)
	if len(records) != 1 {
		t.Fatalf("records=%d want 1", len(records))
	}
	if records[0].Decision != action.DecisionRequireApproval {
		t.Fatalf("receipt decision=%q want require_approval", records[0].Decision)
	}
	if strings.Contains(records[0].DecisionEvidence, "change database") || strings.Contains(records[0].DecisionEvidence, "no ticket") {
		t.Fatalf("receipt evidence leaked PR title/body: %s", records[0].DecisionEvidence)
	}
}

func TestGitHubWebhookRejectsInvalidSignature(t *testing.T) {
	srv := &server{webhookSecret: "webhook-secret"}
	req := httptest.NewRequest(http.MethodPost, "/github/webhook", strings.NewReader(`{"action":"opened"}`))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", "sha256=bad")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s want 401", rec.Code, rec.Body.String())
	}
}

func TestGitHubWebhookMissingClientIsServiceUnavailable(t *testing.T) {
	payload := `{
		"action":"opened",
		"number":842,
		"installation":{"id":99},
		"repository":{"full_name":"acme/checkout","name":"checkout","owner":{"login":"acme"}},
		"pull_request":{"number":842,"title":"OPS-1 safe","body":"","user":{"login":"krish"},"head":{"ref":"feature","sha":"abc123"},"base":{"ref":"main"}},
		"sender":{"login":"krish"}
	}`
	srv := &server{webhookSecret: "webhook-secret"}
	req := httptest.NewRequest(http.MethodPost, "/github/webhook", strings.NewReader(payload))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-Hub-Signature-256", webhookSignature("webhook-secret", []byte(payload)))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s want 503", rec.Code, rec.Body.String())
	}
}

func TestPreflightApprovalReviewAllowsRepeatedDecision(t *testing.T) {
	walDir := t.TempDir()
	approvalPath := filepath.Join(t.TempDir(), "approvals.json")
	srv := &server{
		receiptOpts: actionreceipt.Options{WALDir: walDir, ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
		approvals:   approval.NewService(approval.NewFileStore(approvalPath), nil),
	}
	body := `{
		"project":"acme",
		"session_id":"sess-approval",
		"actor":"agent:claude-code",
		"human_delegator":"krish",
		"action":"github.pull_request",
		"target":"acme/checkout#842",
		"environment":"main",
		"intent":"OPS-842 risky change",
		"findings":[{
			"source":"github",
			"kind":"github_missing_ticket",
			"action":"github.missing_ticket",
			"target":"acme/checkout#842",
			"risk_score":80,
			"risk_class":"high",
			"evidence":["github_linked_ticket=missing"]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", rec.Code, rec.Body.String())
	}
	var first preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first response: %v", err)
	}
	if first.Decision.Decision != action.DecisionRequireApproval || first.ApprovalRequest == nil {
		t.Fatalf("first response=%+v approval=%+v", first.Decision, first.ApprovalRequest)
	}

	reviewBody := `{"reviewer":"owner@example.com","source":"api","decision":"approved","comment":"approved for customer@example.com"}`
	reviewReq := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+first.ApprovalRequest.ApprovalID+"/review", strings.NewReader(reviewBody))
	reviewRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(reviewRec, reviewReq)
	if reviewRec.Code != http.StatusOK {
		t.Fatalf("review status=%d body=%s", reviewRec.Code, reviewRec.Body.String())
	}
	if data, err := os.ReadFile(approvalPath); err != nil {
		t.Fatalf("read approvals: %v", err)
	} else if strings.Contains(string(data), "owner@example.com") || strings.Contains(string(data), "customer@example.com") {
		t.Fatalf("approval store leaked raw reviewer/comment: %s", string(data))
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(body))
	rec = httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", rec.Code, rec.Body.String())
	}
	var second preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode second response: %v", err)
	}
	if second.Decision.Decision != action.DecisionAllow || len(second.Decision.Approvals) != 1 {
		t.Fatalf("second decision=%+v", second.Decision)
	}

	receiptReq := httptest.NewRequest(http.MethodGet, "/v1/receipts/"+second.Decision.DecisionID, nil)
	receiptRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(receiptRec, receiptReq)
	if receiptRec.Code != http.StatusOK {
		t.Fatalf("receipt status=%d body=%s", receiptRec.Code, receiptRec.Body.String())
	}
	if strings.Contains(receiptRec.Body.String(), "owner@example.com") {
		t.Fatalf("receipt endpoint leaked raw reviewer: %s", receiptRec.Body.String())
	}
	var receipt receiptResponse
	if err := json.Unmarshal(receiptRec.Body.Bytes(), &receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if receipt.Decision != action.DecisionAllow || len(receipt.Approvals) != 1 {
		t.Fatalf("receipt=%+v", receipt)
	}
	records := readGateRecords(t, walDir)
	if len(records) != 2 {
		t.Fatalf("records=%d want 2", len(records))
	}
	if records[1].Decision != action.DecisionAllow || len(records[1].Approvals) != 1 {
		t.Fatalf("approved receipt=%+v", records[1])
	}
	if strings.Contains(records[1].DecisionEvidence, "owner@example.com") ||
		!strings.Contains(records[1].DecisionEvidence, "approval_status=approved") {
		t.Fatalf("approved receipt evidence=%s", records[1].DecisionEvidence)
	}
	report := receiptverify.VerifyWithOptions(records, receiptverify.Options{
		ReceiptSecret:     "receipt-secret",
		RequireSignatures: true,
	})
	if !report.Verified {
		t.Fatalf("receipt report not verified: %+v", report)
	}
}

func TestPreflightRejectedApprovalBlocksRepeatedDecision(t *testing.T) {
	walDir := t.TempDir()
	srv := &server{
		receiptOpts: actionreceipt.Options{WALDir: walDir, ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
		approvals:   approval.NewService(approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json")), nil),
	}
	body := `{
		"project":"acme",
		"session_id":"sess-reject",
		"actor":"agent:claude-code",
		"action":"github.pull_request",
		"target":"acme/checkout#900",
		"environment":"main",
		"findings":[{
			"source":"github",
			"kind":"github_missing_ticket",
			"action":"github.missing_ticket",
			"target":"acme/checkout#900",
			"risk_score":80,
			"risk_class":"high",
			"evidence":["github_linked_ticket=missing"]
		}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%s", rec.Code, rec.Body.String())
	}
	var first preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if first.ApprovalRequest == nil {
		t.Fatalf("approval request missing: %+v", first)
	}
	reviewReq := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+first.ApprovalRequest.ApprovalID+"/review", strings.NewReader(`{"reviewer":"sre","source":"api","decision":"rejected"}`))
	reviewRec := httptest.NewRecorder()
	srv.routes().ServeHTTP(reviewRec, reviewReq)
	if reviewRec.Code != http.StatusOK {
		t.Fatalf("review status=%d body=%s", reviewRec.Code, reviewRec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/preflight", strings.NewReader(body))
	rec = httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", rec.Code, rec.Body.String())
	}
	var second preflightResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode second: %v", err)
	}
	if second.Decision.Decision != action.DecisionBlock ||
		!strings.Contains(strings.Join(second.Decision.Evidence, " "), "approval_status=rejected") {
		t.Fatalf("second decision=%+v", second.Decision)
	}
}

func TestOldDecisionIDApprovalMissCreatesFreshRequest(t *testing.T) {
	walDir := t.TempDir()
	approvalStore := approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	approvals := approval.NewService(approvalStore, nil)
	old, _, err := approvals.Request(context.Background(), approval.Request{
		Project:           "acme",
		SessionID:         "sess",
		DecisionID:        "dec_v1_old",
		ReceiptID:         "dec_v1_old",
		Action:            "deploy.release",
		TargetFingerprint: "sha256:old",
		RequiredApprovers: []string{"sre"},
		Reason:            "old approval",
		RiskScore:         85,
		RequestedBy:       "agent:codex",
		Source:            "preflight",
	})
	if err != nil {
		t.Fatalf("request old approval: %v", err)
	}
	if _, err := approvals.Review(context.Background(), approval.ReviewInput{
		ApprovalID: old.ApprovalID,
		Reviewer:   "sre",
		Source:     "api",
		Decision:   "approved",
	}); err != nil {
		t.Fatalf("review old approval: %v", err)
	}
	srv := &server{
		receiptOpts: actionreceipt.Options{WALDir: walDir, ReceiptSecret: "receipt-secret", ReceiptKeyID: "test"},
		approvals:   approvals,
	}
	req := action.Request{
		Project:   "acme",
		SessionID: "sess",
		Actor:     "agent:codex",
		Action:    "deploy.release",
		Target:    "api",
	}
	decision := action.Decision{
		DecisionID:        "dec_v2_new",
		ReceiptID:         "dec_v2_new",
		Decision:          action.DecisionRequireApproval,
		Reason:            "new approval required",
		RiskScore:         85,
		RiskClass:         action.RiskHigh,
		RequiredApprovers: []string{"sre"},
	}

	written, fresh, err := srv.writeDecisionReceipt(context.Background(), req, decision, nil)
	if err != nil {
		t.Fatalf("write decision receipt: %v", err)
	}
	if written.Decision != action.DecisionRequireApproval {
		t.Fatalf("old approval was applied to new decision: %+v", written)
	}
	if fresh == nil || fresh.DecisionID != "dec_v2_new" || fresh.Status != approval.StatusPending {
		t.Fatalf("fresh approval request=%+v", fresh)
	}
}

type fakeGitHubClient struct {
	files              []pregithub.ChangedFile
	codeowners         string
	fileContents       map[string]string
	terraformPlan      string
	terraformPlanFound bool
	check              githubapp.CheckRun
	patch              githubapp.CheckRun
	checkRunID         int64
}

func (f *fakeGitHubClient) GetFileContent(ctx context.Context, token, owner, repo, path, ref string) (string, error) {
	return f.fileContents[path], nil
}

func (f *fakeGitHubClient) GetTerraformPlan(ctx context.Context, token, owner, repo string, number int, headSHA string) (string, bool, error) {
	return f.terraformPlan, f.terraformPlanFound, nil
}

func (f *fakeGitHubClient) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	return "token", nil
}

func (f *fakeGitHubClient) ListPullRequestFiles(ctx context.Context, token, owner, repo string, number int) ([]pregithub.ChangedFile, error) {
	return f.files, nil
}

func (f *fakeGitHubClient) GetCodeOwners(ctx context.Context, token, owner, repo, ref string) (string, error) {
	return f.codeowners, nil
}

func (f *fakeGitHubClient) CreateCheckRun(ctx context.Context, token string, run githubapp.CheckRun) (int64, error) {
	f.check = run
	if f.checkRunID == 0 {
		f.checkRunID = 1001
	}
	return f.checkRunID, nil
}

func (f *fakeGitHubClient) PatchCheckRun(ctx context.Context, token string, run githubapp.CheckRun) error {
	f.patch = run
	f.check = run
	return nil
}

func webhookSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func readGateRecords(t *testing.T, walDir string) []wal.Record {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("wal files=%v err=%v", files, err)
	}
	data, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	var records []wal.Record
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for {
		var rec wal.Record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("decode wal: %v", err)
		}
		records = append(records, rec)
	}
	return records
}
