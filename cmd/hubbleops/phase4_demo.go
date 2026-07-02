package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hubbleops/hubbleops/internal/action"
	"github.com/hubbleops/hubbleops/internal/actionreceipt"
	"github.com/hubbleops/hubbleops/internal/approval"
	"github.com/hubbleops/hubbleops/internal/gate"
	"github.com/hubbleops/hubbleops/internal/policy"
	"github.com/hubbleops/hubbleops/internal/preflight"
	pregithub "github.com/hubbleops/hubbleops/internal/preflight/github"
	"github.com/hubbleops/hubbleops/internal/privacy"
)

type phase4DemoSummary struct {
	Items               int      `json:"items"`
	InitialAllow        int      `json:"initial_allow"`
	InitialApproval     int      `json:"initial_require_approval"`
	InitialBlock        int      `json:"initial_block"`
	ApprovalRequests    int      `json:"approval_requests"`
	ReviewedApprovalID  string   `json:"reviewed_approval_id,omitempty"`
	PostReviewDecision  string   `json:"post_review_decision,omitempty"`
	PostReviewReceiptID string   `json:"post_review_receipt_id,omitempty"`
	WALDir              string   `json:"wal_dir"`
	ApprovalStore       string   `json:"approval_store"`
	ReceiptKeyID        string   `json:"receipt_key_id"`
	SignedReceipts      bool     `json:"signed_receipts"`
	PendingApprovalIDs  []string `json:"pending_approval_ids,omitempty"`
}

type phase4DemoCase struct {
	Name     string
	Kind     string
	Request  action.Request
	Findings []preflight.Finding
}

func runDemo(args []string) int {
	if len(args) < 1 {
		demoUsage()
		return 2
	}
	switch args[0] {
	case "phase4":
		return runPhase4Demo(args[1:])
	default:
		demoUsage()
		return 2
	}
}

func runPhase4Demo(args []string) int {
	fs := flag.NewFlagSet("demo phase4", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	walDir := fs.String("wal-dir", filepath.Join("data", "phase4-demo", "wal"), "WAL directory for demo receipts")
	approvalPath := fs.String("approval-store", filepath.Join("data", "phase4-demo", "approvals.json"), "file-backed approval store for demo")
	receiptSecret := fs.String("receipt-secret", os.Getenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET"), "receipt signing secret; demo fallback is used when empty")
	receiptKeyID := fs.String("receipt-key-id", envOrDefault([]string{"HUBBLEOPS_RECEIPT_KEY_ID"}, "phase4-demo"), "receipt key id")
	jsonOut := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "demo phase4 takes flags only")
		return 2
	}
	secret := strings.TrimSpace(*receiptSecret)
	if secret == "" {
		secret = "phase4-demo-local-receipt-secret"
	}
	opts := actionreceipt.Options{WALDir: *walDir, ReceiptSecret: secret, ReceiptKeyID: *receiptKeyID}
	store := approval.NewService(approval.NewFileStore(*approvalPath), nil)
	pol := phase4DemoPolicy()
	cases := phase4DemoCases()
	summary := phase4DemoSummary{
		Items:          len(cases),
		WALDir:         *walDir,
		ApprovalStore:  *approvalPath,
		ReceiptKeyID:   *receiptKeyID,
		SignedReceipts: true,
	}
	var firstApproval *approval.Record
	var firstApprovalCase *phase4DemoCase
	var firstApprovalDecision action.Decision
	ctx := context.Background()
	for i := range cases {
		item := cases[i]
		decision := gate.Decide(item.Request, item.Findings, pol)
		written, err := actionreceipt.Write(item.Request, decision, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write demo receipt %s: %v\n", item.Name, err)
			return 1
		}
		switch written.Decision {
		case action.DecisionAllow:
			summary.InitialAllow++
		case action.DecisionRequireApproval:
			summary.InitialApproval++
			rec, _, err := store.Request(ctx, approval.Request{
				Project:           item.Request.Project,
				SessionID:         item.Request.SessionID,
				DecisionID:        written.DecisionID,
				ReceiptID:         written.ReceiptID,
				Action:            item.Request.Action,
				TargetFingerprint: written.TargetFingerprint,
				RequiredApprovers: written.RequiredApprovers,
				Reason:            written.Reason,
				RiskScore:         written.RiskScore,
				RequestedBy:       item.Request.Actor,
				Source:            "demo",
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "request demo approval %s: %v\n", item.Name, err)
				return 1
			}
			summary.ApprovalRequests++
			summary.PendingApprovalIDs = append(summary.PendingApprovalIDs, rec.ApprovalID)
			if firstApproval == nil {
				copyItem := item
				firstApproval = &rec
				firstApprovalCase = &copyItem
				firstApprovalDecision = written
			}
		case action.DecisionBlock:
			summary.InitialBlock++
		}
	}
	if firstApproval != nil && firstApprovalCase != nil {
		reviewed, err := store.Review(ctx, approval.ReviewInput{
			ApprovalID: firstApproval.ApprovalID,
			Reviewer:   "founder",
			Source:     "demo",
			Decision:   "approved",
			Comment:    "phase4 demo approval",
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "review demo approval: %v\n", err)
			return 1
		}
		approved := approval.ApplyDecision(firstApprovalDecision, reviewed)
		approved = withDemoApprovalEvidenceHashes(approved)
		written, err := actionreceipt.Write(firstApprovalCase.Request, approved, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "write approved demo receipt: %v\n", err)
			return 1
		}
		summary.ReviewedApprovalID = reviewed.ApprovalID
		summary.PostReviewDecision = written.Decision
		summary.PostReviewReceiptID = written.ReceiptID
		summary.PendingApprovalIDs = removeString(summary.PendingApprovalIDs, reviewed.ApprovalID)
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
	} else {
		fmt.Println("HubbleOps Phase 4 demo")
		fmt.Printf("items=%d allow=%d require_approval=%d block=%d approval_requests=%d\n",
			summary.Items, summary.InitialAllow, summary.InitialApproval, summary.InitialBlock, summary.ApprovalRequests)
		fmt.Printf("reviewed_approval_id=%s post_review_decision=%s post_review_receipt_id=%s\n",
			summary.ReviewedApprovalID, summary.PostReviewDecision, summary.PostReviewReceiptID)
		fmt.Printf("wal_dir=%s approval_store=%s receipt_key_id=%s\n", summary.WALDir, summary.ApprovalStore, summary.ReceiptKeyID)
	}
	return 0
}

func phase4DemoPolicy() *policy.Policy {
	return &policy.Policy{
		Version:            "phase4-demo/v1",
		ProtectedResources: []string{"aws_s3_bucket.audit_logs_prod"},
		Rules: []policy.Rule{
			{
				ID:                "phase4-pr-missing-ticket",
				If:                policy.Conditions{Action: pregithub.ActionMissingTicket},
				Decision:          action.DecisionRequireApproval,
				Reason:            "pull request needs customer review label before merge",
				RiskScore:         80,
				RequiredApprovers: []string{"codeowner"},
			},
			{
				ID:        "phase4-protected-terraform-destroy",
				If:        policy.Conditions{Action: "terraform.destroy", Env: "production", TouchesAny: []string{"aws_s3_bucket.audit_logs_prod"}},
				Decision:  action.DecisionBlock,
				Reason:    "protected infrastructure destroy is blocked",
				RiskScore: 95,
			},
		},
	}
}

func phase4DemoCases() []phase4DemoCase {
	var cases []phase4DemoCase
	for i := 1; i <= 14; i++ {
		target := fmt.Sprintf("acme/checkout#%d", 100+i)
		req := phase4DemoRequest(fmt.Sprintf("phase4-safe-%02d", i), pregithub.ActionPullRequest, target, "main")
		req.Intent = fmt.Sprintf("SAFE-%02d low-risk pull request", i)
		cases = append(cases, phase4DemoCase{Name: fmt.Sprintf("safe-pr-%02d", i), Kind: "pr", Request: req})
	}
	for i := 1; i <= 4; i++ {
		target := fmt.Sprintf("acme/checkout#%d", 200+i)
		req := phase4DemoRequest(fmt.Sprintf("phase4-review-%02d", i), pregithub.ActionPullRequest, target, "main")
		req.Intent = fmt.Sprintf("REV-%02d pull request missing linked ticket", i)
		cases = append(cases, phase4DemoCase{
			Name:    fmt.Sprintf("review-pr-%02d", i),
			Kind:    "pr",
			Request: req,
			Findings: []preflight.Finding{{
				Source:    preflight.SourceGitHub,
				Kind:      preflight.KindGitHubMissingTicket,
				Action:    pregithub.ActionMissingTicket,
				Target:    target,
				RiskScore: 45,
				RiskClass: action.RiskClass(45),
				Evidence: []string{
					"github_linked_ticket=missing",
					"github_pr_fingerprint=" + privacy.FingerprintString(target),
				},
				ChangeTags: []string{"github:missing_ticket"},
			}},
		})
	}
	for i := 1; i <= 2; i++ {
		req := phase4DemoRequest(fmt.Sprintf("phase4-block-%02d", i), "terraform.destroy", "aws_s3_bucket.audit_logs_prod", "production")
		req.Intent = fmt.Sprintf("BLOCK-%02d protected terraform plan", i)
		cases = append(cases, phase4DemoCase{
			Name:    fmt.Sprintf("blocked-plan-%02d", i),
			Kind:    "plan",
			Request: req,
			Findings: []preflight.Finding{{
				Source:    preflight.SourceTerraform,
				Kind:      preflight.KindTerraformDelete,
				Action:    "terraform.destroy",
				Target:    "aws_s3_bucket.audit_logs_prod",
				RiskScore: 95,
				RiskClass: action.RiskCritical,
				Evidence: []string{
					"source=terraform",
					"terraform_action=delete",
					"resource_type=aws_s3_bucket",
					"protected_resource=true",
				},
				ChangeTags: []string{"terraform:delete", "resource:aws_s3_bucket"},
			}},
		})
	}
	return cases
}

func phase4DemoRequest(session, actionName, target, env string) action.Request {
	return action.Request{
		Project:        "phase4-demo",
		SessionID:      session,
		Actor:          "agent:phase4-demo",
		HumanDelegator: "founder",
		Action:         actionName,
		Target:         target,
		Environment:    normalizeEnvironment(env),
		IdempotencyKey: "phase4:" + strings.TrimPrefix(privacy.FingerprintString(session+"\x00"+target), "sha256:"),
		PolicyVersion:  action.PolicyVersion,
		CaptureMode:    privacy.CaptureModeFingerprint,
	}
}

func withDemoApprovalEvidenceHashes(decision action.Decision) action.Decision {
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

func removeString(values []string, remove string) []string {
	var out []string
	for _, value := range values {
		if value != remove {
			out = append(out, value)
		}
	}
	return out
}

func demoUsage() {
	fmt.Fprintln(os.Stderr, "usage: hubbleops demo phase4 [flags]")
}
