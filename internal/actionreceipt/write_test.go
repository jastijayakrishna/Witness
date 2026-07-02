package actionreceipt

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hubbleops/hubbleops/internal/action"
	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/receiptverify"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func TestWriteSanitizesSensitiveReceiptFields(t *testing.T) {
	walDir := t.TempDir()
	rawEmail := "customer@example.com"
	rawEvidence := "raw_note=send receipt to " + rawEmail
	req := action.Request{
		Project:        "project:" + rawEmail,
		SessionID:      "session " + rawEmail,
		Actor:          "agent:" + rawEmail,
		HumanDelegator: rawEmail,
		Action:         "github.pull_request",
		Target:         rawEmail,
		Environment:    "prod",
	}
	decision := action.Decision{
		Decision:           action.DecisionRequireApproval,
		Reason:             "review " + rawEmail + " before deploy",
		RiskScore:          80,
		RiskClass:          action.RiskHigh,
		DecisionID:         "dec_sensitive",
		PolicyVersion:      action.PolicyVersion,
		Evidence:           []string{rawEvidence, "github_linked_ticket=missing", "idempotency_key=missing"},
		EvidenceHashes:     []string{privacy.FingerprintString(rawEvidence)},
		TargetFingerprint:  privacy.FingerprintString(req.Target),
		IntentHash:         privacy.FingerprintString("send email to " + rawEmail),
		IdempotencyKeyHash: privacy.FingerprintString("idem:" + rawEmail),
		RequiredApprovers:  []string{"sre", "owner@example.com"},
	}

	written, err := Write(req, decision, Options{
		WALDir:        walDir,
		ReceiptSecret: "receipt-secret",
		ReceiptKeyID:  "test",
	})
	if err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	if !written.ReceiptAttempted {
		t.Fatalf("receipt was not attempted")
	}
	records := readActionReceiptRecords(t, walDir)
	if len(records) != 1 {
		t.Fatalf("records=%d want 1", len(records))
	}
	rec := records[0]
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if strings.Contains(string(data), rawEmail) || strings.Contains(string(data), "raw_note=") {
		t.Fatalf("receipt leaked sensitive value: %s", string(data))
	}
	if !strings.HasPrefix(rec.Target, "fingerprint:sha256:") {
		t.Fatalf("target=%q want fingerprint marker", rec.Target)
	}
	if !strings.Contains(rec.DecisionEvidence, "evidence_fingerprint=sha256:") {
		t.Fatalf("decision evidence missing raw evidence fingerprint: %q", rec.DecisionEvidence)
	}
	if !strings.Contains(rec.DecisionEvidence, "github_linked_ticket=missing") ||
		!strings.Contains(rec.DecisionEvidence, "idempotency_key=missing") {
		t.Fatalf("decision evidence lost safe labels: %q", rec.DecisionEvidence)
	}
	if !strings.HasPrefix(rec.DecisionReason, "fingerprint:sha256:") {
		t.Fatalf("decision reason=%q want fingerprint marker", rec.DecisionReason)
	}
	if len(rec.RequiredApprovers) != 2 || rec.RequiredApprovers[0] != "sre" ||
		!strings.HasPrefix(rec.RequiredApprovers[1], "fingerprint:sha256:") {
		t.Fatalf("approvers=%v", rec.RequiredApprovers)
	}
	report := receiptverify.VerifyWithOptions(records, receiptverify.Options{
		ReceiptSecret:     "receipt-secret",
		RequireSignatures: true,
	})
	if !report.Verified {
		t.Fatalf("receipt report not verified: %+v", report)
	}
}

func TestWriteKeepsSafeEngineeringReceiptFields(t *testing.T) {
	walDir := t.TempDir()
	req := action.Request{
		Project:        "acme/checkout",
		SessionID:      "sess-1",
		Actor:          "agent:claude-code",
		HumanDelegator: "@sre-owner",
		Action:         "terraform.delete",
		Target:         "aws_s3_bucket.audit_logs_prod",
		Environment:    "production",
	}
	decision := action.Decision{
		Decision:          action.DecisionBlock,
		Reason:            "destructive engineering action detected",
		RiskScore:         95,
		RiskClass:         action.RiskCritical,
		DecisionID:        "dec_safe",
		PolicyVersion:     action.PolicyVersion,
		Evidence:          []string{"terraform_action=delete", "resource_type=aws_s3_bucket", "protected_resource=true"},
		EvidenceHashes:    []string{privacy.FingerprintString("terraform_action=delete")},
		TargetFingerprint: privacy.FingerprintString(req.Target),
		RequiredApprovers: []string{"billing-owner", "@org/team"},
	}

	if _, err := Write(req, decision, Options{WALDir: walDir}); err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	records := readActionReceiptRecords(t, walDir)
	if len(records) != 1 {
		t.Fatalf("records=%d want 1", len(records))
	}
	rec := records[0]
	for name, value := range map[string]string{
		"project":         rec.Project,
		"session_id":      rec.SessionID,
		"actor":           rec.Actor,
		"human_delegator": rec.HumanDelegator,
		"target":          rec.Target,
		"agent_id":        rec.AgentID,
		"user_id":         rec.UserID,
	} {
		if !strings.HasPrefix(value, "fingerprint:sha256:") {
			t.Fatalf("%s=%q want fingerprint marker", name, value)
		}
	}
	if rec.Action != req.Action || rec.Environment != req.Environment {
		t.Fatalf("safe taxonomy fields changed unexpectedly: %+v", rec)
	}
	if rec.DecisionEvidence != "terraform_action=delete; resource_type=aws_s3_bucket; protected_resource=true" {
		t.Fatalf("decision evidence=%q", rec.DecisionEvidence)
	}
	if strings.Join(rec.RequiredApprovers, ",") != "billing-owner,@org/team" {
		t.Fatalf("approvers=%v", rec.RequiredApprovers)
	}
}

func readActionReceiptRecords(t *testing.T, walDir string) []wal.Record {
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
