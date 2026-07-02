package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hubbleops/hubbleops/internal/action"
	"github.com/hubbleops/hubbleops/internal/approval"
	"github.com/hubbleops/hubbleops/internal/receiptverify"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func TestWritePreflightReceiptSignsAndVerifies(t *testing.T) {
	walDir := t.TempDir()
	req := action.Request{
		Project:        "proj-a",
		SessionID:      "sess-a",
		Actor:          "agent:claude-code",
		HumanDelegator: "krish",
		Action:         "terraform.destroy",
		Target:         "aws_s3_bucket.audit_logs_prod",
		Environment:    "production",
		Intent:         "cleanup old audit bucket",
	}
	decision := action.Decision{
		Decision:          action.DecisionBlock,
		DecisionID:        "dec_test",
		ReceiptID:         "dec_test",
		Reason:            "destructive engineering action detected",
		RiskScore:         95,
		RiskClass:         action.RiskCritical,
		PolicyVersion:     action.PolicyVersion,
		Evidence:          []string{"terraform_action=delete"},
		EvidenceHashes:    []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		RequiresReceipt:   true,
		BlastRadius:       "high",
		TargetFingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		IntentHash:        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	}

	got, err := writePreflightReceipt(req, decision, preflightFlags{
		WALDir:        walDir,
		ReceiptSecret: "receipt-secret",
		ReceiptKeyID:  "test",
	})
	if err != nil {
		t.Fatalf("write receipt: %v", err)
	}
	if !got.ReceiptAttempted || got.ReceiptError != "" {
		t.Fatalf("receipt state=%+v", got)
	}

	files, err := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("wal files=%v err=%v", files, err)
	}
	records, err := readWALRecords(files)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	report := receiptverify.VerifyWithOptions(records, receiptverify.Options{
		ReceiptSecret:     "receipt-secret",
		RequireSignatures: true,
	})
	if !report.Verified {
		t.Fatalf("receipt report not verified: %+v", report)
	}
}

func TestConfigurePreflightReceiptSignerAWSKMS(t *testing.T) {
	signer, secret, err := configurePreflightReceiptSigner(preflightFlags{
		ReceiptSigner:      "aws-kms",
		ReceiptKeyID:       "prod-key",
		ReceiptKMSKeyID:    "arn:aws:kms:us-east-1:123:key/prod",
		ReceiptKMSRegion:   "us-east-1",
		ReceiptKMSEndpoint: "https://kms.us-east-1.amazonaws.com/",
	})
	if err != nil {
		t.Fatalf("configure signer: %v", err)
	}
	if signer == nil || secret != "" {
		t.Fatalf("signer=%T secret=%q, want KMS signer and no local secret", signer, secret)
	}
	if signer.KeyID() != "prod-key" {
		t.Fatalf("key id=%q want prod-key", signer.KeyID())
	}
}

func TestConfigurePreflightReceiptSignerAWSKMSRequiresKeyAndRegion(t *testing.T) {
	_, _, err := configurePreflightReceiptSigner(preflightFlags{ReceiptSigner: "aws-kms"})
	if err == nil {
		t.Fatalf("configure signer succeeded, want missing KMS config error")
	}
	if !strings.Contains(err.Error(), "receipt-kms-key-id") {
		t.Fatalf("error %q does not mention KMS key id", err.Error())
	}
}

func TestVerifyReceiptsAnchorDetectsTruncatedWALExitOne(t *testing.T) {
	dir := t.TempDir()
	walDir := filepath.Join(dir, "wal")
	anchorPath := filepath.Join(dir, "checkpoints.jsonl")
	req := action.Request{
		Project:        "proj-a",
		SessionID:      "sess-a",
		Actor:          "agent:claude-code",
		HumanDelegator: "krish",
		Action:         "deploy.release",
		Target:         "checkout-api",
		Environment:    "production",
		Intent:         "deploy checkout",
	}
	for i, decisionValue := range []string{action.DecisionAllow, action.DecisionBlock, action.DecisionAllow} {
		decision := action.Decision{
			Decision:          decisionValue,
			DecisionID:        fmt.Sprintf("dec_%d", i+1),
			ReceiptID:         fmt.Sprintf("dec_%d", i+1),
			Reason:            "test decision",
			RiskScore:         95,
			RiskClass:         action.RiskCritical,
			PolicyVersion:     action.PolicyVersion,
			Evidence:          []string{"deploy_action=release"},
			EvidenceHashes:    []string{"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			RequiresReceipt:   true,
			BlastRadius:       "high",
			TargetFingerprint: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			IntentHash:        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		}
		if _, err := writePreflightReceipt(req, decision, preflightFlags{
			WALDir:        walDir,
			ReceiptSecret: "receipt-secret",
			ReceiptKeyID:  "test",
			AnchorPath:    anchorPath,
		}); err != nil {
			t.Fatalf("write receipt %d: %v", i, err)
		}
	}

	files, err := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("wal files=%v err=%v", files, err)
	}
	records, err := readWALRecords(files)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("records=%d want 3", len(records))
	}
	truncatedPath := filepath.Join(dir, "truncated.jsonl")
	f, err := os.Create(truncatedPath)
	if err != nil {
		t.Fatalf("create truncated wal: %v", err)
	}
	enc := json.NewEncoder(f)
	for _, rec := range records[:2] {
		if err := enc.Encode(rec); err != nil {
			t.Fatalf("encode truncated wal: %v", err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close truncated wal: %v", err)
	}

	var code int
	out := captureStdout(t, func() {
		code = runVerifyReceipts([]string{
			"-receipt-secret", "receipt-secret",
			"-require-signatures",
			"-anchor", anchorPath,
			truncatedPath,
		})
	})
	if code != 1 {
		t.Fatalf("verify-receipts exit=%d want 1; output=%s", code, out)
	}
	if !strings.Contains(out, "truncation detected: anchored seq=3, wal max seq=2") {
		t.Fatalf("verify output missing truncation reason: %s", out)
	}
}

func TestRunPolicyValidateExitCodes(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.yaml")
	if err := os.WriteFile(validPath, []byte(`
version: engineering-gate/v1
rules:
  - id: block-prod
    if:
      action: deploy.release
      env: prod
    decision: block
    risk_score: 90
`), 0600); err != nil {
		t.Fatalf("write valid policy: %v", err)
	}
	var validCode int
	validOut := captureStdout(t, func() {
		validCode = runPolicy([]string{"validate", validPath})
	})
	if validCode != 0 {
		t.Fatalf("valid policy exit=%d want 0; output=%s", validCode, validOut)
	}
	if !strings.Contains(validOut, "ok") || !strings.Contains(validOut, "rules=1") {
		t.Fatalf("valid output %q missing ok/rule count", validOut)
	}

	invalidPath := filepath.Join(dir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte(`
version: engineering-gate/v1
rules:
  - id: ""
    if: {}
    decision: quarantine
    risk_score: 200
`), 0600); err != nil {
		t.Fatalf("write invalid policy: %v", err)
	}
	var invalidCode int
	invalidErr := captureStderr(t, func() {
		invalidCode = runPolicy([]string{"validate", invalidPath})
	})
	if invalidCode != 1 {
		t.Fatalf("invalid policy exit=%d want 1; stderr=%s", invalidCode, invalidErr)
	}
	for _, want := range []string{"rules[0].id is required", "quarantine", "risk_score"} {
		if !strings.Contains(invalidErr, want) {
			t.Fatalf("invalid stderr %q missing %q", invalidErr, want)
		}
	}
}

func TestAnchorFromArgBuildsS3ObjectLockAnchor(t *testing.T) {
	anchor, err := anchorFromArg("s3://audit-bucket/hubbleops/checkpoints?region=us-east-1&retention_days=14")
	if err != nil {
		t.Fatalf("anchorFromArg: %v", err)
	}
	s3Anchor, ok := anchor.(*wal.S3ObjectLockAnchor)
	if !ok {
		t.Fatalf("anchor type=%T want *wal.S3ObjectLockAnchor", anchor)
	}
	if s3Anchor.Bucket != "audit-bucket" ||
		s3Anchor.Prefix != "hubbleops/checkpoints" ||
		s3Anchor.Region != "us-east-1" ||
		s3Anchor.RetentionDays != 14 {
		t.Fatalf("s3 anchor config=%+v", s3Anchor)
	}
}

func TestNormalizeEnvironment(t *testing.T) {
	if got := normalizeEnvironment("prod"); got != "production" {
		t.Fatalf("prod normalized to %q", got)
	}
	if got := normalizeEnvironment(""); got != "unknown" {
		t.Fatalf("empty normalized to %q", got)
	}
}

func TestFlagsFirstAllowsFlagsAfterInput(t *testing.T) {
	fs, _ := newPreflightFlagSet("test")
	got := flagsFirst(fs, []string{"plan.json", "-project", "demo", "-json", "-env=prod"})
	want := []string{"-project", "demo", "-json", "-env=prod", "plan.json"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("flagsFirst=%v want %v", got, want)
	}
}

// TestFlagsFirstDerivesBoolFlagsFromFlagSet: bool flags must be discovered from
// the FlagSet itself, not a hardcoded list — a newly registered bool flag must
// not swallow the next argument as its value during reordering.
func TestFlagsFirstDerivesBoolFlagsFromFlagSet(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dryRun := fs.Bool("dry-run", false, "future bool flag")
	project := fs.String("project", "", "project")

	// The positional argument comes first so reordering actually has to happen:
	// treating -dry-run as a value-taking flag would drag -project in as its
	// value and desync everything after it.
	if err := fs.Parse(flagsFirst(fs, []string{"input.json", "-dry-run", "-project", "p"})); err != nil {
		t.Fatalf("parse after flagsFirst: %v", err)
	}
	if !*dryRun {
		t.Fatalf("dry-run = false, want true")
	}
	if *project != "p" {
		t.Fatalf("project = %q, want %q (bool flag must not consume the next flag as its value)", *project, "p")
	}
	if fs.NArg() != 1 || fs.Arg(0) != "input.json" {
		t.Fatalf("positional args = %v, want [input.json]", fs.Args())
	}
}

// TestRunPreflightUnimplementedSignerExitsUsageBeforeWork: gcp-kms and
// vault-transit signers are stubs; configuring one must be rejected as a
// usage error BEFORE any scan or receipt work happens, not fail at receipt
// write time on every run.
func TestRunPreflightUnimplementedSignerExitsUsageBeforeWork(t *testing.T) {
	dir := t.TempDir()
	walDir := filepath.Join(dir, "wal")
	var code int
	stderr := captureStderr(t, func() {
		code = runPreflightTerraform([]string{
			"-wal-dir", walDir,
			"-project", "p", "-session", "s1", "-actor", "agent:x",
			"-env", "production",
			"-receipt-signer", "vault-transit",
			filepath.Join("..", "..", "internal", "preflight", "terraform", "testdata", "datatalks_destroy_plan.json"),
		})
	})
	if code != 2 {
		t.Fatalf("exit=%d want 2 (usage error before any work); stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "vault-transit") || !strings.Contains(stderr, "not yet implemented") {
		t.Fatalf("stderr %q must name the stub signer and say it is not yet implemented", stderr)
	}
	if files, _ := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl")); len(files) != 0 {
		t.Fatalf("preflight wrote receipts despite unimplemented signer: %v", files)
	}
}

// TestRunPreflightTerraformReceiptWriteFailureExitsInternalError: CI must be
// able to tell "HubbleOps blocked this" (exit 1) from "HubbleOps itself failed"
// (exit 4). A receipt write failure is an internal error, not a block.
func TestRunPreflightTerraformReceiptWriteFailureExitsInternalError(t *testing.T) {
	dir := t.TempDir()
	notADir := filepath.Join(dir, "wal-is-a-file")
	if err := os.WriteFile(notADir, []byte("occupied"), 0600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	var code int
	stderr := captureStderr(t, func() {
		code = runPreflightTerraform([]string{
			"-wal-dir", notADir,
			"-project", "p", "-session", "s1", "-actor", "agent:x",
			"-env", "production",
			"-receipt-secret", "rs",
			filepath.Join("..", "..", "internal", "preflight", "terraform", "testdata", "datatalks_destroy_plan.json"),
		})
	})
	if code != 4 {
		t.Fatalf("exit=%d want 4 (internal error: receipt not written); stderr=%s", code, stderr)
	}
}

// TestRunPreflightTerraformBlockExitsOne pins the contract: a healthy receipt
// plus a destructive plan is a real block decision, exit 1.
func TestRunPreflightTerraformBlockExitsOne(t *testing.T) {
	dir := t.TempDir()
	code := runPreflightTerraform([]string{
		"-wal-dir", filepath.Join(dir, "wal"),
		"-project", "p", "-session", "s1", "-actor", "agent:x",
		"-env", "production",
		"-receipt-secret", "rs",
		filepath.Join("..", "..", "internal", "preflight", "terraform", "testdata", "datatalks_destroy_plan.json"),
	})
	if code != 1 {
		t.Fatalf("exit=%d want 1 (block decision with healthy receipt)", code)
	}
}

// TestRunPreflightDeployUnknownFlagExitsUsageWithoutRunning: a mistyped flag
// must stop the run with a usage error BEFORE any preflight executes —
// continuing with half-parsed flags would burn wrong identity into a signed
// audit receipt and claim an idempotency key.
func TestRunPreflightDeployUnknownFlagExitsUsageWithoutRunning(t *testing.T) {
	dir := t.TempDir()
	walDir := filepath.Join(dir, "wal")
	ledgerPath := filepath.Join(dir, "ledger.json")
	var code int
	stderr := captureStderr(t, func() {
		code = runPreflightDeploy([]string{
			"-service", "api", "-artifact", "v1",
			"-wal-dir", walDir,
			"-action-ledger", ledgerPath,
			"-project", "p", "-session", "s1", "-actor", "agent:x",
			"-env", "dev", "-idempotency-key", "deploy:k9",
			"-receipt-secret", "rs",
			"-nope", // mistyped flag AFTER valid ones: earlier flags already parsed
		})
	})
	if code != 2 {
		t.Fatalf("exit=%d want 2 (usage error); stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "-nope") {
		t.Fatalf("stderr %q does not name the bad flag", stderr)
	}
	if files, _ := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl")); len(files) != 0 {
		t.Fatalf("preflight ran despite flag error: wrote receipts %v", files)
	}
	if _, err := os.Stat(ledgerPath); !os.IsNotExist(err) {
		t.Fatalf("preflight ran despite flag error: created action ledger (stat err=%v)", err)
	}
}

func TestRunPreflightDeployDoesNotMaskUnapprovedDeployAsDuplicate(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
version: engineering-gate/v1
services:
  billing-api:
    risk: tier_0
    owners:
      - billing-owner
rules:
  - id: review-tier0-prod-deploy
    if:
      action: deploy.release
      env: prod
      service_risk: tier_0
    decision: require_approval
    risk_score: 85
`), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	walDir := filepath.Join(dir, "wal")
	ledgerPath := filepath.Join(dir, "action-ledger.json")
	baseArgs := []string{
		"-service", "billing-api",
		"-artifact", "sha-123",
		"-policy", policyPath,
		"-wal-dir", walDir,
		"-action-ledger", ledgerPath,
		"-project", "proj",
		"-session", "sess-1",
		"-actor", "agent:local-cli",
		"-env", "prod",
		"-idempotency-key", "deploy:sha-123",
		"-receipt-secret", "receipt-secret",
	}
	if code := runPreflightDeploy(baseArgs); code != 3 {
		t.Fatalf("first deploy exit=%d want require_approval exit 3", code)
	}
	secondArgs := append([]string{}, baseArgs...)
	for i := range secondArgs {
		if secondArgs[i] == "sess-1" {
			secondArgs[i] = "sess-2"
		}
	}
	// An unapproved deploy never executed, so re-running the same preflight must
	// re-evaluate to require_approval — not be masked as a duplicate side-effect block.
	if code := runPreflightDeploy(secondArgs); code != 3 {
		t.Fatalf("re-run of unapproved deploy exit=%d want require_approval exit 3", code)
	}

	files, err := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("wal files=%v err=%v", files, err)
	}
	records, err := readWALRecords(files)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records=%d want 2", len(records))
	}
	for i, rec := range records {
		if rec.Decision != action.DecisionRequireApproval {
			t.Fatalf("record[%d] decision=%q want require_approval", i, rec.Decision)
		}
		if strings.Contains(rec.DecisionReason, "duplicate") {
			t.Fatalf("record[%d] reason=%q must not be a duplicate block", i, rec.DecisionReason)
		}
	}
	if len(records[0].RequiredApprovers) != 1 || records[0].RequiredApprovers[0] != "billing-owner" {
		t.Fatalf("first receipt approvers=%v want service owner", records[0].RequiredApprovers)
	}
	if records[0].IdempotencyKey != "" || records[0].IdempotencyKeyHash == "" {
		t.Fatalf("receipt idempotency privacy fields raw=%q hash=%q", records[0].IdempotencyKey, records[0].IdempotencyKeyHash)
	}
	report := receiptverify.VerifyWithOptions(records, receiptverify.Options{
		ReceiptSecret:     "receipt-secret",
		RequireSignatures: true,
	})
	if !report.Verified {
		t.Fatalf("receipt report not verified: %+v", report)
	}
}

func TestRunPreflightDeployBlocksDuplicateAfterAllow(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
version: engineering-gate/v1
services:
  docs-api:
    risk: tier_2
    owners:
      - docs-owner
`), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	walDir := filepath.Join(dir, "wal")
	ledgerPath := filepath.Join(dir, "action-ledger.json")
	baseArgs := []string{
		"-service", "docs-api",
		"-artifact", "sha-xyz",
		"-policy", policyPath,
		"-wal-dir", walDir,
		"-action-ledger", ledgerPath,
		"-project", "proj",
		"-session", "sess-1",
		"-actor", "agent:local-cli",
		"-env", "dev",
		"-idempotency-key", "deploy:docs:sha-xyz",
		"-receipt-secret", "receipt-secret",
	}
	if code := runPreflightDeploy(baseArgs); code != 0 {
		t.Fatalf("first allow deploy exit=%d want allow exit 0", code)
	}
	secondArgs := append([]string{}, baseArgs...)
	for i := range secondArgs {
		if secondArgs[i] == "sess-1" {
			secondArgs[i] = "sess-2"
		}
	}
	// An authorized (allow) deploy commits its idempotency key, so an identical re-run
	// must be blocked as a duplicate side-effect.
	if code := runPreflightDeploy(secondArgs); code != 1 {
		t.Fatalf("duplicate of allowed deploy exit=%d want block exit 1", code)
	}

	files, err := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("wal files=%v err=%v", files, err)
	}
	records, err := readWALRecords(files)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records=%d want 2", len(records))
	}
	if records[0].Decision != action.DecisionAllow {
		t.Fatalf("first receipt decision=%q want allow", records[0].Decision)
	}
	if records[1].Decision != action.DecisionBlock || !strings.Contains(records[1].DecisionReason, "duplicate") {
		t.Fatalf("duplicate receipt decision=%q reason=%q", records[1].Decision, records[1].DecisionReason)
	}
}

func deployArgs(dir, session, key string) []string {
	return []string{
		"-service", "api", "-artifact", "v1",
		"-wal-dir", filepath.Join(dir, "wal"),
		"-action-ledger", filepath.Join(dir, "ledger.json"),
		"-project", "p", "-session", session, "-actor", "agent:x",
		"-env", "dev", "-idempotency-key", key,
		"-receipt-secret", "rs",
	}
}

func TestRunPreflightDeployResultFailedFreesKey(t *testing.T) {
	dir := t.TempDir()
	if code := runPreflightDeploy(deployArgs(dir, "s1", "deploy:k1")); code != 0 {
		t.Fatalf("first deploy=%d want 0 allow", code)
	}
	if code := runPreflightDeploy(deployArgs(dir, "s2", "deploy:k1")); code != 1 {
		t.Fatalf("duplicate deploy=%d want 1 block", code)
	}
	// A failed deploy result must free the committed key so a retry is allowed.
	resultArgs := append(deployArgs(dir, "s3", "deploy:k1"), "-status", "failed")
	if code := runPreflightDeployResult(resultArgs); code != 0 {
		t.Fatalf("deploy-result failed=%d want 0", code)
	}
	if code := runPreflightDeploy(deployArgs(dir, "s4", "deploy:k1")); code != 0 {
		t.Fatalf("retry after failure=%d want 0 allow (key should be freed)", code)
	}
}

func TestRunPreflightDeployResultSuccessKeepsKey(t *testing.T) {
	dir := t.TempDir()
	if code := runPreflightDeploy(deployArgs(dir, "s1", "deploy:k2")); code != 0 {
		t.Fatalf("first deploy=%d want 0 allow", code)
	}
	resultArgs := append(deployArgs(dir, "s2", "deploy:k2"), "-status", "success")
	if code := runPreflightDeployResult(resultArgs); code != 0 {
		t.Fatalf("deploy-result success=%d want 0", code)
	}
	// A successful result keeps the key committed, so a duplicate is still blocked.
	if code := runPreflightDeploy(deployArgs(dir, "s3", "deploy:k2")); code != 1 {
		t.Fatalf("duplicate after success=%d want 1 block", code)
	}
}

func TestRunPreflightMigrationJSONSanitizesOutputCanaries(t *testing.T) {
	dir := t.TempDir()
	migrationPath := filepath.Join(dir, "raw_customer_name_AcmePrivate.sql")
	if err := os.WriteFile(migrationPath, []byte(`
-- customer@example.com
DROP TABLE private_customers;
`), 0600); err != nil {
		t.Fatalf("write migration: %v", err)
	}
	walDir := filepath.Join(dir, "wal")
	var code int
	output := captureStdout(t, func() {
		code = runPreflightMigration([]string{
			"-json",
			"-wal-dir", walDir,
			"-project", "customer@example.com",
			"-session", "sess-sk_live_hubbleops_secret",
			"-actor", "agent:customer@example.com",
			"-intent", "password=correct-horse-battery-staple",
			"-receipt-secret", "receipt-secret",
			migrationPath,
		})
	})
	if code != 1 {
		t.Fatalf("migration exit=%d want block exit 1; output=%s", code, output)
	}
	for _, forbidden := range []string{
		"customer@example.com",
		"sk_live_hubbleops_secret",
		"raw_customer_name_AcmePrivate",
		"password=correct-horse-battery-staple",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("CLI JSON output leaked %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "fingerprint:sha256:") {
		t.Fatalf("CLI JSON output missing fingerprints: %s", output)
	}
	files, err := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("wal files=%v err=%v", files, err)
	}
	records, err := readWALRecords(files)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal wal: %v", err)
	}
	for _, forbidden := range []string{
		"customer@example.com",
		"sk_live_hubbleops_secret",
		"raw_customer_name_AcmePrivate",
		"password=correct-horse-battery-staple",
	} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("WAL leaked %q: %s", forbidden, string(data))
		}
	}
}

func TestRunPhase4DemoWritesExpectedSignedReceipts(t *testing.T) {
	dir := t.TempDir()
	walDir := filepath.Join(dir, "wal")
	approvalPath := filepath.Join(dir, "approvals.json")
	if code := runPhase4Demo([]string{
		"-wal-dir", walDir,
		"-approval-store", approvalPath,
		"-receipt-secret", "receipt-secret",
		"-receipt-key-id", "test",
	}); code != 0 {
		t.Fatalf("phase4 demo exit=%d want 0", code)
	}
	files, err := filepath.Glob(filepath.Join(walDir, "wal-*.jsonl"))
	if err != nil || len(files) != 1 {
		t.Fatalf("wal files=%v err=%v", files, err)
	}
	records, err := readWALRecords(files)
	if err != nil {
		t.Fatalf("read wal: %v", err)
	}
	if len(records) != 21 {
		t.Fatalf("records=%d want 21 (20 initial + 1 approved)", len(records))
	}
	counts := map[string]int{}
	approvedReceipt := false
	for _, rec := range records {
		counts[rec.Decision]++
		if rec.Decision == action.DecisionAllow && len(rec.Approvals) == 1 && strings.Contains(rec.DecisionEvidence, "approval_status=approved") {
			approvedReceipt = true
		}
	}
	if counts[action.DecisionAllow] != 15 || counts[action.DecisionRequireApproval] != 4 || counts[action.DecisionBlock] != 2 {
		t.Fatalf("decision counts=%v want allow=15 require_approval=4 block=2", counts)
	}
	if !approvedReceipt {
		t.Fatalf("approved receipt with reviewer fingerprint was not written")
	}
	report := receiptverify.VerifyWithOptions(records, receiptverify.Options{
		ReceiptSecret:     "receipt-secret",
		RequireSignatures: true,
	})
	if !report.Verified {
		t.Fatalf("receipt report not verified: %+v", report)
	}

	data, err := os.ReadFile(approvalPath)
	if err != nil {
		t.Fatalf("read approvals: %v", err)
	}
	var state struct {
		Approvals map[string]approval.Record `json:"approvals"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("decode approvals: %v", err)
	}
	if len(state.Approvals) != 4 {
		t.Fatalf("approvals=%d want 4", len(state.Approvals))
	}
	statuses := map[string]int{}
	for _, rec := range state.Approvals {
		statuses[rec.Status]++
		if rec.ReviewerSource != "" && rec.Reviewer == "" {
			t.Fatalf("reviewed approval missing reviewer: %+v", rec)
		}
		if !rec.ReviewedAt.IsZero() && rec.ReviewerSource == "" {
			t.Fatalf("reviewed approval missing source: %+v", rec)
		}
	}
	if statuses[approval.StatusApproved] != 1 || statuses[approval.StatusPending] != 3 {
		t.Fatalf("approval statuses=%v want approved=1 pending=3", statuses)
	}
	if strings.Contains(string(data), "phase4 demo approval") {
		t.Fatalf("approval store leaked raw review comment: %s", string(data))
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	_ = r.Close()
	return string(data)
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	fn()
	_ = w.Close()
	os.Stderr = old
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	_ = r.Close()
	return string(data)
}
