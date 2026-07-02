package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hubbleops/hubbleops/internal/config"
)

// TestGateStartupUnknownFlagPrintsUsageToStderr: a flag error must be visible.
// The flag set previously wrote to io.Discard, so a typo produced only a bare
// "configure gate" fatal with no usage text naming the bad flag.
func TestGateStartupUnknownFlagPrintsUsageToStderr(t *testing.T) {
	clearGateStartupEnv(t)

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	_, runtimeErr := newGateRuntime([]string{"-nope"})
	_ = w.Close()
	os.Stderr = old
	captured := make([]byte, 64*1024)
	n, _ := r.Read(captured)
	_ = r.Close()

	if runtimeErr == nil {
		t.Fatalf("newGateRuntime succeeded, want flag parse error")
	}
	if stderr := string(captured[:n]); !strings.Contains(stderr, "-nope") {
		t.Fatalf("stderr %q does not name the unknown flag; usage text is being swallowed", stderr)
	}
}

// TestGateStartupRejectsUnimplementedSigner: gcp-kms and vault-transit are
// stubs whose SignRecord fails on every write. Configuring one must refuse to
// start with a clear error instead of failing at runtime per receipt.
func TestGateStartupRejectsUnimplementedSigner(t *testing.T) {
	for _, signer := range []string{"gcp-kms", "vault-transit"} {
		t.Run(signer, func(t *testing.T) {
			clearGateStartupEnv(t)
			// dev is where the stub previously slipped past config.Validate and
			// failed at runtime on every receipt write.
			t.Setenv("HUBBLEOPS_ENV", "dev")
			t.Setenv("HUBBLEOPS_AUTH_ENABLED", "false")
			t.Setenv("HUBBLEOPS_WAL_DIR", t.TempDir())

			_, err := newGateRuntime([]string{"-policy=", "-approval-store=", "-receipt-signer", signer})
			if err == nil {
				t.Fatalf("newGateRuntime succeeded with stub signer %q, want configuration error", signer)
			}
			if !strings.Contains(err.Error(), signer) || !strings.Contains(err.Error(), "not yet implemented") {
				t.Fatalf("error %q must name %q and say it is not yet implemented", err.Error(), signer)
			}
		})
	}
}

func TestGateStartupRejectsProdAuthDisabled(t *testing.T) {
	clearGateStartupEnv(t)
	t.Setenv("HUBBLEOPS_ENV", "prod")
	t.Setenv("HUBBLEOPS_AUTH_ENABLED", "false")
	t.Setenv("HUBBLEOPS_RECEIPT_SIGNER", "aws-kms")
	t.Setenv("HUBBLEOPS_RECEIPT_KMS_KEY_ID", "arn:aws:kms:us-east-1:123:key/prod")
	t.Setenv("HUBBLEOPS_RECEIPT_KMS_REGION", "us-east-1")
	t.Setenv("HUBBLEOPS_WAL_DIR", t.TempDir())

	runtime, err := newGateRuntime([]string{"-policy=", "-approval-store="})
	if err == nil {
		t.Fatalf("newGateRuntime succeeded, want validation error")
	}
	var validationErr config.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error type=%T want config.ValidationError: %v", err, err)
	}
	if !strings.Contains(err.Error(), "HUBBLEOPS_AUTH_ENABLED=true") {
		t.Fatalf("error %q does not mention auth", err.Error())
	}
	if !strings.Contains(runtime.redactedSummaryJSON, `"enabled":false`) {
		t.Fatalf("startup did not surface redacted unsafe config: %s", runtime.redactedSummaryJSON)
	}
}

func TestGateStartupRejectsProdMissingExternalReceiptSigner(t *testing.T) {
	clearGateStartupEnv(t)
	t.Setenv("HUBBLEOPS_ENV", "prod")
	t.Setenv("HUBBLEOPS_GATE_TOKENS", "owner-token=owner:sre")
	t.Setenv("HUBBLEOPS_WAL_DIR", t.TempDir())

	_, err := newGateRuntime([]string{"-policy=", "-approval-store="})
	if err == nil {
		t.Fatalf("newGateRuntime succeeded, want validation error")
	}
	var validationErr config.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error type=%T want config.ValidationError: %v", err, err)
	}
	if !strings.Contains(err.Error(), "external receipt signer") {
		t.Fatalf("error %q does not mention external receipt signer", err.Error())
	}
}

func TestGateStartupRejectsProdLocalSecretSigner(t *testing.T) {
	clearGateStartupEnv(t)
	t.Setenv("HUBBLEOPS_ENV", "prod")
	t.Setenv("HUBBLEOPS_GATE_TOKENS", "owner-token=owner:sre")
	t.Setenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET", "super-secret")
	t.Setenv("HUBBLEOPS_RECEIPT_SIGNER", "local")
	t.Setenv("HUBBLEOPS_WAL_DIR", t.TempDir())

	_, err := newGateRuntime([]string{"-policy=", "-approval-store="})
	if err == nil {
		t.Fatalf("newGateRuntime succeeded, want validation error")
	}
	var validationErr config.ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error type=%T want config.ValidationError: %v", err, err)
	}
	if !strings.Contains(err.Error(), "forbids LocalSecretSigner") {
		t.Fatalf("error %q does not mention local signer", err.Error())
	}
}

func TestGateStartupValidProdAppliesConfigAndSurfacesWarnings(t *testing.T) {
	clearGateStartupEnv(t)
	walDir := t.TempDir()
	t.Setenv("HUBBLEOPS_ENV", "prod")
	t.Setenv("HUBBLEOPS_GATE_TOKENS", "owner-token=owner:sre")
	t.Setenv("HUBBLEOPS_RECEIPT_SIGNER", "aws-kms")
	t.Setenv("HUBBLEOPS_RECEIPT_KMS_KEY_ID", "arn:aws:kms:us-east-1:123:key/prod")
	t.Setenv("HUBBLEOPS_RECEIPT_KMS_REGION", "us-east-1")
	t.Setenv("HUBBLEOPS_RECEIPT_KEY_ID", "prod-key")
	t.Setenv("HUBBLEOPS_WAL_DIR", walDir)
	t.Setenv("HUBBLEOPS_WAL_SYNC_MODE", "sync")
	t.Setenv("HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT", "true")

	runtime, err := newGateRuntime([]string{"-policy=", "-approval-store="})
	if err != nil {
		t.Fatalf("newGateRuntime valid prod: %v", err)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			t.Fatalf("runtime close: %v", err)
		}
	}()
	if runtime.server == nil {
		t.Fatalf("runtime server is nil")
	}
	if !hasStartupWarning(runtime.warnings, "unaudited blocks") {
		t.Fatalf("warnings %v missing enforce-without-receipt warning", runtime.warnings)
	}
	if !runtime.server.authEnabled() {
		t.Fatalf("validated auth config was not applied to server")
	}
	if _, ok := runtime.server.auth.lookup("owner-token"); !ok {
		t.Fatalf("configured gate token was not wired into server auth")
	}
	if runtime.server.receiptOpts.WALDir != walDir || runtime.server.receiptOpts.WALSyncMode != "sync" {
		t.Fatalf("validated WAL config not applied: %+v", runtime.server.receiptOpts)
	}
	if runtime.server.receiptOpts.ReceiptSecret != "" || runtime.server.receiptOpts.ReceiptKeyID != "prod-key" || runtime.server.receiptOpts.ReceiptSigner == nil {
		t.Fatalf("receipt signing config not applied: %+v", runtime.server.receiptOpts)
	}
	if !runtime.server.receiptConfig.RequireForBlock || !runtime.server.receiptConfig.EnforceWithoutReceipt {
		t.Fatalf("receipt safety config not applied: %+v", runtime.server.receiptConfig)
	}
	if strings.Contains(runtime.redactedSummaryJSON, "arn:aws:kms") {
		t.Fatalf("redacted summary leaked KMS key id: %s", runtime.redactedSummaryJSON)
	}
	if !strings.Contains(runtime.redactedSummaryJSON, `"signer":"aws-kms"`) {
		t.Fatalf("redacted summary missing receipt signer: %s", runtime.redactedSummaryJSON)
	}
}

func TestGateStartupCreatesSharedReceiptWriter(t *testing.T) {
	clearGateStartupEnv(t)
	walDir := t.TempDir()
	t.Setenv("HUBBLEOPS_ENV", "dev")
	t.Setenv("HUBBLEOPS_AUTH_ENABLED", "false")
	t.Setenv("HUBBLEOPS_WAL_DIR", walDir)
	t.Setenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET", "startup-shared-writer-secret")

	runtime, err := newGateRuntime([]string{"-policy=", "-approval-store="})
	if err != nil {
		t.Fatalf("newGateRuntime: %v", err)
	}
	if runtime.server == nil {
		t.Fatalf("runtime server is nil")
	}
	if runtime.server.receiptWriter == nil {
		t.Fatalf("gate did not create a shared receipt writer")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("runtime close: %v", err)
	}
}

func TestGateStartupRejectsInvalidPolicy(t *testing.T) {
	clearGateStartupEnv(t)
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(`
version: engineering-gate/v1
rules:
  - id: ""
    if: {}
    decision: quarantine
    risk_score: 200
`), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	t.Setenv("HUBBLEOPS_ENV", "dev")
	t.Setenv("HUBBLEOPS_AUTH_ENABLED", "false")
	t.Setenv("HUBBLEOPS_WAL_DIR", filepath.Join(dir, "wal"))
	t.Setenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET", "startup-invalid-policy-secret")

	_, err := newGateRuntime([]string{"-policy", policyPath, "-approval-store="})
	if err == nil {
		t.Fatalf("newGateRuntime succeeded, want invalid policy error")
	}
	for _, want := range []string{"load policy", policyPath, "rules[0].id is required", "quarantine", "risk_score"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err.Error(), want)
		}
	}
}

func clearGateStartupEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"HUBBLEOPS_ENV",
		"HUBBLEOPS_AUTH_ENABLED",
		"HUBBLEOPS_DEV_AUTH_BYPASS",
		"HUBBLEOPS_METRICS_PUBLIC",
		"HUBBLEOPS_GATE_AUTH_DISABLED",
		"HUBBLEOPS_GATE_TOKENS",
		"HUBBLEOPS_GATE_ADDR",
		"HUBBLEOPS_WAL_DIR",
		"HUBBLEOPS_WAL_SYNC_MODE",
		"HUBBLEOPS_RECEIPT_SIGNING_SECRET",
		"HUBBLEOPS_RECEIPT_SIGNING_SECRET_FILE",
		"HUBBLEOPS_RECEIPT_KEY_ID",
		"HUBBLEOPS_RECEIPT_SIGNER",
		"HUBBLEOPS_RECEIPT_KMS_KEY_ID",
		"HUBBLEOPS_RECEIPT_KMS_REGION",
		"HUBBLEOPS_RECEIPT_KMS_ENDPOINT",
		"AWS_REGION",
		"AWS_DEFAULT_REGION",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"HUBBLEOPS_APPROVAL_STORE",
		"HUBBLEOPS_SLACK_WEBHOOK_URL",
		"HUBBLEOPS_POLICY",
		"HUBBLEOPS_REQUIRE_RECEIPT_FOR_BLOCK",
		"HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT",
		"HUBBLEOPS_CAPTURE_MODE",
		"HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD",
		"HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD_NOTE",
		"HUBBLEOPS_OUTCOME_CAPTURE_ENABLED",
		"HUBBLEOPS_OUTCOME_CAPTURE_MODE",
		"HUBBLEOPS_OUTCOME_CAPTURE_RAW",
		"HUBBLEOPS_REVIEW_RAW_NOTES",
		"GITHUB_WEBHOOK_SECRET",
		"GITHUB_APP_ID",
		"GITHUB_APP_PRIVATE_KEY",
		"GITHUB_APP_PRIVATE_KEY_FILE",
		"GITHUB_API_URL",
		"HUBBLEOPS_GITHUB_CHECK_NAME",
	} {
		t.Setenv(key, "")
	}
}

func hasStartupWarning(warnings []string, want string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, want) {
			return true
		}
	}
	return false
}
