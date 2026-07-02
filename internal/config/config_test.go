package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyConfigParsesFromYAML(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "hubbleops.yaml")
	yaml := `
policy:
  path: configs/customer-policy.yaml
wal:
  sync_mode: sync
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Policy.Path != "configs/customer-policy.yaml" {
		t.Fatalf("policy path=%q", cfg.Policy.Path)
	}
	if cfg.WAL.SyncMode != "sync" {
		t.Fatalf("wal sync=%q", cfg.WAL.SyncMode)
	}
}

func TestAuthDefaultsAreProductionSafe(t *testing.T) {
	clearEnv(t)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Environment != "prod" || !cfg.Auth.Enabled || cfg.Auth.DevBypass || cfg.Auth.MetricsPublic {
		t.Fatalf("unsafe auth defaults: %+v", cfg.Auth)
	}
	if cfg.Capture.Mode != CaptureModeFingerprint || cfg.OutcomeCapture.Mode != CaptureModeFingerprint || cfg.OutcomeCapture.Raw {
		t.Fatalf("unsafe capture defaults: capture=%+v outcome=%+v", cfg.Capture, cfg.OutcomeCapture)
	}
	if !cfg.Receipts.RequireForBlock || cfg.Receipts.EnforceWithoutReceipt {
		t.Fatalf("unsafe receipt defaults: %+v", cfg.Receipts)
	}
}

func TestDevAuthBypassOnlyHonoredInDev(t *testing.T) {
	clearEnv(t)
	t.Setenv("HUBBLEOPS_ENV", "prod")
	t.Setenv("HUBBLEOPS_DEV_AUTH_BYPASS", "true")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Auth.DevBypass {
		t.Fatalf("prod honored dev bypass")
	}

	clearEnv(t)
	t.Setenv("HUBBLEOPS_ENV", "dev")
	t.Setenv("HUBBLEOPS_DEV_AUTH_BYPASS", "true")
	cfg, err = Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Auth.DevBypass {
		t.Fatalf("dev bypass not honored in dev")
	}
}

func TestPolicyEnvOverride(t *testing.T) {
	clearEnv(t)
	t.Setenv("HUBBLEOPS_POLICY", "configs/override.yaml")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Policy.Path != "configs/override.yaml" {
		t.Fatalf("policy path=%q", cfg.Policy.Path)
	}
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"HUBBLEOPS_ENV",
		"HUBBLEOPS_AUTH_ENABLED",
		"HUBBLEOPS_DEV_AUTH_BYPASS",
		"HUBBLEOPS_METRICS_PUBLIC",
		"HUBBLEOPS_CAPTURE_MODE",
		"HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD",
		"HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD_NOTE",
		"HUBBLEOPS_OUTCOME_CAPTURE_ENABLED",
		"HUBBLEOPS_OUTCOME_CAPTURE_MODE",
		"HUBBLEOPS_OUTCOME_CAPTURE_RAW",
		"HUBBLEOPS_REVIEW_RAW_NOTES",
		"HUBBLEOPS_REQUIRE_RECEIPT_FOR_BLOCK",
		"HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT",
		"HUBBLEOPS_POLICY",
	} {
		t.Setenv(key, "")
	}
}
