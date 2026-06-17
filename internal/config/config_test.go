package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLimitsConfigParsesFromYAML(t *testing.T) {
	clearAuthEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.yaml")
	yaml := `
limits:
  cumulative:
    - name: refunds-per-agent-hour
      tool: refund_customer
      scope: agent
      window_seconds: 3600
      max_amount_cents: 10000
  velocity:
    - name: money-moves-per-minute
      min_risk: write
      scope: agent
      window_seconds: 60
      max_actions: 10
  breaker:
    trips: 5
    window_seconds: 600
    cooldown_seconds: 900
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Limits.Cumulative) != 1 || cfg.Limits.Cumulative[0].MaxAmountCents != 10_000 || cfg.Limits.Cumulative[0].Tool != "refund_customer" {
		t.Fatalf("cumulative=%+v", cfg.Limits.Cumulative)
	}
	if len(cfg.Limits.Velocity) != 1 || cfg.Limits.Velocity[0].MaxActions != 10 || cfg.Limits.Velocity[0].WindowSeconds != 60 {
		t.Fatalf("velocity=%+v", cfg.Limits.Velocity)
	}
	if cfg.Limits.Breaker.Trips != 5 || cfg.Limits.Breaker.CooldownSeconds != 900 {
		t.Fatalf("breaker=%+v", cfg.Limits.Breaker)
	}
}

// A half-declared limit must fail validation loudly, not silently never fire.
func TestValidateRejectsBrokenLimitRules(t *testing.T) {
	cases := map[string]func(*Config){
		"cumulative without window": func(c *Config) {
			c.Limits.Cumulative = []CumulativeLimit{{Name: "x", MaxAmountCents: 100}}
		},
		"cumulative without cap": func(c *Config) {
			c.Limits.Cumulative = []CumulativeLimit{{Name: "x", WindowSeconds: 60}}
		},
		"cumulative with unknown scope": func(c *Config) {
			c.Limits.Cumulative = []CumulativeLimit{{Name: "x", WindowSeconds: 60, MaxAmountCents: 100, Scope: "customerz"}}
		},
		"velocity without max": func(c *Config) {
			c.Limits.Velocity = []VelocityLimit{{Name: "x", WindowSeconds: 60}}
		},
		"breaker without cooldown": func(c *Config) {
			c.Limits.Breaker = BreakerLimit{Trips: 3, WindowSeconds: 60}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			clearAuthEnv(t)
			cfg, err := Load("")
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			mutate(cfg)
			if _, err := cfg.Validate(RuntimeSecrets{ReceiptSigningSecretSet: true, ActionCapabilitySecretSet: true}); err == nil {
				t.Fatalf("validation accepted a broken limit rule")
			} else if !strings.Contains(err.Error(), "limits") {
				t.Fatalf("error does not mention limits: %v", err)
			}
		})
	}
}

func TestAuthDefaultsAreProductionSafe(t *testing.T) {
	clearAuthEnv(t)
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Environment != "prod" {
		t.Fatalf("environment=%q want prod", cfg.Environment)
	}
	if !cfg.Auth.Enabled {
		t.Fatalf("auth enabled=false want true")
	}
	if cfg.Auth.DevBypass {
		t.Fatalf("dev auth bypass=true want false")
	}
	if cfg.Auth.MetricsPublic {
		t.Fatalf("metrics public=true want false")
	}
	if !cfg.Receipts.RequireForBlock {
		t.Fatalf("require receipt for block=false want true")
	}
	if cfg.Receipts.EnforceWithoutReceipt {
		t.Fatalf("enforce without receipt=true want false")
	}
	if !cfg.OutcomeCapture.Enabled {
		t.Fatalf("outcome capture enabled=false want true")
	}
	if cfg.OutcomeCapture.Mode != "fingerprint" {
		t.Fatalf("outcome capture mode=%q want fingerprint", cfg.OutcomeCapture.Mode)
	}
	if cfg.OutcomeCapture.Raw {
		t.Fatalf("outcome capture raw=true want false")
	}
	if cfg.Reviews.RawNotes {
		t.Fatalf("review raw notes=true want false")
	}
}

func TestDevAuthBypassOnlyHonoredInDev(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("HUBBLEOPS_ENV", "prod")
	t.Setenv("HUBBLEOPS_DEV_AUTH_BYPASS", "true")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Auth.DevBypass {
		t.Fatalf("prod dev_auth_bypass=true was honored")
	}

	clearAuthEnv(t)
	t.Setenv("HUBBLEOPS_ENV", "dev")
	t.Setenv("HUBBLEOPS_DEV_AUTH_BYPASS", "true")
	cfg, err = Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.Auth.DevBypass {
		t.Fatalf("dev auth bypass=false want true")
	}
}

func TestAuthEnvOverrides(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("HUBBLEOPS_AUTH_ENABLED", "false")
	t.Setenv("HUBBLEOPS_METRICS_PUBLIC", "true")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Auth.Enabled {
		t.Fatalf("auth enabled=true want false")
	}
	if !cfg.Auth.MetricsPublic {
		t.Fatalf("metrics public=false want true")
	}
}

func TestReceiptEnvOverrides(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("HUBBLEOPS_REQUIRE_RECEIPT_FOR_BLOCK", "false")
	t.Setenv("HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT", "true")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Receipts.RequireForBlock {
		t.Fatalf("require receipt for block=true want false")
	}
	if !cfg.Receipts.EnforceWithoutReceipt {
		t.Fatalf("enforce without receipt=false want true")
	}
}

func TestCaptureEnvOverrides(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("HUBBLEOPS_CAPTURE_MODE", "raw")
	t.Setenv("HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD", "true")
	t.Setenv("HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD_NOTE", "incident-debug-window")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Capture.Mode != "raw" {
		t.Fatalf("capture mode=%q want raw", cfg.Capture.Mode)
	}
	if !cfg.Capture.AllowRawInProd {
		t.Fatalf("allow raw in prod=false want true")
	}
	if cfg.Capture.AllowRawInProdNote != "incident-debug-window" {
		t.Fatalf("allow raw note=%q", cfg.Capture.AllowRawInProdNote)
	}
}

func TestOutcomeCaptureEnvOverrides(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("HUBBLEOPS_OUTCOME_CAPTURE_ENABLED", "false")
	t.Setenv("HUBBLEOPS_OUTCOME_CAPTURE_MODE", "raw")
	t.Setenv("HUBBLEOPS_OUTCOME_CAPTURE_RAW", "true")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.OutcomeCapture.Enabled {
		t.Fatalf("outcome capture enabled=true want false")
	}
	if cfg.OutcomeCapture.Mode != "raw" {
		t.Fatalf("outcome capture mode=%q want raw", cfg.OutcomeCapture.Mode)
	}
	if !cfg.OutcomeCapture.Raw {
		t.Fatalf("outcome capture raw=false want true")
	}
}

func TestReviewRawNotesEnvOverride(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("HUBBLEOPS_REVIEW_RAW_NOTES", "true")
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.Reviews.RawNotes {
		t.Fatalf("review raw notes=false want true")
	}
}

func clearAuthEnv(t *testing.T) {
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
	} {
		t.Setenv(key, "")
	}
}
