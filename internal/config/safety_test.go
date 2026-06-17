package config

import (
	"strings"
	"testing"
)

func TestProdMissingAuthConfigFails(t *testing.T) {
	cfg := productionSafeTestConfig()
	cfg.Auth.Enabled = false

	_, err := cfg.Validate(RuntimeSecrets{ReceiptSigningSecretSet: true})
	if err == nil {
		t.Fatalf("Validate succeeded, want auth failure")
	}
	if !strings.Contains(err.Error(), "HUBBLEOPS_AUTH_ENABLED=true") {
		t.Fatalf("error %q does not mention auth", err.Error())
	}
}

func TestProdMissingReceiptSigningSecretFails(t *testing.T) {
	cfg := productionSafeTestConfig()

	_, err := cfg.Validate(RuntimeSecrets{})
	if err == nil {
		t.Fatalf("Validate succeeded, want receipt signing failure")
	}
	if !strings.Contains(err.Error(), "HUBBLEOPS_RECEIPT_SIGNING_SECRET") {
		t.Fatalf("error %q does not mention receipt signing", err.Error())
	}
}

func TestProdRawCaptureFailsUnlessExplicit(t *testing.T) {
	cfg := productionSafeTestConfig()
	cfg.Capture.Mode = "raw"

	_, err := cfg.Validate(RuntimeSecrets{ReceiptSigningSecretSet: true})
	if err == nil {
		t.Fatalf("Validate succeeded, want raw capture failure")
	}
	if !strings.Contains(err.Error(), "HUBBLEOPS_CAPTURE_MODE=raw") {
		t.Fatalf("error %q does not mention raw capture", err.Error())
	}

	cfg.Capture.AllowRawInProd = true
	result, err := cfg.Validate(RuntimeSecrets{ReceiptSigningSecretSet: true})
	if err != nil {
		t.Fatalf("Validate explicit raw capture: %v", err)
	}
	if !hasWarning(result.Warnings, "raw capture explicitly enabled") {
		t.Fatalf("warnings %v do not mention raw capture", result.Warnings)
	}
}

func TestProdBlockModeRequiresSessionSafetyFloor(t *testing.T) {
	cfg := productionSafeTestConfig()
	cfg.LoopDetection.Action = "block"
	cfg.LoopDetection.RequireSessionForBlock = false

	_, err := cfg.Validate(RuntimeSecrets{ReceiptSigningSecretSet: true})
	if err == nil {
		t.Fatalf("Validate succeeded, want block session failure")
	}
	if !strings.Contains(err.Error(), "HUBBLEOPS_LOOP_REQUIRE_SESSION_FOR_BLOCK=true") {
		t.Fatalf("error %q does not mention session safety floor", err.Error())
	}
}

func TestProdOutcomeCaptureStaysFingerprintOnly(t *testing.T) {
	cfg := productionSafeTestConfig()
	cfg.OutcomeCapture.Mode = "raw"

	_, err := cfg.Validate(RuntimeSecrets{ReceiptSigningSecretSet: true})
	if err == nil {
		t.Fatalf("Validate succeeded, want outcome capture mode failure")
	}
	if !strings.Contains(err.Error(), "HUBBLEOPS_OUTCOME_CAPTURE_MODE=fingerprint") {
		t.Fatalf("error %q does not mention outcome capture mode", err.Error())
	}

	cfg = productionSafeTestConfig()
	cfg.OutcomeCapture.Raw = true
	_, err = cfg.Validate(RuntimeSecrets{ReceiptSigningSecretSet: true})
	if err == nil {
		t.Fatalf("Validate succeeded, want raw outcome capture failure")
	}
	if !strings.Contains(err.Error(), "HUBBLEOPS_OUTCOME_CAPTURE_RAW=true") {
		t.Fatalf("error %q does not mention raw outcome capture", err.Error())
	}
}

func TestProdRawReviewNotesRequireRawCaptureOverride(t *testing.T) {
	cfg := productionSafeTestConfig()
	cfg.Reviews.RawNotes = true

	_, err := cfg.Validate(RuntimeSecrets{ReceiptSigningSecretSet: true})
	if err == nil {
		t.Fatalf("Validate succeeded, want raw review notes failure")
	}
	if !strings.Contains(err.Error(), "raw review notes") {
		t.Fatalf("error %q does not mention raw review notes", err.Error())
	}

	cfg.Capture.Mode = "raw"
	cfg.Capture.AllowRawInProd = true
	result, err := cfg.Validate(RuntimeSecrets{ReceiptSigningSecretSet: true})
	if err != nil {
		t.Fatalf("Validate raw review notes with explicit override: %v", err)
	}
	if !hasWarning(result.Warnings, "raw capture explicitly enabled") {
		t.Fatalf("warnings %v missing raw capture warning", result.Warnings)
	}
}

func TestDevStartsWithWarnings(t *testing.T) {
	cfg := productionSafeTestConfig()
	cfg.Environment = "dev"
	cfg.Auth.Enabled = false
	cfg.Auth.DevBypass = true
	cfg.Auth.MetricsPublic = true
	cfg.Capture.Mode = "raw"
	cfg.OutcomeCapture.Mode = "raw"
	cfg.OutcomeCapture.Raw = true
	cfg.Reviews.RawNotes = true

	result, err := cfg.Validate(RuntimeSecrets{})
	if err != nil {
		t.Fatalf("Validate dev config: %v", err)
	}
	for _, want := range []string{
		"auth disabled",
		"dev auth bypass",
		"metrics endpoint is public",
		"receipt signing secret unset",
		"raw capture enabled",
		"raw outcome capture requested",
		"raw review notes enabled",
	} {
		if !hasWarning(result.Warnings, want) {
			t.Fatalf("warnings %v missing %q", result.Warnings, want)
		}
	}
}

func TestSecretsRedactedInConfigOutput(t *testing.T) {
	cfg := productionSafeTestConfig()
	cfg.Postgres.Password = "postgres-super-secret"
	cfg.Redis.Password = "redis-super-secret"
	cfg.Alerts.WebhookURL = "https://hooks.example.test/services/token-secret"

	out := cfg.RedactedSummaryJSON(RuntimeSecrets{
		ReceiptSigningSecretSet:   true,
		ActionCapabilitySecretSet: true,
	})
	for _, leaked := range []string{
		"postgres-super-secret",
		"redis-super-secret",
		"token-secret",
	} {
		if strings.Contains(out, leaked) {
			t.Fatalf("redacted summary leaked %q: %s", leaked, out)
		}
	}
	if !strings.Contains(out, redacted) {
		t.Fatalf("redacted summary missing redaction marker: %s", out)
	}
	if !strings.Contains(out, `"receipt_signing_secret":"set"`) {
		t.Fatalf("redacted summary missing secret presence: %s", out)
	}
}

func TestRedactURLHidesCredentialsAndSecretQuery(t *testing.T) {
	got := RedactURL("https://user:pass@example.test/path?api_key=secret&model=ok")
	if strings.Contains(got, "user") || strings.Contains(got, "pass") || strings.Contains(got, "secret") {
		t.Fatalf("RedactURL leaked secret: %s", got)
	}
	if !strings.Contains(got, "redacted") || !strings.Contains(got, "model=ok") {
		t.Fatalf("RedactURL = %s", got)
	}
}

func productionSafeTestConfig() *Config {
	cfg, err := Load("")
	if err != nil {
		panic(err)
	}
	cfg.Environment = "prod"
	cfg.Auth.Enabled = true
	cfg.Auth.DevBypass = false
	cfg.Auth.MetricsPublic = false
	cfg.Capture.Mode = "fingerprint"
	cfg.Capture.AllowRawInProd = false
	cfg.OutcomeCapture.Enabled = true
	cfg.OutcomeCapture.Mode = "fingerprint"
	cfg.OutcomeCapture.Raw = false
	cfg.Reviews.RawNotes = false
	cfg.WAL.Dir = "data/wal"
	cfg.WAL.SyncMode = "batch"
	cfg.Receipts.RequireForBlock = true
	cfg.Receipts.EnforceWithoutReceipt = false
	cfg.LoopDetection.Enabled = true
	cfg.LoopDetection.Action = "shadow"
	cfg.LoopDetection.RequireSessionForBlock = true
	return cfg
}

func hasWarning(warnings []string, want string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, want) {
			return true
		}
	}
	return false
}
