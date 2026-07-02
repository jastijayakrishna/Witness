package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

const (
	EnvironmentDev  = "dev"
	EnvironmentTest = "test"
	EnvironmentProd = "prod"

	CaptureModeFingerprint = "fingerprint"
	CaptureModeRaw         = "raw"

	ReceiptSignerNone         = "none"
	ReceiptSignerLocal        = "local"
	ReceiptSignerAWSKMS       = "aws-kms"
	ReceiptSignerGCPKMS       = "gcp-kms"
	ReceiptSignerVaultTransit = "vault-transit"
)

const redacted = "<redacted>"

type RuntimeSecrets struct {
	ReceiptSigningSecretSet bool
}

type ValidationResult struct {
	Warnings []string
}

type ValidationError struct {
	Failures []string
}

func (e ValidationError) Error() string {
	return "unsafe HubbleOps configuration: " + strings.Join(e.Failures, "; ")
}

func (cfg *Config) Validate(secrets RuntimeSecrets) (ValidationResult, error) {
	cfg.normalize()

	var failures []string
	var warnings []string

	if !isKnownEnvironment(cfg.Environment) {
		failures = append(failures, fmt.Sprintf("HUBBLEOPS_ENV must be one of dev, test, prod; got %q", cfg.Environment))
	}
	if !isKnownCaptureMode(cfg.Capture.Mode) {
		failures = append(failures, fmt.Sprintf("HUBBLEOPS_CAPTURE_MODE must be fingerprint or raw; got %q", cfg.Capture.Mode))
	}
	if !isKnownCaptureMode(cfg.OutcomeCapture.Mode) {
		failures = append(failures, fmt.Sprintf("HUBBLEOPS_OUTCOME_CAPTURE_MODE must be fingerprint or raw; got %q", cfg.OutcomeCapture.Mode))
	}
	if cfg.WAL.SyncMode != "batch" && cfg.WAL.SyncMode != "sync" {
		failures = append(failures, fmt.Sprintf("HUBBLEOPS_WAL_SYNC_MODE must be batch or sync; got %q", cfg.WAL.SyncMode))
	}
	receiptSigner := cfg.resolvedReceiptSigner(secrets)
	if !isKnownReceiptSigner(receiptSigner) {
		failures = append(failures, fmt.Sprintf("HUBBLEOPS_RECEIPT_SIGNER must be one of none, local, aws-kms, gcp-kms, vault-transit; got %q", cfg.Receipts.Signer))
	}

	if cfg.Environment == EnvironmentProd {
		if !cfg.Auth.Enabled {
			failures = append(failures, "production requires HUBBLEOPS_AUTH_ENABLED=true")
		}
		if cfg.Auth.DevBypass {
			failures = append(failures, "production forbids HUBBLEOPS_DEV_AUTH_BYPASS=true")
		}
		if cfg.Auth.MetricsPublic {
			failures = append(failures, "production requires HUBBLEOPS_METRICS_PUBLIC=false")
		}
		if strings.TrimSpace(cfg.WAL.Dir) == "" {
			failures = append(failures, "production requires HUBBLEOPS_WAL_DIR")
		}
		if secrets.ReceiptSigningSecretSet || receiptSigner == ReceiptSignerLocal {
			failures = append(failures, "production forbids LocalSecretSigner and HUBBLEOPS_RECEIPT_SIGNING_SECRET; use HUBBLEOPS_RECEIPT_SIGNER=aws-kms")
		}
		if receiptSigner == ReceiptSignerNone {
			failures = append(failures, "production requires an external receipt signer such as HUBBLEOPS_RECEIPT_SIGNER=aws-kms")
		}
		if receiptSigner == ReceiptSignerAWSKMS {
			if strings.TrimSpace(cfg.Receipts.KMSKeyID) == "" {
				failures = append(failures, "production requires HUBBLEOPS_RECEIPT_KMS_KEY_ID when HUBBLEOPS_RECEIPT_SIGNER=aws-kms")
			}
			if strings.TrimSpace(cfg.Receipts.KMSRegion) == "" {
				failures = append(failures, "production requires HUBBLEOPS_RECEIPT_KMS_REGION or AWS_REGION when HUBBLEOPS_RECEIPT_SIGNER=aws-kms")
			}
		}
		if receiptSigner == ReceiptSignerGCPKMS || receiptSigner == ReceiptSignerVaultTransit {
			failures = append(failures, fmt.Sprintf("production receipt signer %q is stubbed; use aws-kms until implemented", receiptSigner))
		}
		if !cfg.Receipts.RequireForBlock {
			failures = append(failures, "production requires HUBBLEOPS_REQUIRE_RECEIPT_FOR_BLOCK=true")
		}
		if cfg.Capture.Mode == CaptureModeRaw && !cfg.Capture.AllowRawInProd {
			failures = append(failures, "production forbids HUBBLEOPS_CAPTURE_MODE=raw unless HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD=true")
		}
		if cfg.OutcomeCapture.Mode != CaptureModeFingerprint {
			failures = append(failures, "production requires HUBBLEOPS_OUTCOME_CAPTURE_MODE=fingerprint")
		}
		if cfg.OutcomeCapture.Raw {
			failures = append(failures, "production forbids HUBBLEOPS_OUTCOME_CAPTURE_RAW=true")
		}
		if cfg.Reviews.RawNotes && !(cfg.Capture.Mode == CaptureModeRaw && cfg.Capture.AllowRawInProd) {
			failures = append(failures, "production raw review notes require HUBBLEOPS_CAPTURE_MODE=raw and HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD=true")
		}
		if cfg.Receipts.EnforceWithoutReceipt {
			warnings = append(warnings, "CRITICAL: HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT=true can enforce unaudited blocks")
		}
		if cfg.Capture.Mode == CaptureModeRaw && cfg.Capture.AllowRawInProd {
			warnings = append(warnings, "CRITICAL: raw capture explicitly enabled in production")
		}
	} else {
		if !cfg.Auth.Enabled {
			warnings = append(warnings, "HubbleOps API-key auth disabled outside production")
		}
		if cfg.Auth.DevBypass {
			warnings = append(warnings, "HubbleOps dev auth bypass enabled")
		}
		if cfg.Auth.MetricsPublic {
			warnings = append(warnings, "HubbleOps metrics endpoint is public")
		}
		if strings.TrimSpace(cfg.WAL.Dir) == "" {
			warnings = append(warnings, "HUBBLEOPS_WAL_DIR is empty; receipt writes will fail")
		}
		if receiptSigner == ReceiptSignerNone {
			warnings = append(warnings, "receipt signer unset; local/dev receipts will be unsigned")
		}
		if receiptSigner == ReceiptSignerLocal {
			warnings = append(warnings, "dev-only LocalSecretSigner configured; production requires external KMS signing")
		}
		if receiptSigner == ReceiptSignerGCPKMS || receiptSigner == ReceiptSignerVaultTransit {
			warnings = append(warnings, fmt.Sprintf("receipt signer %q is stubbed and will fail signing", receiptSigner))
		}
		if cfg.Capture.Mode == CaptureModeRaw {
			warnings = append(warnings, "raw capture enabled; use only with sanitized local data")
		}
		if cfg.OutcomeCapture.Mode != CaptureModeFingerprint || cfg.OutcomeCapture.Raw {
			warnings = append(warnings, "raw outcome capture requested; MVP writer remains fingerprint-only")
		}
		if cfg.Reviews.RawNotes {
			warnings = append(warnings, "raw review notes enabled; use only with sanitized local data")
		}
		if cfg.Receipts.EnforceWithoutReceipt {
			warnings = append(warnings, "HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT=true can enforce unaudited blocks")
		}
	}

	result := ValidationResult{Warnings: warnings}
	if len(failures) > 0 {
		return result, ValidationError{Failures: failures}
	}
	return result, nil
}

func (cfg *Config) normalize() {
	cfg.Environment = strings.ToLower(strings.TrimSpace(cfg.Environment))
	if cfg.Environment == "" {
		cfg.Environment = EnvironmentProd
	}
	cfg.Capture.Mode = strings.ToLower(strings.TrimSpace(cfg.Capture.Mode))
	if cfg.Capture.Mode == "" {
		cfg.Capture.Mode = CaptureModeFingerprint
	}
	cfg.OutcomeCapture.Mode = strings.ToLower(strings.TrimSpace(cfg.OutcomeCapture.Mode))
	if cfg.OutcomeCapture.Mode == "" {
		cfg.OutcomeCapture.Mode = CaptureModeFingerprint
	}
	cfg.WAL.SyncMode = strings.ToLower(strings.TrimSpace(cfg.WAL.SyncMode))
	if cfg.WAL.SyncMode == "" {
		cfg.WAL.SyncMode = "batch"
	}
	cfg.Receipts.Signer = normalizeReceiptSigner(cfg.Receipts.Signer)
	cfg.Receipts.KMSKeyID = strings.TrimSpace(cfg.Receipts.KMSKeyID)
	cfg.Receipts.KMSRegion = strings.TrimSpace(cfg.Receipts.KMSRegion)
	cfg.Receipts.KMSEndpoint = strings.TrimSpace(cfg.Receipts.KMSEndpoint)
}

func isKnownEnvironment(env string) bool {
	switch env {
	case EnvironmentDev, EnvironmentTest, EnvironmentProd:
		return true
	default:
		return false
	}
}

func isKnownCaptureMode(mode string) bool {
	switch mode {
	case CaptureModeFingerprint, CaptureModeRaw:
		return true
	default:
		return false
	}
}

func normalizeReceiptSigner(value string) string {
	value = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(value, "_", "-")))
	switch value {
	case "", ReceiptSignerNone:
		return value
	case ReceiptSignerLocal, "secret", "local-secret":
		return ReceiptSignerLocal
	case ReceiptSignerAWSKMS, "awskms", "kms":
		return ReceiptSignerAWSKMS
	case ReceiptSignerGCPKMS, "gcpkms":
		return ReceiptSignerGCPKMS
	case ReceiptSignerVaultTransit, "vault", "vaulttransit":
		return ReceiptSignerVaultTransit
	default:
		return value
	}
}

func (cfg *Config) resolvedReceiptSigner(secrets RuntimeSecrets) string {
	mode := normalizeReceiptSigner(cfg.Receipts.Signer)
	if mode != "" {
		return mode
	}
	if secrets.ReceiptSigningSecretSet {
		return ReceiptSignerLocal
	}
	return ReceiptSignerNone
}

func isKnownReceiptSigner(mode string) bool {
	switch mode {
	case ReceiptSignerNone, ReceiptSignerLocal, ReceiptSignerAWSKMS, ReceiptSignerGCPKMS, ReceiptSignerVaultTransit:
		return true
	default:
		return false
	}
}

// CheckReceiptSignerImplemented rejects signer modes that are reserved but not
// yet implemented (their SignRecord fails on every write), so a stubbed signer
// is refused at configuration time instead of failing every receipt at runtime.
func CheckReceiptSignerImplemented(signer string) error {
	switch normalizeReceiptSigner(signer) {
	case ReceiptSignerGCPKMS, ReceiptSignerVaultTransit:
		return fmt.Errorf("receipt signer %q is not yet implemented; supported: none, local (dev only), aws-kms", strings.TrimSpace(signer))
	}
	return nil
}

func (p PostgresConfig) RedactedDSN() string {
	cp := p
	if cp.Password != "" {
		cp.Password = redacted
	}
	return cp.DSN()
}

func RedactURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return redactSuspiciousText(raw)
	}
	if u.User != nil {
		u.User = url.UserPassword(redacted, redacted)
	}
	q := u.Query()
	for key := range q {
		if isSecretKey(key) {
			q.Set(key, redacted)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func redactSuspiciousText(value string) string {
	if strings.Contains(strings.ToLower(value), "key=") ||
		strings.Contains(strings.ToLower(value), "token=") ||
		strings.Contains(strings.ToLower(value), "secret=") ||
		strings.Contains(strings.ToLower(value), "password=") {
		return redacted
	}
	return value
}

func isSecretKey(key string) bool {
	key = strings.ToLower(key)
	return strings.Contains(key, "key") ||
		strings.Contains(key, "token") ||
		strings.Contains(key, "secret") ||
		strings.Contains(key, "password")
}

func (cfg *Config) RedactedSummary(secrets RuntimeSecrets) map[string]any {
	cfg.normalize()
	return map[string]any{
		"environment": cfg.Environment,
		"postgres": map[string]any{
			"host":     cfg.Postgres.Host,
			"port":     cfg.Postgres.Port,
			"user":     cfg.Postgres.User,
			"password": redactedIfSet(cfg.Postgres.Password),
			"dbname":   cfg.Postgres.DBName,
			"sslmode":  cfg.Postgres.SSLMode,
		},
		"wal": map[string]any{
			"dir":       cfg.WAL.Dir,
			"sync_mode": cfg.WAL.SyncMode,
		},
		"auth": map[string]any{
			"enabled":         cfg.Auth.Enabled,
			"dev_auth_bypass": cfg.Auth.DevBypass,
			"metrics_public":  cfg.Auth.MetricsPublic,
		},
		"capture": map[string]any{
			"mode":              cfg.Capture.Mode,
			"allow_raw_in_prod": cfg.Capture.AllowRawInProd,
		},
		"outcome_capture": map[string]any{
			"enabled": cfg.OutcomeCapture.Enabled,
			"mode":    cfg.OutcomeCapture.Mode,
			"raw":     cfg.OutcomeCapture.Raw,
		},
		"reviews": map[string]any{
			"raw_notes": cfg.Reviews.RawNotes,
		},
		"receipts": map[string]any{
			"require_receipt_for_block": cfg.Receipts.RequireForBlock,
			"enforce_without_receipt":   cfg.Receipts.EnforceWithoutReceipt,
			"signer":                    cfg.resolvedReceiptSigner(secrets),
			"signing_secret":            presence(secrets.ReceiptSigningSecretSet),
			"kms_key_id":                redactedIfSet(cfg.Receipts.KMSKeyID),
			"kms_region":                cfg.Receipts.KMSRegion,
			"kms_endpoint":              RedactURL(cfg.Receipts.KMSEndpoint),
		},
		"policy": map[string]any{
			"path": cfg.Policy.Path,
		},
	}
}

func (cfg *Config) RedactedSummaryJSON(secrets RuntimeSecrets) string {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(cfg.RedactedSummary(secrets)); err != nil {
		return "{}"
	}
	return strings.TrimSpace(out.String())
}

func redactedIfSet(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	return redacted
}

func presence(set bool) string {
	if set {
		return "set"
	}
	return "unset"
}
