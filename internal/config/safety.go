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
)

const redacted = "<redacted>"

// RuntimeSecrets describes startup-only secret presence without carrying the
// secret values through config validation or logs.
type RuntimeSecrets struct {
	ReceiptSigningSecretSet   bool
	ActionCapabilitySecretSet bool
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

// Validate enforces production safety invariants and returns loud dev warnings
// for the same settings. It intentionally does not run inside Load so tests and
// helper CLIs can parse config without requiring production runtime secrets.
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
	if !isKnownLoopAction(cfg.LoopDetection.Action) {
		failures = append(failures, fmt.Sprintf("HUBBLEOPS_LOOP_ACTION must be shadow, warn, or block; got %q", cfg.LoopDetection.Action))
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
		if !secrets.ReceiptSigningSecretSet {
			failures = append(failures, "production requires HUBBLEOPS_RECEIPT_SIGNING_SECRET")
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
		if cfg.LoopDetection.Enabled && cfg.LoopDetection.Action == "block" && !cfg.LoopDetection.RequireSessionForBlock {
			failures = append(failures, "production block mode requires HUBBLEOPS_LOOP_REQUIRE_SESSION_FOR_BLOCK=true")
		}
		if cfg.Receipts.EnforceWithoutReceipt {
			warnings = append(warnings, "CRITICAL: HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT=true can enforce unaudited blocks")
		}
		if cfg.Capture.Mode == CaptureModeRaw && cfg.Capture.AllowRawInProd {
			warnings = append(warnings, "CRITICAL: raw capture explicitly enabled in production")
		}
		if !secrets.ActionCapabilitySecretSet {
			warnings = append(warnings, "HUBBLEOPS_ACTION_CAPABILITY_SECRET is unset; dangerous actions must rely on backup_id only")
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
			warnings = append(warnings, "HUBBLEOPS_WAL_DIR is empty; proxy startup will fail if WAL is needed")
		}
		if !secrets.ReceiptSigningSecretSet {
			warnings = append(warnings, "receipt signing secret unset; local/dev receipts will be unsigned")
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

	// Limit rules are environment-independent: a half-declared limit silently
	// never firing is worse than a startup failure in any environment.
	failures = append(failures, validateLimits(cfg.Limits)...)

	result := ValidationResult{Warnings: warnings}
	if len(failures) > 0 {
		return result, ValidationError{Failures: failures}
	}
	return result, nil
}

func validateLimits(limits LimitsConfig) []string {
	var failures []string
	scopeOK := func(scope string) bool {
		switch strings.ToLower(strings.TrimSpace(scope)) {
		case "", "agent", "session", "resource", "recipient":
			return true
		}
		return false
	}
	for i, rule := range limits.Cumulative {
		label := fmt.Sprintf("limits.cumulative[%d] (%s)", i, rule.Name)
		if rule.WindowSeconds <= 0 {
			failures = append(failures, label+" requires window_seconds > 0")
		}
		if rule.MaxAmountCents <= 0 {
			failures = append(failures, label+" requires max_amount_cents > 0")
		}
		if !scopeOK(rule.Scope) {
			failures = append(failures, label+" scope must be agent, session, resource, or recipient")
		}
	}
	for i, rule := range limits.Velocity {
		label := fmt.Sprintf("limits.velocity[%d] (%s)", i, rule.Name)
		if rule.WindowSeconds <= 0 {
			failures = append(failures, label+" requires window_seconds > 0")
		}
		if rule.MaxActions <= 0 {
			failures = append(failures, label+" requires max_actions > 0")
		}
		if !scopeOK(rule.Scope) {
			failures = append(failures, label+" scope must be agent, session, resource, or recipient")
		}
		switch strings.ToLower(strings.TrimSpace(rule.MinRisk)) {
		case "", "write", "dangerous":
		default:
			failures = append(failures, label+" min_risk must be write or dangerous")
		}
	}
	if limits.Breaker.Trips > 0 {
		if limits.Breaker.WindowSeconds <= 0 {
			failures = append(failures, "limits.breaker requires window_seconds > 0")
		}
		if limits.Breaker.CooldownSeconds <= 0 {
			failures = append(failures, "limits.breaker requires cooldown_seconds > 0")
		}
	}
	return failures
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
	cfg.LoopDetection.Action = strings.ToLower(strings.TrimSpace(cfg.LoopDetection.Action))
	if cfg.LoopDetection.Action == "" {
		cfg.LoopDetection.Action = "shadow"
	}
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

func isKnownLoopAction(action string) bool {
	switch action {
	case "shadow", "warn", "block":
		return true
	default:
		return false
	}
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
		"server": map[string]any{
			"host": cfg.Server.Host,
			"port": cfg.Server.Port,
		},
		"postgres": map[string]any{
			"host":     cfg.Postgres.Host,
			"port":     cfg.Postgres.Port,
			"user":     cfg.Postgres.User,
			"password": redactedIfSet(cfg.Postgres.Password),
			"dbname":   cfg.Postgres.DBName,
			"sslmode":  cfg.Postgres.SSLMode,
		},
		"redis": map[string]any{
			"host":     cfg.Redis.Host,
			"port":     cfg.Redis.Port,
			"password": redactedIfSet(cfg.Redis.Password),
			"db":       cfg.Redis.DB,
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
			"signing_secret":            presence(secrets.ReceiptSigningSecretSet),
		},
		"loop_detection": map[string]any{
			"enabled":                   cfg.LoopDetection.Enabled,
			"action":                    cfg.LoopDetection.Action,
			"max_repeated":              cfg.LoopDetection.MaxRepeated,
			"require_session_for_block": cfg.LoopDetection.RequireSessionForBlock,
		},
		"budget": map[string]any{
			"daily_soft_usd":          cfg.Budget.DailySoftUSD,
			"daily_hard_usd":          cfg.Budget.DailyHardUSD,
			"reserve_per_request_usd": cfg.Budget.ReservePerRequestUSD,
		},
		"alerts": map[string]any{
			"webhook_url": redactedIfSet(cfg.Alerts.WebhookURL),
		},
		"secrets": map[string]any{
			"receipt_signing_secret":   presence(secrets.ReceiptSigningSecretSet),
			"action_capability_secret": presence(secrets.ActionCapabilitySecretSet),
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
