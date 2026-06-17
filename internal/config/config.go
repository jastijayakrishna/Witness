package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Environment    string               `yaml:"environment"`
	Server         ServerConfig         `yaml:"server"`
	Postgres       PostgresConfig       `yaml:"postgres"`
	Redis          RedisConfig          `yaml:"redis"`
	WAL            WALConfig            `yaml:"wal"`
	Auth           AuthConfig           `yaml:"auth"`
	Capture        CaptureConfig        `yaml:"capture"`
	OutcomeCapture OutcomeCaptureConfig `yaml:"outcome_capture"`
	Reviews        ReviewConfig         `yaml:"reviews"`
	Receipts       ReceiptConfig        `yaml:"receipts"`
	LoopDetection  LoopDetectionConfig  `yaml:"loop_detection"`
	Budget         BudgetConfig         `yaml:"budget"`
	Limits         LimitsConfig         `yaml:"limits"`
	Alerts         AlertsConfig         `yaml:"alerts"`
}

// AuthConfig controls HubbleOps API-key authentication.
type AuthConfig struct {
	Enabled       bool `yaml:"enabled"`         // production default true
	DevBypass     bool `yaml:"dev_auth_bypass"` // honored only when environment=dev
	MetricsPublic bool `yaml:"metrics_public"`  // production default false
}

// CaptureConfig controls whether raw action data can be captured.
type CaptureConfig struct {
	Mode               string `yaml:"mode"`                   // "fingerprint" (default) or "raw"
	AllowRawInProd     bool   `yaml:"allow_raw_in_prod"`      // explicit unsafe override
	AllowRawInProdNote string `yaml:"allow_raw_in_prod_note"` // optional operator reason
}

// OutcomeCaptureConfig controls privacy-safe data moat outcome writes.
type OutcomeCaptureConfig struct {
	Enabled bool   `yaml:"enabled"` // default true
	Mode    string `yaml:"mode"`    // "fingerprint" by default; raw mode is not used by the MVP writer
	Raw     bool   `yaml:"raw"`     // default false; must remain false in production
}

// ReviewConfig controls customer review label capture.
type ReviewConfig struct {
	RawNotes bool `yaml:"raw_notes"` // default false: store notes_fingerprint only
}

// ReceiptConfig controls the "no block without receipt attempt" invariant.
type ReceiptConfig struct {
	RequireForBlock       bool `yaml:"require_receipt_for_block"` // production default true
	EnforceWithoutReceipt bool `yaml:"enforce_without_receipt"`   // default false: fail open if block receipt fails
}

// LoopDetectionConfig controls the loop detection engine.
type LoopDetectionConfig struct {
	Enabled                bool    `yaml:"enabled"`
	Action                 string  `yaml:"action"`                    // "shadow" (default), "warn", "block"
	MaxRepeated            int     `yaml:"max_repeated"`              // identical repetitions to fire (default 3)
	VelocityAccelRatio     float64 `yaml:"velocity_accel_ratio"`      // cost acceleration threshold (default 1.5)
	VelocityWindowMs       int64   `yaml:"velocity_window_ms"`        // half-window for velocity (default 300000 = 5min)
	WarnConfidence         float64 `yaml:"warn_confidence"`           // confidence for warn (default 0.40)
	BlockConfidence        float64 `yaml:"block_confidence"`          // confidence for block (default 0.70)
	RequireSessionForBlock bool    `yaml:"require_session_for_block"` // safety floor (default true)

	// ToolRiskFloors maps tool/action names to a minimum risk class the client
	// cannot downgrade (e.g. "refund_customer": "write", "delete_resource": "dangerous").
	// Unknown tools fall back to the client-supplied label. This is a floor, not a
	// rules engine — it refuses to let the client lie about tools you classified.
	ToolRiskFloors map[string]string `yaml:"tool_risk_floors"`
}

// BudgetConfig controls per-project spending caps.
type BudgetConfig struct {
	DailySoftUSD         float64 `yaml:"daily_soft_usd"`          // soft cap → warn (default 0 = disabled)
	DailyHardUSD         float64 `yaml:"daily_hard_usd"`          // hard cap → block (default 0 = disabled)
	ReservePerRequestUSD float64 `yaml:"reserve_per_request_usd"` // atomic reservation per request (default 0.50)
}

// LimitsConfig declares the resource-rogue layer: limits that apply ACROSS
// actions (cumulative spend, action velocity, breaker quarantine), scoped to
// the server-derived agent identity. Operator-declared only; nothing here is
// client-tunable. Empty = disabled.
type LimitsConfig struct {
	Cumulative []CumulativeLimit `yaml:"cumulative"`
	Velocity   []VelocityLimit   `yaml:"velocity"`
	Breaker    BreakerLimit      `yaml:"breaker"`
}

type CumulativeLimit struct {
	Name           string `yaml:"name"`
	Tool           string `yaml:"tool"`  // optional exact tool filter; "" = any
	Scope          string `yaml:"scope"` // agent (default) | session | resource | recipient
	WindowSeconds  int    `yaml:"window_seconds"`
	MaxAmountCents int64  `yaml:"max_amount_cents"`
}

type VelocityLimit struct {
	Name          string `yaml:"name"`
	Tool          string `yaml:"tool"`     // optional exact tool filter; "" = any
	MinRisk       string `yaml:"min_risk"` // write (default) | dangerous
	Scope         string `yaml:"scope"`    // agent (default) | session | resource | recipient
	WindowSeconds int    `yaml:"window_seconds"`
	MaxActions    int    `yaml:"max_actions"`
}

type BreakerLimit struct {
	Trips           int `yaml:"trips"` // 0 = disabled
	WindowSeconds   int `yaml:"window_seconds"`
	CooldownSeconds int `yaml:"cooldown_seconds"`
}

// AlertsConfig controls webhook notifications.
type AlertsConfig struct {
	WebhookURL string `yaml:"webhook_url"` // Slack/webhook URL for loop alerts (empty = disabled)
}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type PostgresConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
	SSLMode  string `yaml:"sslmode"`
}

type RedisConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

// WALConfig controls write-ahead log behavior.
type WALConfig struct {
	// Dir is the directory for WAL files. Default: "data/wal".
	Dir string `yaml:"dir"`
	// SyncMode controls fsync behavior:
	//   "batch" (default): fsync every 50 records or 100ms — fast, ~100ms durability window
	//   "sync": fsync on every write — per-request durability, ~0.5ms overhead
	SyncMode string `yaml:"sync_mode"`
}

func (p PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, p.Password, p.Host, p.Port, p.DBName, p.SSLMode,
	)
}

func (r RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Environment: "prod",
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Postgres: PostgresConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "hubbleops",
			Password: "hubbleops",
			DBName:   "hubbleops",
			SSLMode:  "disable",
		},
		Redis: RedisConfig{
			Host: "localhost",
			Port: 6379,
			DB:   0,
		},
		WAL: WALConfig{
			Dir:      "data/wal",
			SyncMode: "batch",
		},
		Auth: AuthConfig{
			Enabled:       true,
			DevBypass:     false,
			MetricsPublic: false,
		},
		Capture: CaptureConfig{
			Mode:           "fingerprint",
			AllowRawInProd: false,
		},
		OutcomeCapture: OutcomeCaptureConfig{
			Enabled: true,
			Mode:    "fingerprint",
			Raw:     false,
		},
		Reviews: ReviewConfig{
			RawNotes: false,
		},
		Receipts: ReceiptConfig{
			RequireForBlock:       true,
			EnforceWithoutReceipt: false,
		},
		LoopDetection: LoopDetectionConfig{
			Enabled:                true,
			Action:                 "shadow",
			MaxRepeated:            3,
			VelocityAccelRatio:     1.5,
			VelocityWindowMs:       300_000,
			WarnConfidence:         0.40,
			BlockConfidence:        0.70,
			RequireSessionForBlock: true,
		},
		Budget: BudgetConfig{
			DailySoftUSD:         0,    // disabled by default
			DailyHardUSD:         0,    // disabled by default
			ReservePerRequestUSD: 0.50, // atomic reservation per request
		},
		Alerts: AlertsConfig{
			WebhookURL: "", // disabled by default
		},
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("HUBBLEOPS_ENV"); v != "" {
		cfg.Environment = v
	}
	cfg.Environment = strings.ToLower(strings.TrimSpace(cfg.Environment))
	if cfg.Environment == "" {
		cfg.Environment = "prod"
	}
	if v := os.Getenv("HUBBLEOPS_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("HUBBLEOPS_SERVER_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = port
		}
	}
	if v := os.Getenv("HUBBLEOPS_POSTGRES_HOST"); v != "" {
		cfg.Postgres.Host = v
	}
	if v := os.Getenv("HUBBLEOPS_POSTGRES_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Postgres.Port = port
		}
	}
	if v := os.Getenv("HUBBLEOPS_POSTGRES_USER"); v != "" {
		cfg.Postgres.User = v
	}
	if v := os.Getenv("HUBBLEOPS_POSTGRES_PASSWORD"); v != "" {
		cfg.Postgres.Password = v
	}
	if v := os.Getenv("HUBBLEOPS_POSTGRES_DBNAME"); v != "" {
		cfg.Postgres.DBName = v
	}
	if v := os.Getenv("HUBBLEOPS_POSTGRES_SSLMODE"); v != "" {
		cfg.Postgres.SSLMode = v
	}
	if v := os.Getenv("HUBBLEOPS_REDIS_HOST"); v != "" {
		cfg.Redis.Host = v
	}
	if v := os.Getenv("HUBBLEOPS_REDIS_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Redis.Port = port
		}
	}
	if v := os.Getenv("HUBBLEOPS_REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("HUBBLEOPS_REDIS_DB"); v != "" {
		if db, err := strconv.Atoi(v); err == nil {
			cfg.Redis.DB = db
		}
	}
	if v := os.Getenv("HUBBLEOPS_WAL_DIR"); v != "" {
		cfg.WAL.Dir = v
	}
	if v := os.Getenv("HUBBLEOPS_WAL_SYNC_MODE"); v != "" {
		cfg.WAL.SyncMode = v
	}
	if v := os.Getenv("HUBBLEOPS_AUTH_ENABLED"); v != "" {
		cfg.Auth.Enabled = parseBool(v)
	}
	if v := os.Getenv("HUBBLEOPS_DEV_AUTH_BYPASS"); v != "" {
		cfg.Auth.DevBypass = cfg.Environment == "dev" && parseBool(v)
	}
	if cfg.Environment != "dev" {
		cfg.Auth.DevBypass = false
	}
	if v := os.Getenv("HUBBLEOPS_METRICS_PUBLIC"); v != "" {
		cfg.Auth.MetricsPublic = parseBool(v)
	}
	if v := os.Getenv("HUBBLEOPS_CAPTURE_MODE"); v != "" {
		cfg.Capture.Mode = v
	}
	if v := os.Getenv("HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD"); v != "" {
		cfg.Capture.AllowRawInProd = parseBool(v)
	}
	if v := os.Getenv("HUBBLEOPS_ALLOW_RAW_CAPTURE_IN_PROD_NOTE"); v != "" {
		cfg.Capture.AllowRawInProdNote = v
	}
	if v := os.Getenv("HUBBLEOPS_OUTCOME_CAPTURE_ENABLED"); v != "" {
		cfg.OutcomeCapture.Enabled = parseBool(v)
	}
	if v := os.Getenv("HUBBLEOPS_OUTCOME_CAPTURE_MODE"); v != "" {
		cfg.OutcomeCapture.Mode = v
	}
	if v := os.Getenv("HUBBLEOPS_OUTCOME_CAPTURE_RAW"); v != "" {
		cfg.OutcomeCapture.Raw = parseBool(v)
	}
	if v := os.Getenv("HUBBLEOPS_REVIEW_RAW_NOTES"); v != "" {
		cfg.Reviews.RawNotes = parseBool(v)
	}
	if v := os.Getenv("HUBBLEOPS_REQUIRE_RECEIPT_FOR_BLOCK"); v != "" {
		cfg.Receipts.RequireForBlock = parseBool(v)
	}
	if v := os.Getenv("HUBBLEOPS_ENFORCE_WITHOUT_RECEIPT"); v != "" {
		cfg.Receipts.EnforceWithoutReceipt = parseBool(v)
	}
	if v := os.Getenv("HUBBLEOPS_LOOP_ENABLED"); v != "" {
		cfg.LoopDetection.Enabled = parseBool(v)
	}
	if v := os.Getenv("HUBBLEOPS_LOOP_ACTION"); v != "" {
		cfg.LoopDetection.Action = v
	}
	if v := os.Getenv("HUBBLEOPS_LOOP_MAX_REPEATED"); v != "" {
		if val, err := strconv.Atoi(v); err == nil {
			cfg.LoopDetection.MaxRepeated = val
		}
	}
	if v := os.Getenv("HUBBLEOPS_LOOP_VELOCITY_ACCEL_RATIO"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.LoopDetection.VelocityAccelRatio = val
		}
	}
	if v := os.Getenv("HUBBLEOPS_LOOP_VELOCITY_WINDOW_MS"); v != "" {
		if val, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.LoopDetection.VelocityWindowMs = val
		}
	}
	if v := os.Getenv("HUBBLEOPS_LOOP_WARN_CONFIDENCE"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.LoopDetection.WarnConfidence = val
		}
	}
	if v := os.Getenv("HUBBLEOPS_LOOP_BLOCK_CONFIDENCE"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.LoopDetection.BlockConfidence = val
		}
	}
	if v := os.Getenv("HUBBLEOPS_LOOP_REQUIRE_SESSION_FOR_BLOCK"); v != "" {
		cfg.LoopDetection.RequireSessionForBlock = parseBool(v)
	}
	if v := os.Getenv("HUBBLEOPS_BUDGET_DAILY_SOFT_USD"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Budget.DailySoftUSD = val
		}
	}
	if v := os.Getenv("HUBBLEOPS_BUDGET_DAILY_HARD_USD"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Budget.DailyHardUSD = val
		}
	}
	if v := os.Getenv("HUBBLEOPS_BUDGET_RESERVE_PER_REQUEST_USD"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Budget.ReservePerRequestUSD = val
		}
	}
	if v := os.Getenv("HUBBLEOPS_ALERTS_WEBHOOK_URL"); v != "" {
		cfg.Alerts.WebhookURL = v
	}
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}
