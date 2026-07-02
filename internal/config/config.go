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
	Postgres       PostgresConfig       `yaml:"postgres"`
	WAL            WALConfig            `yaml:"wal"`
	Auth           AuthConfig           `yaml:"auth"`
	Capture        CaptureConfig        `yaml:"capture"`
	OutcomeCapture OutcomeCaptureConfig `yaml:"outcome_capture"`
	Reviews        ReviewConfig         `yaml:"reviews"`
	Receipts       ReceiptConfig        `yaml:"receipts"`
	Policy         PolicyConfig         `yaml:"policy"`
}

type AuthConfig struct {
	Enabled       bool `yaml:"enabled"`
	DevBypass     bool `yaml:"dev_auth_bypass"`
	MetricsPublic bool `yaml:"metrics_public"`
}

type CaptureConfig struct {
	Mode               string `yaml:"mode"`
	AllowRawInProd     bool   `yaml:"allow_raw_in_prod"`
	AllowRawInProdNote string `yaml:"allow_raw_in_prod_note"`
}

type OutcomeCaptureConfig struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"`
	Raw     bool   `yaml:"raw"`
}

type ReviewConfig struct {
	RawNotes bool `yaml:"raw_notes"`
}

type ReceiptConfig struct {
	RequireForBlock       bool   `yaml:"require_receipt_for_block"`
	EnforceWithoutReceipt bool   `yaml:"enforce_without_receipt"`
	Signer                string `yaml:"signer"`
	KMSKeyID              string `yaml:"kms_key_id"`
	KMSRegion             string `yaml:"kms_region"`
	KMSEndpoint           string `yaml:"kms_endpoint"`
}

type PolicyConfig struct {
	Path string `yaml:"path"`
}

type PostgresConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	DBName   string `yaml:"dbname"`
	SSLMode  string `yaml:"sslmode"`
}

type WALConfig struct {
	Dir      string `yaml:"dir"`
	SyncMode string `yaml:"sync_mode"`
}

func (p PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s?sslmode=%s",
		p.User, p.Password, p.Host, p.Port, p.DBName, p.SSLMode,
	)
}

func Load(path string) (*Config, error) {
	cfg := &Config{
		Environment: "prod",
		Postgres: PostgresConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "hubbleops",
			Password: "hubbleops",
			DBName:   "hubbleops",
			SSLMode:  "disable",
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
			Mode:           CaptureModeFingerprint,
			AllowRawInProd: false,
		},
		OutcomeCapture: OutcomeCaptureConfig{
			Enabled: true,
			Mode:    CaptureModeFingerprint,
			Raw:     false,
		},
		Reviews: ReviewConfig{
			RawNotes: false,
		},
		Receipts: ReceiptConfig{
			RequireForBlock:       true,
			EnforceWithoutReceipt: false,
			Signer:                "",
		},
		Policy: PolicyConfig{
			Path: "configs/policy.yaml",
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

func FromEnv() (*Config, error) {
	return Load("")
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("HUBBLEOPS_ENV"); v != "" {
		cfg.Environment = v
	}
	cfg.Environment = strings.ToLower(strings.TrimSpace(cfg.Environment))
	if cfg.Environment == "" {
		cfg.Environment = EnvironmentProd
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
		cfg.Auth.DevBypass = cfg.Environment == EnvironmentDev && parseBool(v)
	}
	if cfg.Environment != EnvironmentDev {
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
	if v := os.Getenv("HUBBLEOPS_RECEIPT_SIGNER"); v != "" {
		cfg.Receipts.Signer = v
	}
	if v := os.Getenv("HUBBLEOPS_RECEIPT_KMS_KEY_ID"); v != "" {
		cfg.Receipts.KMSKeyID = v
	}
	if v := firstEnv("HUBBLEOPS_RECEIPT_KMS_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"); v != "" {
		cfg.Receipts.KMSRegion = v
	}
	if v := os.Getenv("HUBBLEOPS_RECEIPT_KMS_ENDPOINT"); v != "" {
		cfg.Receipts.KMSEndpoint = v
	}
	if v := os.Getenv("HUBBLEOPS_POLICY"); v != "" {
		cfg.Policy.Path = v
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

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}
