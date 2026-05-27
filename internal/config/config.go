package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Postgres      PostgresConfig      `yaml:"postgres"`
	Redis         RedisConfig         `yaml:"redis"`
	WAL           WALConfig           `yaml:"wal"`
	LoopDetection LoopDetectionConfig `yaml:"loop_detection"`
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
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Postgres: PostgresConfig{
			Host:     "localhost",
			Port:     5432,
			User:     "witness",
			Password: "witness",
			DBName:   "witness",
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
	if v := os.Getenv("WITNESS_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("WITNESS_SERVER_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = port
		}
	}
	if v := os.Getenv("WITNESS_POSTGRES_HOST"); v != "" {
		cfg.Postgres.Host = v
	}
	if v := os.Getenv("WITNESS_POSTGRES_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Postgres.Port = port
		}
	}
	if v := os.Getenv("WITNESS_POSTGRES_USER"); v != "" {
		cfg.Postgres.User = v
	}
	if v := os.Getenv("WITNESS_POSTGRES_PASSWORD"); v != "" {
		cfg.Postgres.Password = v
	}
	if v := os.Getenv("WITNESS_POSTGRES_DBNAME"); v != "" {
		cfg.Postgres.DBName = v
	}
	if v := os.Getenv("WITNESS_POSTGRES_SSLMODE"); v != "" {
		cfg.Postgres.SSLMode = v
	}
	if v := os.Getenv("WITNESS_REDIS_HOST"); v != "" {
		cfg.Redis.Host = v
	}
	if v := os.Getenv("WITNESS_REDIS_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Redis.Port = port
		}
	}
	if v := os.Getenv("WITNESS_REDIS_PASSWORD"); v != "" {
		cfg.Redis.Password = v
	}
	if v := os.Getenv("WITNESS_REDIS_DB"); v != "" {
		if db, err := strconv.Atoi(v); err == nil {
			cfg.Redis.DB = db
		}
	}
	if v := os.Getenv("WITNESS_WAL_DIR"); v != "" {
		cfg.WAL.Dir = v
	}
	if v := os.Getenv("WITNESS_WAL_SYNC_MODE"); v != "" {
		cfg.WAL.SyncMode = v
	}
	if v := os.Getenv("WITNESS_LOOP_ENABLED"); v != "" {
		cfg.LoopDetection.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("WITNESS_LOOP_ACTION"); v != "" {
		cfg.LoopDetection.Action = v
	}
	if v := os.Getenv("WITNESS_LOOP_MAX_REPEATED"); v != "" {
		if val, err := strconv.Atoi(v); err == nil {
			cfg.LoopDetection.MaxRepeated = val
		}
	}
	if v := os.Getenv("WITNESS_LOOP_VELOCITY_ACCEL_RATIO"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.LoopDetection.VelocityAccelRatio = val
		}
	}
	if v := os.Getenv("WITNESS_LOOP_VELOCITY_WINDOW_MS"); v != "" {
		if val, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.LoopDetection.VelocityWindowMs = val
		}
	}
	if v := os.Getenv("WITNESS_LOOP_WARN_CONFIDENCE"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.LoopDetection.WarnConfidence = val
		}
	}
	if v := os.Getenv("WITNESS_LOOP_BLOCK_CONFIDENCE"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.LoopDetection.BlockConfidence = val
		}
	}
	if v := os.Getenv("WITNESS_LOOP_REQUIRE_SESSION_FOR_BLOCK"); v != "" {
		cfg.LoopDetection.RequireSessionForBlock = v == "true" || v == "1"
	}
}
