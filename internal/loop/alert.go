package loop

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

const (
	alertCooldownTTL = 10 * time.Minute // don't spam the same alert repeatedly
)

// Alerter sends loop detection alerts via webhook (Slack, etc).
// Uses Redis to enforce a cooldown per (project, session) so the same loop
// doesn't trigger 100 alerts — one alert per 10 minutes is enough.
type Alerter struct {
	webhookURL string
	httpClient *http.Client
	rdb        *redis.Client
}

// NewAlerter creates an Alerter with the given webhook URL.
// If webhookURL is empty, alerts are no-ops (silently skipped).
func NewAlerter(webhookURL string, rdb *redis.Client) *Alerter {
	return &Alerter{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		rdb:        rdb,
	}
}

// LoopAlert is the payload sent to the webhook when a loop is detected.
type LoopAlert struct {
	Type       string   `json:"type"`        // "loop_detected"
	Project    string   `json:"project"`
	SessionID  string   `json:"session_id"`
	Signals    []string `json:"signals"`
	Confidence float64  `json:"confidence"`
	Action     string   `json:"action"` // "warn" or "block"
	Reason     string   `json:"reason"`
	Timestamp  int64    `json:"timestamp"` // unix millis
}

// Send sends a loop alert to the configured webhook, respecting cooldown.
// Returns immediately (no-op) if the webhook URL is empty or if the same
// (project, session) was already alerted within the cooldown window.
func (a *Alerter) Send(ctx context.Context, alert LoopAlert) error {
	if a.webhookURL == "" {
		return nil // no webhook configured — silent skip
	}

	// Check cooldown: one alert per (project, session) per 10 minutes
	cooldownKey := fmt.Sprintf("alert_cooldown:%s:%s", alert.Project, alert.SessionID)
	set, err := a.rdb.SetNX(ctx, cooldownKey, "1", alertCooldownTTL).Result()
	if err != nil {
		log.Warn().Err(err).Msg("alert cooldown check failed — sending anyway")
	} else if !set {
		log.Info().
			Str("project", alert.Project).
			Str("session", alert.SessionID).
			Msg("alert cooldown active — skipping duplicate alert")
		return nil
	}

	// Marshal payload
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}

	// POST to webhook (best-effort, don't block the request path)
	req, err := http.NewRequestWithContext(ctx, "POST", a.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create alert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send alert: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("alert webhook returned %d", resp.StatusCode)
	}

	log.Info().
		Str("project", alert.Project).
		Str("session", alert.SessionID).
		Str("action", alert.Action).
		Msg("loop alert sent")

	return nil
}
