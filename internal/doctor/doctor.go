package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	BaseURL string
	Project string
	APIKey  string
	Timeout time.Duration
}

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type Report struct {
	BaseURL string  `json:"base_url"`
	Project string  `json:"project,omitempty"`
	Checks  []Check `json:"checks"`
}

func (r Report) OK() bool {
	if len(r.Checks) == 0 {
		return false
	}
	for _, check := range r.Checks {
		if !check.OK {
			return false
		}
	}
	return true
}

func Run(ctx context.Context, cfg Config) Report {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:8080"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.Project == "" {
		cfg.Project = "witness-doctor"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}

	report := Report{BaseURL: cfg.BaseURL, Project: cfg.Project}
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		report.Checks = append(report.Checks, Check{Name: "base_url", OK: false, Detail: "base URL must include scheme and host"})
		return report
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLocalHost(parsed.Hostname())) {
		report.Checks = append(report.Checks, Check{Name: "base_url", OK: false, Detail: "use HTTPS for non-local Witness endpoints"})
		return report
	}
	report.Checks = append(report.Checks, Check{Name: "base_url", OK: true, Detail: cfg.BaseURL})

	client := &http.Client{Timeout: cfg.Timeout}
	report.Checks = append(report.Checks, getJSON(ctx, client, cfg, "/healthz", "healthz"))
	report.Checks = append(report.Checks, postToolEvent(ctx, client, cfg, "/v1/tool/check", "tool_check", map[string]any{
		"project":      cfg.Project,
		"session_id":   "witness-doctor",
		"step_id":      "doctor-check",
		"tool_name":    "witness_doctor_noop",
		"args":         map[string]any{"probe": true},
		"unix_millis":  time.Now().UnixMilli(),
		"result_class": "",
	}))
	report.Checks = append(report.Checks, postToolEvent(ctx, client, cfg, "/v1/tool/result", "tool_result", map[string]any{
		"project":          cfg.Project,
		"session_id":       "witness-doctor",
		"step_id":          "doctor-result",
		"tool_name":        "witness_doctor_noop",
		"args":             map[string]any{"probe": true},
		"result":           map[string]any{"ok": true},
		"result_class":     "success",
		"state_delta_hash": "witness-doctor-ok",
		"unix_millis":      time.Now().UnixMilli(),
	}))
	return report
}

func getJSON(ctx context.Context, client *http.Client, cfg Config, path, name string) Check {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.BaseURL+path, nil)
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}
	}
	addHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Check{Name: name, OK: false, Detail: fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	return Check{Name: name, OK: true, Detail: strings.TrimSpace(string(body))}
}

func postToolEvent(ctx context.Context, client *http.Client, cfg Config, path, name string, payload map[string]any) Check {
	body, err := json.Marshal(payload)
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}
	}
	addHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Project", cfg.Project)

	resp, err := client.Do(req)
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Check{Name: name, OK: false, Detail: fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))}
	}

	var decoded struct {
		Action     string `json:"action"`
		FailOpen   bool   `json:"fail_open"`
		WouldBlock string `json:"would_action"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return Check{Name: name, OK: false, Detail: "invalid JSON response: " + err.Error()}
	}
	if decoded.Action == "block" {
		return Check{Name: name, OK: false, Detail: strings.TrimSpace(string(respBody))}
	}
	detail := "action=" + decoded.Action
	if decoded.FailOpen {
		detail += " fail_open=true"
	}
	if decoded.WouldBlock != "" && decoded.WouldBlock != "none" {
		detail += " would_action=" + decoded.WouldBlock
	}
	return Check{Name: name, OK: true, Detail: detail}
}

func addHeaders(req *http.Request, cfg Config) {
	req.Header.Set("User-Agent", "witness-doctor/0")
	if cfg.APIKey != "" {
		req.Header.Set("X-Witness-API-Key", cfg.APIKey)
	}
}

func isLocalHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}
