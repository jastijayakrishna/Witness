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
		cfg.Project = "hubbleops-doctor"
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
		report.Checks = append(report.Checks, Check{Name: "base_url", OK: false, Detail: "use HTTPS for non-local HubbleOps endpoints"})
		return report
	}
	report.Checks = append(report.Checks, Check{Name: "base_url", OK: true, Detail: cfg.BaseURL})

	client := &http.Client{Timeout: cfg.Timeout}
	report.Checks = append(report.Checks, getJSON(ctx, client, cfg, "/livez", "proxy_reachable"))
	readyCheck, ready := getReadiness(ctx, client, cfg)
	report.Checks = append(report.Checks, readyCheck)
	report.Checks = append(report.Checks, componentCheck(ready, "postgres"))
	report.Checks = append(report.Checks, componentCheck(ready, "redis"))
	report.Checks = append(report.Checks, componentCheck(ready, "wal"))
	report.Checks = append(report.Checks, authConfigCheck(cfg, parsed.Hostname()))
	actionCheck, actionProbe := postActionEvent(ctx, client, cfg, "/v1/action/check", "action_check", map[string]any{
		"project":      cfg.Project,
		"session_id":   "hubbleops-doctor",
		"step_id":      "doctor-check",
		"action_name":  "hubbleops_doctor_noop",
		"action_risk":  "read",
		"args":         map[string]any{"probe": true},
		"unix_millis":  time.Now().UnixMilli(),
		"result_class": "",
	})
	report.Checks = append(report.Checks, actionCheck)
	report.Checks = append(report.Checks, receiptSigningCheck(cfg, parsed.Hostname(), actionProbe))
	actionResult, _ := postActionEvent(ctx, client, cfg, "/v1/action/result", "action_result", map[string]any{
		"project":          cfg.Project,
		"session_id":       "hubbleops-doctor",
		"step_id":          "doctor-result",
		"action_name":      "hubbleops_doctor_noop",
		"action_risk":      "read",
		"args":             map[string]any{"probe": true},
		"result":           map[string]any{"ok": true},
		"result_class":     "success",
		"state_delta_hash": "hubbleops-doctor-ok",
		"unix_millis":      time.Now().UnixMilli(),
	})
	report.Checks = append(report.Checks, actionResult)
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
		return Check{Name: name, OK: false, Detail: friendlyHTTPError(err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Check{Name: name, OK: false, Detail: fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	return Check{Name: name, OK: true, Detail: strings.TrimSpace(string(body))}
}

type actionProbe struct {
	Action     string `json:"action"`
	FailOpen   bool   `json:"fail_open"`
	WouldBlock string `json:"would_action"`
	Reason     string `json:"reason"`
	Receipt    struct {
		Signature string `json:"signature"`
		KeyID     string `json:"key_id"`
	} `json:"receipt"`
}

func getReadiness(ctx context.Context, client *http.Client, cfg Config) (Check, map[string]string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.BaseURL+"/readyz", nil)
	if err != nil {
		return Check{Name: "readyz", OK: false, Detail: err.Error()}, nil
	}
	addHeaders(req, cfg)
	resp, err := client.Do(req)
	if err != nil {
		return Check{Name: "readyz", OK: false, Detail: friendlyHTTPError(err)}, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Check{Name: "readyz", OK: false, Detail: fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))}, nil
	}
	var decoded map[string]string
	if err := json.Unmarshal(body, &decoded); err != nil {
		return Check{Name: "readyz", OK: false, Detail: "invalid JSON response: " + err.Error()}, nil
	}
	if decoded["status"] != "healthy" {
		return Check{Name: "readyz", OK: false, Detail: strings.TrimSpace(string(body))}, decoded
	}
	return Check{Name: "readyz", OK: true, Detail: "status=healthy"}, decoded
}

func componentCheck(ready map[string]string, name string) Check {
	checkName := name + "_reachable"
	if name == "wal" {
		checkName = "wal_writable"
	}
	if ready == nil {
		return Check{Name: checkName, OK: false, Detail: "readyz did not return component status"}
	}
	status := ready[name]
	if status == "" {
		return Check{Name: checkName, OK: false, Detail: "readyz response missing " + name + " status"}
	}
	if status != "ok" {
		return Check{Name: checkName, OK: false, Detail: "status=" + status}
	}
	return Check{Name: checkName, OK: true, Detail: "status=ok"}
}

func authConfigCheck(cfg Config, hostname string) Check {
	if cfg.APIKey != "" {
		return Check{Name: "auth_config", OK: true, Detail: "api key provided"}
	}
	if isLocalHost(hostname) {
		return Check{Name: "auth_config", OK: true, Detail: "no api key; expecting local dev auth bypass"}
	}
	return Check{Name: "auth_config", OK: false, Detail: "no API key for non-local endpoint; set HUBBLEOPS_API_KEY or pass -api-key"}
}

func receiptSigningCheck(cfg Config, hostname string, probe actionProbe) Check {
	if probe.Receipt.Signature != "" {
		detail := "signed"
		if probe.Receipt.KeyID != "" {
			detail += " key_id=" + probe.Receipt.KeyID
		}
		return Check{Name: "receipt_signing_config", OK: true, Detail: detail}
	}
	if cfg.APIKey == "" && isLocalHost(hostname) {
		return Check{Name: "receipt_signing_config", OK: true, Detail: "unsigned local/dev receipt"}
	}
	return Check{Name: "receipt_signing_config", OK: false, Detail: "receipt missing signature; set HUBBLEOPS_RECEIPT_SIGNING_SECRET"}
}

func postActionEvent(ctx context.Context, client *http.Client, cfg Config, path, name string, payload map[string]any) (Check, actionProbe) {
	var decoded actionProbe
	body, err := json.Marshal(payload)
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}, decoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return Check{Name: name, OK: false, Detail: err.Error()}, decoded
	}
	addHeaders(req, cfg)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Project", cfg.Project)

	resp, err := client.Do(req)
	if err != nil {
		return Check{Name: name, OK: false, Detail: friendlyHTTPError(err)}, decoded
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := fmt.Sprintf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		if resp.StatusCode == http.StatusUnauthorized {
			detail += "; provide -api-key or set HUBBLEOPS_API_KEY"
		}
		return Check{Name: name, OK: false, Detail: detail}, decoded
	}

	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return Check{Name: name, OK: false, Detail: "invalid JSON response: " + err.Error()}, decoded
	}
	if decoded.Action == "block" {
		return Check{Name: name, OK: false, Detail: strings.TrimSpace(string(respBody))}, decoded
	}
	detail := "action=" + decoded.Action
	if decoded.FailOpen {
		detail += " fail_open=true"
	}
	if decoded.WouldBlock != "" && decoded.WouldBlock != "none" {
		detail += " would_action=" + decoded.WouldBlock
	}
	return Check{Name: name, OK: true, Detail: detail}, decoded
}

func addHeaders(req *http.Request, cfg Config) {
	req.Header.Set("User-Agent", "hubbleops-doctor/0")
	if cfg.APIKey != "" {
		req.Header.Set("X-HubbleOps-API-Key", cfg.APIKey)
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

func friendlyHTTPError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused") {
		return msg + "; is HubbleOps running? try `docker compose -f deploy/docker-compose.yml up --build -d`"
	}
	return msg
}
