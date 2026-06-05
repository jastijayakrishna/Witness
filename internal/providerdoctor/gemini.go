package providerdoctor

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

	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/providers"
)

type Config struct {
	APIKey  string
	Model   string
	BaseURL string
	Timeout time.Duration
}

type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type Report struct {
	Provider string  `json:"provider"`
	Model    string  `json:"model"`
	BaseURL  string  `json:"base_url"`
	Checks   []Check `json:"checks"`
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

func RunGemini(ctx context.Context, cfg Config) Report {
	if cfg.Model == "" {
		cfg.Model = "gemini-2.5-flash-lite"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://generativelanguage.googleapis.com"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}

	report := Report{Provider: "gemini", Model: cfg.Model, BaseURL: cfg.BaseURL}
	if cfg.APIKey == "" {
		report.Checks = append(report.Checks, Check{Name: "api_key", OK: false, Detail: "GOOGLE_API_KEY or GEMINI_API_KEY is required"})
		return report
	}
	report.Checks = append(report.Checks, Check{Name: "api_key", OK: true, Detail: "present"})

	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		report.Checks = append(report.Checks, Check{Name: "base_url", OK: false, Detail: "base URL must include scheme and host"})
		return report
	}
	report.Checks = append(report.Checks, Check{Name: "base_url", OK: true, Detail: cfg.BaseURL})

	if notice := providers.DeprecationNotice(cfg.Model); notice != "" {
		report.Checks = append(report.Checks, Check{Name: "model_status", OK: false, Detail: notice})
	} else {
		report.Checks = append(report.Checks, Check{Name: "model_status", OK: true, Detail: "active_or_not_known_deprecated"})
	}

	if providers.HasPricing(cfg.Model) {
		report.Checks = append(report.Checks, Check{Name: "pricing_known", OK: true, Detail: "cost can be computed"})
	} else {
		report.Checks = append(report.Checks, Check{Name: "pricing_known", OK: false, Detail: "model missing from pricing table; costs would record as zero"})
	}

	client := &http.Client{Timeout: cfg.Timeout}
	models, check := listGeminiModels(ctx, client, cfg)
	report.Checks = append(report.Checks, check)
	if check.OK {
		report.Checks = append(report.Checks, Check{Name: "model_available", OK: models[cfg.Model], Detail: modelAvailableDetail(cfg.Model, models[cfg.Model])})
	}
	report.Checks = append(report.Checks, generateGemini(ctx, client, cfg))
	return report
}

func listGeminiModels(ctx context.Context, client *http.Client, cfg Config) (map[string]bool, Check) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.BaseURL+"/v1beta/models", nil)
	if err != nil {
		return nil, Check{Name: "models_list", OK: false, Detail: err.Error()}
	}
	req.Header.Set("x-goog-api-key", cfg.APIKey)
	req.Header.Set("User-Agent", "witness-provider-doctor/0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, Check{Name: "models_list", OK: false, Detail: err.Error()}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, Check{Name: "models_list", OK: false, Detail: statusDetail(resp.StatusCode, body)}
	}

	var decoded struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, Check{Name: "models_list", OK: false, Detail: "invalid JSON response: " + err.Error()}
	}
	models := make(map[string]bool, len(decoded.Models))
	for _, model := range decoded.Models {
		name := strings.TrimPrefix(model.Name, "models/")
		if name != "" {
			models[name] = true
		}
	}
	return models, Check{Name: "models_list", OK: true, Detail: fmt.Sprintf("models_visible=%d", len(models))}
}

func generateGemini(ctx context.Context, client *http.Client, cfg Config) Check {
	payload := map[string]any{
		"contents": []map[string]any{{
			"role": "user",
			"parts": []map[string]string{{
				"text": "Reply with exactly: witness-provider-ok",
			}},
		}},
		"generationConfig": map[string]any{
			"temperature":     0,
			"maxOutputTokens": 8,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Check{Name: "quota_generate_content", OK: false, Detail: err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.BaseURL+"/v1beta/models/"+url.PathEscape(cfg.Model)+":generateContent", bytes.NewReader(body))
	if err != nil {
		return Check{Name: "quota_generate_content", OK: false, Detail: err.Error()}
	}
	req.Header.Set("x-goog-api-key", cfg.APIKey)
	req.Header.Set("User-Agent", "witness-provider-doctor/0")
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Check{Name: "quota_generate_content", OK: false, Detail: err.Error()}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Check{Name: "quota_generate_content", OK: false, Detail: statusDetail(resp.StatusCode, respBody)}
	}

	var decoded struct {
		ModelVersion  string `json:"modelVersion"`
		UsageMetadata *struct {
			TotalTokenCount int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(respBody, &decoded); err != nil {
		return Check{Name: "quota_generate_content", OK: false, Detail: "invalid JSON response: " + err.Error()}
	}
	detail := "status=200"
	if decoded.ModelVersion != "" {
		detail += " model_version=" + decoded.ModelVersion
	}
	if decoded.UsageMetadata != nil {
		detail += fmt.Sprintf(" total_tokens=%d", decoded.UsageMetadata.TotalTokenCount)
	}
	return Check{Name: "quota_generate_content", OK: true, Detail: detail}
}

func statusDetail(statusCode int, body []byte) string {
	class := classifyStatus(statusCode, body)
	safe := strings.TrimSpace(strings.ReplaceAll(string(body), "\n", " "))
	if len(safe) > 600 {
		safe = safe[:600] + "...<truncated>"
	}
	return fmt.Sprintf("status %d %s: %s", statusCode, class, safe)
}

func classifyStatus(statusCode int, body []byte) string {
	lower := strings.ToLower(string(body))
	switch {
	case statusCode == http.StatusTooManyRequests || strings.Contains(lower, "resource_exhausted") || strings.Contains(lower, "quota") || strings.Contains(lower, "rate limit"):
		return loop.ResultRateLimited
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden || strings.Contains(lower, "api key") || strings.Contains(lower, "permission") || strings.Contains(lower, "unauthorized"):
		return loop.ResultPermissionError
	case statusCode == http.StatusBadRequest || strings.Contains(lower, "invalid_argument") || strings.Contains(lower, "schema"):
		return loop.ResultSchemaError
	default:
		return loop.ResultUnknownError
	}
}

func modelAvailableDetail(model string, ok bool) string {
	if ok {
		return model + " visible"
	}
	return model + " not visible to this key/project"
}
