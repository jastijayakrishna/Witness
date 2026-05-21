package proxy

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/witness-proxy/witness-proxy/internal/providers"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

// Handler is the main reverse-proxy handler for LLM API requests.
type Handler struct {
	WAL       *wal.Writer
	Transport *http.Transport
}

// NewHandler creates a new proxy handler with connection pooling.
func NewHandler(w *wal.Writer) *Handler {
	return &Handler{
		WAL: w,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// ServeHTTP handles incoming proxy requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	provider := providers.Lookup(r.URL.Path)
	if provider == nil {
		http.Error(w, `{"error":"unknown provider"}`, http.StatusNotFound)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// Resolve attribution
	project := ResolveProject(r)

	// Check if streaming
	isStream := provider.IsStreamRequest != nil && provider.IsStreamRequest(body)

	if isStream {
		h.handleStream(w, r, provider, body, project)
		return
	}

	h.handleNonStream(w, r, provider, body, project)
}

func (h *Handler) handleNonStream(w http.ResponseWriter, r *http.Request, provider *providers.Provider, body []byte, project string) {
	start := time.Now()

	// Build upstream request: strip the provider prefix from path
	upstreamPath := strings.TrimPrefix(r.URL.Path, provider.PathPrefix)
	upstreamURL := fmt.Sprintf("%s%s", provider.Target.String(), upstreamPath)
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		log.Error().Err(err).Msg("failed to create upstream request")
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	// Copy headers (except Host and X-Project)
	copyHeaders(r.Header, upReq.Header)
	upReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	// Forward request
	resp, err := h.Transport.RoundTrip(upReq)
	if err != nil {
		log.Error().Err(err).Msg("upstream request failed")
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("failed to read upstream response")
		http.Error(w, `{"error":"failed to read upstream response"}`, http.StatusBadGateway)
		return
	}

	latency := time.Since(start)

	// Extract usage
	var usage providers.Usage
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && provider.ExtractUsage != nil {
		usage, err = provider.ExtractUsage(respBody)
		if err != nil {
			log.Warn().Err(err).Str("provider", provider.Name).Msg("failed to extract usage")
		}
	}

	// Compute cost
	cost := providers.ComputeCost(usage.Model, usage.InputTokens, usage.OutputTokens)

	// Compute prompt hash
	promptHash := hashPrompt(body)

	// Write WAL BEFORE returning response (non-negotiable)
	walErr := h.WAL.Write(wal.Record{
		Project:      project,
		Provider:     provider.Name,
		Model:        usage.Model,
		PromptHash:   promptHash,
		InputTokens:  usage.InputTokens,
		OutputTokens: usage.OutputTokens,
		TotalTokens:  usage.TotalTokens,
		Cost:         cost,
		LatencyMs:    latency.Milliseconds(),
		StatusCode:   resp.StatusCode,
		CacheHit:     false,
		Stream:       false,
	})
	if walErr != nil {
		log.Error().Err(walErr).Msg("failed to write WAL")
		// Still return the response — WAL failure is logged but not fatal to the request
	}

	// Write response to client
	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// copyHeaders copies HTTP headers, skipping hop-by-hop and internal headers.
func copyHeaders(src, dst http.Header) {
	skip := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
		"Proxy-Authorization": true,
		"Proxy-Authenticate":  true,
		"Te":                  true,
		"Trailers":            true,
		"X-Project":           true,
	}
	for k, vv := range src {
		if skip[k] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// hashPrompt produces a SHA256 truncated hex hash of the request body.
func hashPrompt(body []byte) string {
	h := sha256.Sum256(body)
	return fmt.Sprintf("%x", h[:8])
}
