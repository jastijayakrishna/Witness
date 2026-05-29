package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"

	"github.com/witness-proxy/witness-proxy/internal/attribution"
	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/providers"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

var (
	normalizationRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "llmproxy_normalization_ratio",
			Help: "Normalization ratio of prompt content per project. Below 0.5 indicates mostly dynamic data with low dedup potential.",
		},
		[]string{"project"},
	)
	walWriteFailures = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "llmproxy_wal_write_failures_total",
			Help: "Total WAL write failures. Each increment is a request whose cost record was lost.",
		},
	)
	loopConfidence = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "witness_loop_confidence",
			Help:    "Loop detector confidence score distribution.",
			Buckets: []float64{0, 0.10, 0.20, 0.30, 0.40, 0.50, 0.60, 0.70, 0.80, 0.90, 1.0},
		},
	)
	loopSignalsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "witness_loop_signals_total",
			Help: "Total loop signals fired by signal type.",
		},
		[]string{"signal"},
	)
	loopRedisFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "witness_loop_redis_failures_total",
			Help: "Total loop detector Redis failures (timeouts + errors) by operation.",
		},
		[]string{"op"},
	)
	upstreamTimeouts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "witness_upstream_timeouts_total",
			Help: "Upstream requests terminated due to timeout, by type (deadline=non-stream, idle=stream).",
		},
		[]string{"type"},
	)
	inflightGauge = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "witness_inflight_requests",
			Help: "Number of requests currently being proxied.",
		},
	)
	shedTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "witness_requests_shed_total",
			Help: "Total requests shed due to concurrency limit.",
		},
	)
)

func init() {
	prometheus.MustRegister(normalizationRatio)
	prometheus.MustRegister(walWriteFailures)
	prometheus.MustRegister(loopConfidence)
	prometheus.MustRegister(loopSignalsTotal)
	prometheus.MustRegister(loopRedisFailures)
	prometheus.MustRegister(upstreamTimeouts)
	prometheus.MustRegister(inflightGauge)
	prometheus.MustRegister(shedTotal)
}

// Handler is the main reverse-proxy handler for LLM API requests.
type Handler struct {
	WAL               *wal.Writer
	Transport         *http.Transport
	LoopStore         *loop.StateStore // nil = loop detection disabled
	LoopCfg           loop.Config
	NonStreamTimeout  time.Duration    // total deadline for non-streaming requests
	StreamIdleTimeout time.Duration    // max idle time between SSE events
	Inflight          chan struct{}     // semaphore; cap = max concurrent requests
	MaxResponseBody   int64            // max upstream response body size (0 = default)
}

// NewHandler creates a new proxy handler with connection pooling.
func NewHandler(w *wal.Writer, loopStore *loop.StateStore, loopCfg loop.Config) *Handler {
	return &Handler{
		WAL:               w,
		LoopStore:         loopStore,
		LoopCfg:           loopCfg,
		NonStreamTimeout:  upstreamNonStreamTimeout,
		StreamIdleTimeout: upstreamStreamIdleTimeout,
		Inflight:          make(chan struct{}, defaultMaxInflight),
		MaxResponseBody:   maxResponseBodySize,
		Transport: &http.Transport{
			MaxIdleConns:        200,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,

			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,

			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ForceAttemptHTTP2:     true,
		},
	}
}

// maxRequestBodySize caps the request body to prevent OOM from oversized payloads.
// 10MB accommodates large LLM context windows while bounding memory usage.
const maxRequestBodySize = 10 << 20 // 10MB

// upstreamNonStreamTimeout caps the total time for a non-streaming upstream
// request (connect + headers + body read). Prevents goroutine leaks when an
// upstream hangs after sending headers. 5 minutes accommodates thinking models.
const upstreamNonStreamTimeout = 5 * time.Minute

// upstreamStreamIdleTimeout is the maximum time between consecutive reads on a
// streaming upstream connection. Resets on each SSE line. Prevents goroutine
// leaks when an upstream stops sending events without closing the connection.
const upstreamStreamIdleTimeout = 5 * time.Minute

// defaultMaxInflight is the maximum number of requests the proxy will handle
// concurrently. Beyond this, requests are immediately shed with 503.
const defaultMaxInflight = 256

// maxResponseBodySize caps the upstream response body to prevent OOM from
// unexpectedly large responses. 50MB accommodates large JSON completions.
const maxResponseBodySize int64 = 50 << 20 // 50MB

// ServeHTTP handles incoming proxy requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Load shedding: non-blocking semaphore acquire. If the proxy is at
	// capacity, immediately return 503 with Retry-After so clients back off.
	select {
	case h.Inflight <- struct{}{}:
		// acquired
	default:
		shedTotal.Inc()
		w.Header().Set("Retry-After", "5")
		http.Error(w, `{"error":"server overloaded, retry later"}`, http.StatusServiceUnavailable)
		return
	}
	inflightGauge.Inc()
	defer func() {
		<-h.Inflight
		inflightGauge.Dec()
	}()

	provider := providers.Lookup(r.URL.Path)
	if provider == nil {
		http.Error(w, `{"error":"unknown provider"}`, http.StatusNotFound)
		return
	}

	// Read request body (capped at 10MB to prevent OOM)
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"request body too large or unreadable"}`, http.StatusBadRequest)
		return
	}
	r.Body.Close()

	// Resolve attribution
	project := ResolveProject(r)
	sessionID := ResolveSession(r)

	// Check if streaming
	isStream := provider.IsStreamRequest != nil && provider.IsStreamRequest(body)

	if isStream {
		h.handleStream(w, r, provider, body, project, sessionID)
		return
	}

	h.handleNonStream(w, r, provider, body, project, sessionID)
}

func (h *Handler) handleNonStream(w http.ResponseWriter, r *http.Request, provider *providers.Provider, body []byte, project, sessionID string) {
	start := time.Now()

	// Bound total upstream time to prevent goroutine leaks on hung upstreams
	ctx, cancel := context.WithTimeout(r.Context(), h.NonStreamTimeout)
	defer cancel()

	// Build upstream request: strip the provider prefix from path
	upstreamPath := strings.TrimPrefix(r.URL.Path, provider.PathPrefix)
	upstreamURL := fmt.Sprintf("%s%s", provider.Target.String(), upstreamPath)
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	upReq, err := http.NewRequestWithContext(ctx, r.Method, upstreamURL, bytes.NewReader(body))
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
		if ctx.Err() == context.DeadlineExceeded {
			upstreamTimeouts.WithLabelValues("deadline").Inc()
			log.Error().Err(err).Msg("upstream request timed out")
			http.Error(w, `{"error":"upstream request timed out"}`, http.StatusGatewayTimeout)
			return
		}
		log.Error().Err(err).Msg("upstream request failed")
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body (capped to prevent OOM from unexpectedly large responses)
	cap := h.MaxResponseBody
	if cap <= 0 {
		cap = maxResponseBodySize
	}
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, cap+1))
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			upstreamTimeouts.WithLabelValues("deadline").Inc()
			log.Error().Err(err).Msg("upstream response body read timed out")
			http.Error(w, `{"error":"upstream request timed out"}`, http.StatusGatewayTimeout)
			return
		}
		log.Error().Err(err).Msg("failed to read upstream response")
		http.Error(w, `{"error":"failed to read upstream response"}`, http.StatusBadGateway)
		return
	}
	if int64(len(respBody)) > cap {
		log.Warn().Int64("cap", cap).Int("got", len(respBody)).Msg("upstream response body exceeded cap — truncated")
		http.Error(w, `{"error":"upstream response too large"}`, http.StatusBadGateway)
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

	// Extract tool calls from response
	var toolCalls []providers.ToolCall
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && provider.ExtractToolCalls != nil {
		toolCalls = provider.ExtractToolCalls(respBody)
	}

	// Finalize: compute cost, normalization, loop detection, and write WAL
	h.finalizeRequest(r.Context(), provider.Name, body, usage, toolCalls, latency, resp.StatusCode, false, project, sessionID)

	// Write response to client
	copyHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// hopByHopHeaders is the set of headers that must not be forwarded by a proxy.
// Package-level to avoid allocating a new map on every request.
var hopByHopHeaders = map[string]bool{
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

// copyHeaders copies HTTP headers, skipping hop-by-hop and internal headers.
func copyHeaders(src, dst http.Header) {
	for k, vv := range src {
		if hopByHopHeaders[k] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// finalizeRequest handles post-response processing shared by streaming and
// non-streaming paths: cost computation, normalization ratio, loop detection,
// and WAL writing.
func (h *Handler) finalizeRequest(ctx context.Context, providerName string, body []byte, usage providers.Usage, toolCalls []providers.ToolCall, latency time.Duration, statusCode int, stream bool, project, sessionID string) {
	cost := providers.ComputeCost(usage.Model, usage.InputTokens, usage.OutputTokens)
	promptHash := hashPrompt(body)
	toolSig, argsFP := computeToolFingerprints(toolCalls)

	// Log normalization ratio per project (Phase 2)
	ratio := attribution.NormalizationRatio(string(body))
	normalizationRatio.WithLabelValues(project).Set(ratio)
	if ratio < 0.5 {
		log.Warn().
			Str("project", project).
			Float64("ratio", ratio).
			Msg("low normalization ratio: project feeds mostly dynamic data, dedup accuracy is lower")
	}

	// Loop detection (shadow mode — observe only, no enforcement yet)
	loopSignals, loopConf, loopAct := h.observeLoop(ctx, project, sessionID, toolCalls, usage, cost)

	// Write WAL BEFORE returning response (non-negotiable)
	walErr := h.WAL.Write(wal.Record{
		Project:          project,
		Provider:         providerName,
		Model:            usage.Model,
		PromptHash:       promptHash,
		InputTokens:      usage.InputTokens,
		OutputTokens:     usage.OutputTokens,
		TotalTokens:      usage.TotalTokens,
		Cost:             cost,
		LatencyMs:        latency.Milliseconds(),
		StatusCode:       statusCode,
		CacheHit:         false,
		Stream:           stream,
		SessionID:        sessionID,
		ToolSignature:    toolSig,
		ArgsFingerprint:  argsFP,
		LoopSignalsFired: loopSignals,
		LoopConfidence:   loopConf,
		LoopAction:       loopAct,
	})
	if walErr != nil {
		walWriteFailures.Inc()
		log.Error().Err(walErr).Msg("failed to write WAL — reconciliation gap")
	}
}

// hashPrompt produces a normalized SHA256 hash of the request body.
// Phase 2: Uses prompt normalization to strip dynamic data for deduplication.
func hashPrompt(body []byte) string {
	return attribution.HashNormalizedPrompt(string(body))
}

// computeToolFingerprints returns tool_signature (first tool name) and
// args_fingerprint (SHA256 of normalized canonical args) from extracted tool calls.
// Returns empty strings if no tool calls present.
func computeToolFingerprints(calls []providers.ToolCall) (toolSig, argsFP string) {
	if len(calls) == 0 {
		return "", ""
	}
	toolSig = calls[0].Name

	// Canonical args: normalize dynamic values, sort keys, hash
	normalized := attribution.NormalizePrompt(calls[0].Arguments)
	canonical := canonicalJSON(normalized)
	hash := sha256.Sum256([]byte(canonical))
	argsFP = fmt.Sprintf("%x", hash[:8])

	return toolSig, argsFP
}

// canonicalJSON sorts JSON object keys for stable hashing.
// Falls back to the input string if it's not valid JSON.
func canonicalJSON(s string) string {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	return canonicalValue(v)
}

func canonicalValue(v any) string {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%q:%s", k, canonicalValue(val[k])))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		parts := make([]string, 0, len(val))
		for _, item := range val {
			parts = append(parts, canonicalValue(item))
		}
		return "[" + strings.Join(parts, ",") + "]"
	default:
		b, _ := json.Marshal(val)
		return string(b)
	}
}

// loopRedisTimeout caps each Redis call in the loop detector path.
// 5ms is ~10x a local Redis GET/SET and well under the 50ms p95 budget.
const loopRedisTimeout = 5 * time.Millisecond

// observeLoop runs the loop detector for this request and returns WAL fields.
// Returns ("", 0, "") when the detector is disabled (LoopStore == nil).
// Uses atomic WATCH/MULTI to prevent concurrent requests from clobbering each
// other's state. Falls back to stateless detection on Redis errors — a slow or
// down Redis never adds more than 10ms to the request and never blocks it.
func (h *Handler) observeLoop(ctx context.Context, project, sessionID string, toolCalls []providers.ToolCall, usage providers.Usage, cost float64) (signalsFired string, confidence float64, action string) {
	if h.LoopStore == nil {
		return "", 0, ""
	}

	// Build observation from the first tool call (if any)
	var toolName string
	var args any
	if len(toolCalls) > 0 {
		toolName = toolCalls[0].Name
		// Parse arguments as JSON for stable hashing; fall back to raw string
		var parsed any
		if err := json.Unmarshal([]byte(toolCalls[0].Arguments), &parsed); err == nil {
			args = parsed
		} else {
			args = toolCalls[0].Arguments
		}
	}

	obs := loop.Observation{
		Project:      project,
		SessionID:    sessionID,
		ToolName:     toolName,
		Args:         args,
		PromptTokens: usage.InputTokens,
		OutputTokens: usage.OutputTokens,
		CostUSD:      cost,
		UnixMillis:   time.Now().UnixMilli(),
	}

	// Atomic load→observe→save via WATCH/MULTI (fail-open with timeout)
	txCtx, txCancel := context.WithTimeout(ctx, 2*loopRedisTimeout)
	var decision loop.Decision
	_, err := h.LoopStore.Transact(txCtx, project, sessionID, func(state loop.State) loop.State {
		var newState loop.State
		newState, decision = loop.Observe(state, obs, h.LoopCfg)
		return newState
	})
	txCancel()
	if err != nil {
		loopRedisFailures.WithLabelValues("transact").Inc()
		log.Warn().Err(err).Str("project", project).Msg("loop state transact failed, running stateless")
		// Fail-open: run detector with empty state so we still get a decision
		_, decision = loop.Observe(loop.State{}, obs, h.LoopCfg)
	}

	// Compute effective action (cap by configured action)
	effective := loop.EffectiveAction(loop.Action(h.LoopCfg.Action), decision.ActionCeiling)

	// Safety floor: if no session ID and RequireSessionForBlock, cap at shadow
	if sessionID == "" && h.LoopCfg.RequireSessionForBlock && effective == loop.ActionBlock {
		effective = loop.ActionWarn
	}

	// Record metrics
	loopConfidence.Observe(decision.Confidence)
	for _, sig := range decision.SignalsFired {
		loopSignalsTotal.WithLabelValues(sig).Inc()
	}

	// Log when signals fire
	if len(decision.SignalsFired) > 0 {
		log.Info().
			Str("project", project).
			Str("session_id", sessionID).
			Strs("signals", decision.SignalsFired).
			Float64("confidence", decision.Confidence).
			Str("ceiling", string(decision.ActionCeiling)).
			Str("effective", string(effective)).
			Str("reason", decision.Reason).
			Msg("loop detector fired")
	}

	return strings.Join(decision.SignalsFired, ","), decision.Confidence, string(effective)
}
