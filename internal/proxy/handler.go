package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
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
)

func init() {
	prometheus.MustRegister(normalizationRatio)
	prometheus.MustRegister(walWriteFailures)
	prometheus.MustRegister(loopConfidence)
	prometheus.MustRegister(loopSignalsTotal)
	prometheus.MustRegister(loopRedisFailures)
}

// Handler is the main reverse-proxy handler for LLM API requests.
type Handler struct {
	WAL       *wal.Writer
	Transport *http.Transport
	LoopStore *loop.StateStore // nil = loop detection disabled
	LoopCfg   loop.Config
}

// NewHandler creates a new proxy handler with connection pooling.
func NewHandler(w *wal.Writer, loopStore *loop.StateStore, loopCfg loop.Config) *Handler {
	return &Handler{
		WAL:       w,
		LoopStore: loopStore,
		LoopCfg:   loopCfg,
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

	// Extract tool calls from response
	var toolCalls []providers.ToolCall
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && provider.ExtractToolCalls != nil {
		toolCalls = provider.ExtractToolCalls(respBody)
	}

	// Compute cost
	cost := providers.ComputeCost(usage.Model, usage.InputTokens, usage.OutputTokens)

	// Compute prompt hash
	promptHash := hashPrompt(body)

	// Compute tool signature + args fingerprint (Phase 2)
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
	loopSignals, loopConf, loopAct := h.observeLoop(r.Context(), project, sessionID, toolCalls, usage, cost)

	// Write WAL BEFORE returning response (non-negotiable)
	walErr := h.WAL.Write(wal.Record{
		Project:          project,
		Provider:         provider.Name,
		Model:            usage.Model,
		PromptHash:       promptHash,
		InputTokens:      usage.InputTokens,
		OutputTokens:     usage.OutputTokens,
		TotalTokens:      usage.TotalTokens,
		Cost:             cost,
		LatencyMs:        latency.Milliseconds(),
		StatusCode:       resp.StatusCode,
		CacheHit:         false,
		Stream:           false,
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
// All Redis calls are wrapped with a 5ms timeout and fail open — a slow or
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

	// Load state from Redis (fail-open with timeout)
	loadCtx, loadCancel := context.WithTimeout(ctx, loopRedisTimeout)
	state, err := h.LoopStore.Load(loadCtx, project, sessionID)
	loadCancel()
	if err != nil {
		loopRedisFailures.WithLabelValues("load").Inc()
		log.Warn().Err(err).Str("project", project).Msg("loop state load failed, using empty state")
		state = loop.State{}
	}

	// Run detector (pure function, no I/O)
	newState, decision := loop.Observe(state, obs, h.LoopCfg)

	// Save updated state to Redis (fail-open with timeout)
	saveCtx, saveCancel := context.WithTimeout(ctx, loopRedisTimeout)
	if err := h.LoopStore.Save(saveCtx, project, sessionID, newState); err != nil {
		loopRedisFailures.WithLabelValues("save").Inc()
		log.Warn().Err(err).Str("project", project).Msg("loop state save failed")
	}
	saveCancel()

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
