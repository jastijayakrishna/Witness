package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/witness-proxy/witness-proxy/internal/attribution"
	"github.com/witness-proxy/witness-proxy/internal/providers"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

func (h *Handler) handleStream(w http.ResponseWriter, r *http.Request, provider *providers.Provider, body []byte, project, sessionID string) {
	start := time.Now()

	// Before modifying the body, check if the client already requested
	// include_usage. If they did, we must NOT suppress the usage chunk
	// later — they expect it for their own accounting.
	weInjectedUsage := false
	if provider.PrepareStreamBody != nil {
		if provider.Name == "openai" {
			weInjectedUsage = !clientHasIncludeUsage(body)
		}
		modified, err := provider.PrepareStreamBody(body)
		if err != nil {
			log.Error().Err(err).Msg("failed to prepare stream body")
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		body = modified
	}

	// Build upstream request
	upstreamPath := strings.TrimPrefix(r.URL.Path, provider.PathPrefix)
	upstreamURL := fmt.Sprintf("%s%s", provider.Target.String(), upstreamPath)
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(body))
	if err != nil {
		log.Error().Err(err).Msg("failed to create upstream stream request")
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	copyHeaders(r.Header, upReq.Header)
	upReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	resp, err := h.Transport.RoundTrip(upReq)
	if err != nil {
		log.Error().Err(err).Msg("upstream stream request failed")
		http.Error(w, `{"error":"upstream request failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// If the upstream returned a non-streaming response (e.g., error), pass it through directly
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/event-stream") {
		respBody, _ := io.ReadAll(resp.Body)
		copyHeaders(resp.Header, w.Header())
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	// Set up streaming response
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, `{"error":"streaming not supported"}`, http.StatusInternalServerError)
		return
	}

	copyHeaders(resp.Header, w.Header())
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(resp.StatusCode)

	// Only accumulate events needed for usage + tool_call extraction — NOT every
	// content delta. Long agent streams can produce thousands of content chunks;
	// storing them all is an OOM risk under concurrency.
	var usageEvents []providers.SSEEvent
	var toolCallEvents []providers.SSEEvent
	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer for large SSE chunks
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	var currentEvent providers.SSEEvent

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// Empty line = end of event
			if currentEvent.Data != "" || currentEvent.Event != "" {
				// Decide whether to keep this event for usage extraction
				if isUsageRelevantEvent(provider.Name, currentEvent, len(usageEvents) == 0) {
					usageEvents = append(usageEvents, currentEvent)
				}

				// Keep tool_call-relevant events for tool extraction
				if isToolCallRelevantEvent(provider.Name, currentEvent) {
					toolCallEvents = append(toolCallEvents, currentEvent)
				}

				// Decide whether to forward this event to the client.
				// Suppress usage-only chunks ONLY when we injected include_usage.
				suppress := false
				if weInjectedUsage && provider.Name == "openai" &&
					currentEvent.Data != "" && currentEvent.Data != "[DONE]" {
					suppress = isOpenAIUsageOnlyChunk(currentEvent.Data)
				}

				if !suppress {
					writeSSEEvent(w, currentEvent)
					flusher.Flush()
				}

				currentEvent = providers.SSEEvent{}
			} else {
				// Forward empty lines as-is (SSE delimiter)
				fmt.Fprint(w, "\n")
				flusher.Flush()
			}
			continue
		}

		if strings.HasPrefix(line, "event:") || strings.HasPrefix(line, "event: ") {
			currentEvent.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") || strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data:")
			data = strings.TrimPrefix(data, " ")
			if currentEvent.Data != "" {
				currentEvent.Data += "\n" + data
			} else {
				currentEvent.Data = data
			}
		} else {
			// Forward unknown lines directly
			fmt.Fprintf(w, "%s\n", line)
			flusher.Flush()
		}
	}

	// Handle any remaining event
	if currentEvent.Data != "" || currentEvent.Event != "" {
		if isUsageRelevantEvent(provider.Name, currentEvent, len(usageEvents) == 0) {
			usageEvents = append(usageEvents, currentEvent)
		}
		if isToolCallRelevantEvent(provider.Name, currentEvent) {
			toolCallEvents = append(toolCallEvents, currentEvent)
		}

		suppress := false
		if weInjectedUsage && provider.Name == "openai" &&
			currentEvent.Data != "" && currentEvent.Data != "[DONE]" {
			suppress = isOpenAIUsageOnlyChunk(currentEvent.Data)
		}
		if !suppress {
			writeSSEEvent(w, currentEvent)
			flusher.Flush()
		}
	}

	latency := time.Since(start)

	// Extract usage from the (small) set of usage-relevant events
	var usage providers.Usage
	if provider.ExtractStreamUsage != nil {
		usage, err = provider.ExtractStreamUsage(usageEvents)
		if err != nil {
			log.Warn().Err(err).Str("provider", provider.Name).Msg("failed to extract stream usage")
		}
	}

	// Extract tool calls from accumulated tool_call events
	var toolCalls []providers.ToolCall
	if provider.ExtractStreamToolCalls != nil {
		toolCalls = provider.ExtractStreamToolCalls(toolCallEvents)
	}

	cost := providers.ComputeCost(usage.Model, usage.InputTokens, usage.OutputTokens)
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

	// Write WAL BEFORE client connection closes
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
		Stream:           true,
		SessionID:        sessionID,
		ToolSignature:    toolSig,
		ArgsFingerprint:  argsFP,
		LoopSignalsFired: loopSignals,
		LoopConfidence:   loopConf,
		LoopAction:       loopAct,
	})
	if walErr != nil {
		walWriteFailures.Inc()
		log.Error().Err(walErr).Msg("failed to write WAL for stream — reconciliation gap")
	}
}

// isUsageRelevantEvent returns true if this event should be kept for usage
// extraction. Content delta events are forwarded to the client but NOT stored,
// keeping memory bounded regardless of stream length.
func isUsageRelevantEvent(providerName string, ev providers.SSEEvent, isFirst bool) bool {
	switch providerName {
	case "openai":
		// Keep first event (model name fallback) + any event with real usage data.
		if isFirst {
			return true
		}
		if ev.Data == "" || ev.Data == "[DONE]" {
			return false
		}
		return isOpenAIUsageOnlyChunk(ev.Data)

	case "anthropic":
		// Only message_start (input tokens + model) and message_delta (output tokens).
		return ev.Event == "message_start" || ev.Event == "message_delta"

	default:
		// Unknown provider: keep all for safety.
		return true
	}
}

// isToolCallRelevantEvent returns true if this event may contain tool call data.
func isToolCallRelevantEvent(providerName string, ev providers.SSEEvent) bool {
	if ev.Data == "" || ev.Data == "[DONE]" {
		return false
	}
	switch providerName {
	case "openai":
		// OpenAI tool_call deltas appear in choices[].delta.tool_calls
		return strings.Contains(ev.Data, "tool_calls")
	case "anthropic":
		// Anthropic tool_use arrives via content_block_start and content_block_delta
		return ev.Event == "content_block_start" || ev.Event == "content_block_delta"
	default:
		return false
	}
}

// clientHasIncludeUsage checks if the client's original request body already
// has stream_options.include_usage set to true. If so, we must not suppress
// the usage chunk — the client expects it for their own accounting.
func clientHasIncludeUsage(body []byte) bool {
	var req struct {
		StreamOptions *struct {
			IncludeUsage bool `json:"include_usage"`
		} `json:"stream_options"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return false
	}
	return req.StreamOptions != nil && req.StreamOptions.IncludeUsage
}

// writeSSEEvent writes a single SSE event to the writer.
func writeSSEEvent(w io.Writer, ev providers.SSEEvent) {
	if ev.Event != "" {
		fmt.Fprintf(w, "event: %s\n", ev.Event)
	}
	if ev.Data != "" {
		// Data may contain newlines (multi-line data fields)
		for _, line := range strings.Split(ev.Data, "\n") {
			fmt.Fprintf(w, "data: %s\n", line)
		}
	}
	fmt.Fprint(w, "\n")
}

// isOpenAIUsageOnlyChunk checks if an OpenAI streaming chunk contains usage
// data but no content delta — these are the injected usage chunks that should
// NOT be forwarded to the client (when we injected include_usage).
func isOpenAIUsageOnlyChunk(data string) bool {
	var chunk struct {
		Usage   *json.RawMessage `json:"usage"`
		Choices []struct {
			Delta struct {
				Content *string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal([]byte(data), &chunk); err != nil {
		return false
	}
	// Has usage and either no choices or empty delta content
	if chunk.Usage == nil {
		return false
	}
	if len(chunk.Choices) == 0 {
		return true
	}
	for _, c := range chunk.Choices {
		if c.Delta.Content != nil && *c.Delta.Content != "" {
			return false
		}
	}
	return true
}
