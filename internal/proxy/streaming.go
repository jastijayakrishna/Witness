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

	"github.com/witness-proxy/witness-proxy/internal/providers"
	"github.com/witness-proxy/witness-proxy/internal/wal"
)

func (h *Handler) handleStream(w http.ResponseWriter, r *http.Request, provider *providers.Provider, body []byte, project string) {
	start := time.Now()

	// Prepare stream body (e.g., inject stream_options for OpenAI)
	if provider.PrepareStreamBody != nil {
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

	// Accumulate SSE events while streaming to client
	var events []providers.SSEEvent
	scanner := bufio.NewScanner(resp.Body)
	// Increase buffer for large SSE chunks
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)

	var currentEvent providers.SSEEvent
	isUsageChunk := false

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			// Empty line = end of event
			if currentEvent.Data != "" || currentEvent.Event != "" {
				events = append(events, currentEvent)

				// For OpenAI: check if this is the final usage-only chunk
				// (has usage but no content delta). Don't forward it.
				isUsageChunk = false
				if provider.Name == "openai" && currentEvent.Data != "" && currentEvent.Data != "[DONE]" {
					isUsageChunk = isOpenAIUsageOnlyChunk(currentEvent.Data)
				}

				if !isUsageChunk {
					// Forward event to client
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
		events = append(events, currentEvent)
		isUsageChunk = false
		if provider.Name == "openai" && currentEvent.Data != "" && currentEvent.Data != "[DONE]" {
			isUsageChunk = isOpenAIUsageOnlyChunk(currentEvent.Data)
		}
		if !isUsageChunk {
			writeSSEEvent(w, currentEvent)
			flusher.Flush()
		}
	}

	latency := time.Since(start)

	// Extract usage from accumulated events
	var usage providers.Usage
	if provider.ExtractStreamUsage != nil {
		usage, err = provider.ExtractStreamUsage(events)
		if err != nil {
			log.Warn().Err(err).Str("provider", provider.Name).Msg("failed to extract stream usage")
		}
	}

	cost := providers.ComputeCost(usage.Model, usage.InputTokens, usage.OutputTokens)
	promptHash := hashPrompt(body)

	// Write WAL BEFORE client connection closes
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
		Stream:       true,
	})
	if walErr != nil {
		log.Error().Err(walErr).Msg("failed to write WAL for stream")
	}
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
// NOT be forwarded to the client.
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
