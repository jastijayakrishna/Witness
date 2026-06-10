// Package synthcorpus replays synthetic-corpus JSONL sessions through the REAL
// Witness pipeline (loop detector + action firewall) and scores the results.
// It never reimplements detection logic; it drives loop.Decide / loop.Observe /
// ActionStore.Decide exactly as internal/proxy/tool_events.go does.
package synthcorpus

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Event mirrors the proxy's toolEventRequest JSON shape plus the corpus
// ground-truth fields (label, expected_action, expected_signal, source_incident).
type Event struct {
	Project                string  `json:"project"`
	SessionID              string  `json:"session_id"`
	StepID                 string  `json:"step_id"`
	ToolName               string  `json:"tool_name"`
	ActionName             string  `json:"action_name"`
	Args                   any     `json:"args"`
	Result                 any     `json:"result"`
	ResultClass            string  `json:"result_class"`
	StateDeltaHash         string  `json:"state_delta_hash"`
	PromptTokens           int     `json:"prompt_tokens"`
	OutputTokens           int     `json:"output_tokens"`
	CostUSD                float64 `json:"cost_usd"`
	UnixMillis             int64   `json:"unix_millis"`
	AgentID                string  `json:"agent_id"`
	UserID                 string  `json:"user_id"`
	ActionRisk             string  `json:"action_risk"`
	IdempotencyKey         string  `json:"idempotency_key"`
	ResourceID             string  `json:"resource_id"`
	AmountCents            int64   `json:"amount_cents"`
	MaxAmountCents         int64   `json:"max_amount_cents"`
	BackupID               string  `json:"backup_id"`
	Recipient              string  `json:"recipient"`
	AllowedDomain          string  `json:"allowed_domain"`
	CapabilityToken        string  `json:"capability_token"`
	DuplicateWindowSeconds int     `json:"duplicate_window_seconds"`

	Label          string `json:"label"`
	ExpectedAction string `json:"expected_action"`
	ExpectedSignal string `json:"expected_signal"`
	SourceIncident string `json:"source_incident"`
}

// Session is one agent session's events in stream order.
type Session struct {
	Project   string
	SessionID string
	Events    []Event
}

func ReadJSONL(r io.Reader, source string) ([]Event, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	var events []Event
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", source, lineNo, err)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", source, err)
	}
	return events, nil
}

// ReadDir reads every *.jsonl file in dir (sorted by name) and concatenates events.
func ReadDir(dir string) ([]Event, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no *.jsonl files in %s", dir)
	}
	var all []Event
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		events, err := ReadJSONL(f, filepath.Base(file))
		f.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, events...)
	}
	return all, nil
}

// GroupSessions splits events into per-session streams, preserving first-seen
// session order and within-session event order.
func GroupSessions(events []Event) []Session {
	type key struct{ project, session string }
	index := make(map[key]int)
	var out []Session
	for _, ev := range events {
		k := key{ev.Project, ev.SessionID}
		i, ok := index[k]
		if !ok {
			i = len(out)
			index[k] = i
			out = append(out, Session{Project: ev.Project, SessionID: ev.SessionID})
		}
		out[i].Events = append(out[i].Events, ev)
	}
	return out
}
