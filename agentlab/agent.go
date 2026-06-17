// Package main is agentlab: a disposable stress harness that drives a REAL
// LLM agent (Gemini function calling) against a real, embedded HubbleOps and
// reports — brutally honestly — what the firewall caught and what it missed.
//
// Nothing in the product imports this folder. Delete agentlab/ to remove it.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ToolCall is one function call proposed by the planner (the model).
type ToolCall struct {
	Name string
	Args map[string]any
}

// Tool is a fake business tool plus the HubbleOps protocol parameters an SDK
// integration would declare for it.
type Tool struct {
	Name        string
	Description string
	Schema      map[string]any
	Risk        string

	// Execute runs the fake side effect. attempt is the 1-based count of
	// executions of THIS tool within the scene, which is how scenes inject
	// failures ("first call times out, second succeeds").
	Execute func(args map[string]any, attempt int) (result map[string]any, resultClass string)

	// IdempotencyKey derives the key an integration would send. Nil = unkeyed.
	IdempotencyKey func(args map[string]any) string
	AmountCents    func(args map[string]any) int64
	MaxAmountCents int64
	BackupID       string
	// DuplicateWindowSeconds is sent verbatim when > 0 (W5 sends a hostile 1).
	DuplicateWindowSeconds int
}

// Episode is one user ask within a scene's conversation.
type Episode struct {
	UserMessage string
	// PauseBefore lets a scene wait out a lease or duplicate window first.
	PauseBefore time.Duration
}

// Scene is one best-case or worst-case scenario.
type Scene struct {
	Name        string
	Expect      string // CLEAN | CAUGHT | PARTIAL | MISSED
	Description string
	System      string
	Tools       []Tool
	Episodes    []Episode
	MaxTurnsPerEpisode int
	// RotateSessionEachCall makes the agent shed its session per call (W7).
	RotateSessionEachCall bool
	// Verdict inspects the transcript and returns the achieved verdict plus
	// human-readable findings.
	Verdict func(tr *Transcript) (string, []string)
}

// ActionEvent records one tool call's full round trip through HubbleOps.
type ActionEvent struct {
	Episode     int
	Turn        int
	Tool        string
	Args        map[string]any
	CheckStatus int
	Action      string
	Signals     []string
	Reason      string
	Executed    bool
	ResultClass string
}

// Transcript accumulates everything that happened in one scene run.
type Transcript struct {
	Scene      string
	Events     []ActionEvent
	Executions map[string]int
	Notes      []string
}

func (tr *Transcript) blocked() []ActionEvent {
	var out []ActionEvent
	for _, ev := range tr.Events {
		if ev.CheckStatus == http.StatusTooManyRequests || ev.CheckStatus == http.StatusUnprocessableEntity || ev.CheckStatus == http.StatusConflict {
			out = append(out, ev)
		}
	}
	return out
}

func (tr *Transcript) count(pred func(ActionEvent) bool) int {
	n := 0
	for _, ev := range tr.Events {
		if pred(ev) {
			n++
		}
	}
	return n
}

func (tr *Transcript) hasSignal(name string) bool {
	for _, ev := range tr.Events {
		for _, s := range ev.Signals {
			if s == name {
				return true
			}
		}
	}
	return false
}

// checkResponse is the subset of the HubbleOps check/result response the lab uses.
type checkResponse struct {
	Action     string          `json:"action"`
	Signals    []string        `json:"signals"`
	Reason     string          `json:"reason"`
	ClaimNonce string          `json:"claim_nonce"`
	Replay     json.RawMessage `json:"replay"`
}

// runScene drives one scene: planner proposes calls, HubbleOps adjudicates, the
// fake tool executes only when allowed, and every decision is fed back to the
// planner the way a real integration would.
func runScene(ctx context.Context, lab *hubbleopsLab, p planner, scene Scene) (*Transcript, error) {
	tr := &Transcript{Scene: scene.Name, Executions: map[string]int{}}
	tools := map[string]*Tool{}
	for i := range scene.Tools {
		tools[scene.Tools[i].Name] = &scene.Tools[i]
	}
	maxTurns := scene.MaxTurnsPerEpisode
	if maxTurns <= 0 {
		maxTurns = 10
	}
	session := "scene-" + slug(scene.Name)
	// Each scene authenticates as its own agent so limits scoped to the key
	// identity are isolated per scene, exactly like distinct agents in a fleet.
	sceneKey := "agentlab-key-" + slug(scene.Name)
	callSeq := 0

	for epIdx, ep := range scene.Episodes {
		if ep.PauseBefore > 0 {
			tr.Notes = append(tr.Notes, fmt.Sprintf("episode %d: waited %s before asking", epIdx+1, ep.PauseBefore))
			time.Sleep(ep.PauseBefore)
		}
		p.UserMessage(ep.UserMessage)

		for turn := 1; turn <= maxTurns; turn++ {
			calls, err := p.Next(ctx)
			if err != nil {
				return tr, fmt.Errorf("planner: %w", err)
			}
			if len(calls) == 0 {
				break // the model decided it is done
			}
			backoff := time.Duration(0)
			for _, call := range calls {
				tool, ok := tools[call.Name]
				if !ok {
					p.ToolResult(call, map[string]any{"error": "unknown tool"})
					continue
				}
				callSeq++
				callSession := session
				if scene.RotateSessionEachCall {
					callSession = fmt.Sprintf("%s-rotated-%d", session, callSeq)
				}

				payload := map[string]any{
					"project":     labProject,
					"session_id":  callSession,
					"step_id":     fmt.Sprintf("%s-%d", slug(scene.Name), callSeq),
					"action_name": tool.Name,
					"action_risk": tool.Risk,
					"args":        call.Args,
					"agent_id":    "agentlab-gemini",
				}
				if tool.IdempotencyKey != nil {
					payload["idempotency_key"] = tool.IdempotencyKey(call.Args)
				}
				if tool.AmountCents != nil {
					payload["amount_cents"] = tool.AmountCents(call.Args)
				}
				if tool.MaxAmountCents > 0 {
					payload["max_amount_cents"] = tool.MaxAmountCents
				}
				if tool.BackupID != "" {
					payload["backup_id"] = tool.BackupID
				}
				if tool.DuplicateWindowSeconds > 0 {
					payload["duplicate_window_seconds"] = tool.DuplicateWindowSeconds
				}

				status, check, err := lab.post(ctx, "/v1/action/check", payload, sceneKey)
				if err != nil {
					return tr, fmt.Errorf("action check: %w", err)
				}
				ev := ActionEvent{
					Episode:     epIdx + 1,
					Turn:        turn,
					Tool:        tool.Name,
					Args:        call.Args,
					CheckStatus: status,
					Action:      check.Action,
					Signals:     check.Signals,
					Reason:      check.Reason,
				}

				switch {
				case status == http.StatusOK && check.Action == "duplicate":
					// Committed replay: hand the recorded outcome to the model,
					// never re-execute.
					var replay map[string]any
					_ = json.Unmarshal(check.Replay, &replay)
					p.ToolResult(call, map[string]any{"replayed": true, "recorded_outcome": replay})
				case status == http.StatusConflict:
					p.ToolResult(call, map[string]any{
						"error":   "in_flight",
						"message": "an identical action is already in flight; retry shortly",
					})
					backoff = lab.inFlightBackoff
				case status == http.StatusOK && (check.Action == "allow" || check.Action == "warn"):
					tr.Executions[tool.Name]++
					result, resultClass := tool.Execute(call.Args, tr.Executions[tool.Name])
					ev.Executed = true
					ev.ResultClass = resultClass

					resultPayload := map[string]any{
						"project":      labProject,
						"session_id":   callSession,
						"step_id":      payload["step_id"],
						"action_name":  tool.Name,
						"action_risk":  tool.Risk,
						"args":         call.Args,
						"result":       result,
						"result_class": resultClass,
						"agent_id":     "agentlab-gemini",
					}
					if k, ok := payload["idempotency_key"]; ok {
						resultPayload["idempotency_key"] = k
					}
					if v, ok := payload["amount_cents"]; ok {
						resultPayload["amount_cents"] = v
					}
					if tool.DuplicateWindowSeconds > 0 {
						resultPayload["duplicate_window_seconds"] = tool.DuplicateWindowSeconds
					}
					if check.ClaimNonce != "" {
						resultPayload["claim_nonce"] = check.ClaimNonce
					}
					if _, _, err := lab.post(ctx, "/v1/action/result", resultPayload, sceneKey); err != nil {
						return tr, fmt.Errorf("action result: %w", err)
					}
					p.ToolResult(call, result)
				default: // blocked (429 policy/loop, 422 tamper)
					p.ToolResult(call, map[string]any{
						"error":  "blocked_by_hubbleops",
						"reason": check.Reason,
					})
				}
				tr.Events = append(tr.Events, ev)
			}
			if backoff > 0 {
				tr.Notes = append(tr.Notes, fmt.Sprintf("episode %d turn %d: agent backed off %s after in-flight signal", epIdx+1, turn, backoff))
				time.Sleep(backoff)
			}
		}
	}
	return tr, nil
}

func slug(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+32)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// post sends one authenticated JSON request to the embedded HubbleOps.
func (l *hubbleopsLab) post(ctx context.Context, path string, payload map[string]any, apiKey string) (int, checkResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, checkResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, checkResponse{}, err
	}
	if apiKey == "" {
		apiKey = l.apiKey
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-HubbleOps-API-Key", apiKey)
	resp, err := l.client.Do(req)
	if err != nil {
		return 0, checkResponse{}, err
	}
	defer resp.Body.Close()
	var parsed checkResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return resp.StatusCode, checkResponse{}, fmt.Errorf("decode %s response: %w", path, err)
	}
	return resp.StatusCode, parsed, nil
}
