// Command loopreplay replays JSONL observations through the loop detector.
//
// Each line is a loop.Observation-like JSON object. Add label and
// expected_action to turn the file into an assertion corpus:
//
//	{"project":"p","session_id":"s","tool_name":"search","args":{"q":"x"},
//	 "result":{"error":"not_found"},"label":"true_runaway","expected_action":"block"}
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/witness-proxy/witness-proxy/internal/loop"
)

type observation struct {
	Project        string  `json:"project"`
	SessionID      string  `json:"session_id"`
	StepID         string  `json:"step_id"`
	DecisionStage  string  `json:"decision_stage"`
	ToolName       string  `json:"tool_name"`
	Args           any     `json:"args"`
	Result         any     `json:"result"`
	ResultClass    string  `json:"result_class"`
	StateDeltaHash string  `json:"state_delta_hash"`
	PromptTokens   int     `json:"prompt_tokens"`
	OutputTokens   int     `json:"output_tokens"`
	CostUSD        float64 `json:"cost_usd"`
	UnixMillis     int64   `json:"unix_millis"`
	Label          string  `json:"label"`
	ExpectedAction string  `json:"expected_action"`
}

type sessionKey struct {
	project string
	session string
}

func main() {
	batchMax := flag.Float64("batch-max-confidence", 0.30, "max confidence for label=legit_batch")
	runawayMin := flag.Float64("runaway-min-confidence", 0.70, "min confidence for label=true_runaway")
	assertMode := flag.Bool("assert", false, "exit non-zero if corpus assertions fail")
	flag.Parse()

	groups := make(map[sessionKey][]observation)
	labels := make(map[sessionKey]string)
	expected := make(map[sessionKey]string)
	var order []sessionKey

	if flag.NArg() == 0 {
		readObservations(os.Stdin, "stdin", groups, &order, labels, expected)
	} else {
		for _, path := range flag.Args() {
			f, err := os.Open(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "open %s: %v\n", path, err)
				os.Exit(1)
			}
			readObservations(f, path, groups, &order, labels, expected)
			f.Close()
		}
	}

	if len(groups) == 0 {
		fmt.Fprintln(os.Stderr, "no observations found")
		os.Exit(1)
	}

	cfg := loop.DefaultConfig()
	failures := 0

	for _, key := range order {
		observations := groups[key]
		state := loop.NewState()
		var lastDecision loop.Decision

		for _, obs := range observations {
			loopObs := loop.Observation{
				Project:        obs.Project,
				SessionID:      obs.SessionID,
				StepID:         obs.StepID,
				DecisionStage:  obs.DecisionStage,
				ToolName:       obs.ToolName,
				Args:           obs.Args,
				Result:         obs.Result,
				ResultClass:    obs.ResultClass,
				StateDeltaHash: obs.StateDeltaHash,
				PromptTokens:   obs.PromptTokens,
				OutputTokens:   obs.OutputTokens,
				CostUSD:        obs.CostUSD,
				UnixMillis:     obs.UnixMillis,
			}
			state, lastDecision = loop.Observe(state, loopObs, cfg)
		}

		got := actionName(lastDecision.ActionCeiling)
		fmt.Printf("session=%s/%s  label=%s  expected=%s  got=%s  turns=%d  signals=[%s]  confidence=%.2f  reason=%q\n",
			key.project, key.session,
			labels[key],
			expected[key],
			got,
			len(observations),
			strings.Join(lastDecision.SignalsFired, ","),
			lastDecision.Confidence,
			lastDecision.Reason,
		)

		if !*assertMode {
			continue
		}
		want := expected[key]
		if want == "" {
			want = legacyExpectedAction(key.session)
		}
		if want != "" && got != want {
			fmt.Fprintf(os.Stderr, "FAIL: session %s/%s action %s != expected %s (confidence %.2f signals=%v)\n",
				key.project, key.session, got, want, lastDecision.Confidence, lastDecision.SignalsFired)
			failures++
		}
		if labels[key] == "legit_batch" && lastDecision.Confidence > *batchMax {
			fmt.Fprintf(os.Stderr, "FAIL: legit_batch %s/%s confidence %.2f > max %.2f\n",
				key.project, key.session, lastDecision.Confidence, *batchMax)
			failures++
		}
		if labels[key] == "true_runaway" && lastDecision.Confidence < *runawayMin {
			fmt.Fprintf(os.Stderr, "FAIL: true_runaway %s/%s confidence %.2f < min %.2f\n",
				key.project, key.session, lastDecision.Confidence, *runawayMin)
			failures++
		}
	}

	if *assertMode && failures > 0 {
		fmt.Fprintf(os.Stderr, "\n%d assertion(s) failed\n", failures)
		os.Exit(1)
	}
}

func readObservations(r io.Reader, name string, groups map[sessionKey][]observation, order *[]sessionKey, labels, expected map[sessionKey]string) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		var obs observation
		if err := json.Unmarshal([]byte(line), &obs); err != nil {
			fmt.Fprintf(os.Stderr, "%s line %d: %v\n", name, lineNo, err)
			os.Exit(1)
		}
		key := sessionKey{obs.Project, obs.SessionID}
		if _, seen := groups[key]; !seen {
			*order = append(*order, key)
		}
		groups[key] = append(groups[key], obs)
		if obs.Label != "" {
			labels[key] = obs.Label
		}
		if obs.ExpectedAction != "" {
			expected[key] = obs.ExpectedAction
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", name, err)
		os.Exit(1)
	}
}

func actionName(a loop.Action) string {
	switch a {
	case loop.ActionBlock:
		return "block"
	case loop.ActionWarn:
		return "warn"
	default:
		return "allow"
	}
}

func legacyExpectedAction(sessionID string) string {
	sid := strings.ToLower(sessionID)
	if strings.Contains(sid, "batch") {
		return "allow"
	}
	if strings.Contains(sid, "runaway") {
		return "block"
	}
	return ""
}
