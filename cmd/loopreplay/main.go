// Command loopreplay replays a JSONL file of Observations through the loop detector.
//
// Usage:
//
//	loopreplay [--batch-max-confidence 0.30] [--runaway-min-confidence 0.70] [file.jsonl]
//
// Reads from stdin if no file argument is given. Each line must be a JSON object with:
//
//	{
//	  "session_id": "s1",
//	  "project": "p1",
//	  "tool_name": "bash",
//	  "args": {"cmd": "ls"},
//	  "result": {"output": "file.go"},
//	  "prompt_tokens": 1000,
//	  "output_tokens": 50,
//	  "cost_usd": 0.01,
//	  "unix_millis": 1700000000000
//	}
//
// Groups observations by (project, session_id), feeds each group through the
// detector in order, and prints the final verdict per session.
//
// With --assert, exits non-zero if any session labeled "batch" exceeds
// --batch-max-confidence or any session labeled "runaway" falls below
// --runaway-min-confidence. Label by putting "batch" or "runaway" in
// the session_id.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/witness-proxy/witness-proxy/internal/loop"
)

type observation struct {
	Project      string `json:"project"`
	SessionID    string `json:"session_id"`
	ToolName     string `json:"tool_name"`
	Args         any    `json:"args"`
	Result       any    `json:"result"`
	PromptTokens int    `json:"prompt_tokens"`
	OutputTokens int    `json:"output_tokens"`
	CostUSD      float64 `json:"cost_usd"`
	UnixMillis   int64  `json:"unix_millis"`
}

func main() {
	batchMax := flag.Float64("batch-max-confidence", 0.30, "max confidence for sessions containing 'batch' in session_id")
	runawayMin := flag.Float64("runaway-min-confidence", 0.70, "min confidence for sessions containing 'runaway' in session_id")
	assertMode := flag.Bool("assert", false, "exit non-zero if corpus assertions fail")
	flag.Parse()

	// Open input
	var scanner *bufio.Scanner
	if flag.NArg() > 0 {
		f, err := os.Open(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "open: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		scanner = bufio.NewScanner(f)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	// Parse all observations, group by (project, session_id)
	type sessionKey struct{ project, session string }
	groups := make(map[sessionKey][]observation)
	var order []sessionKey

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		var obs observation
		if err := json.Unmarshal([]byte(line), &obs); err != nil {
			fmt.Fprintf(os.Stderr, "line %d: %v\n", lineNo, err)
			os.Exit(1)
		}
		key := sessionKey{obs.Project, obs.SessionID}
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], obs)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "read: %v\n", err)
		os.Exit(1)
	}

	if len(groups) == 0 {
		fmt.Fprintln(os.Stderr, "no observations found")
		os.Exit(1)
	}

	cfg := loop.DefaultConfig()
	failures := 0

	for _, key := range order {
		observations := groups[key]
		state := loop.State{}
		var lastDecision loop.Decision

		for _, obs := range observations {
			loopObs := loop.Observation{
				Project:      obs.Project,
				SessionID:    obs.SessionID,
				ToolName:     obs.ToolName,
				Args:         obs.Args,
				Result:       obs.Result,
				PromptTokens: obs.PromptTokens,
				OutputTokens: obs.OutputTokens,
				CostUSD:      obs.CostUSD,
				UnixMillis:   obs.UnixMillis,
			}
			state, lastDecision = loop.Observe(state, loopObs, cfg)
		}

		fmt.Printf("session=%s/%s  turns=%d  signals=[%s]  confidence=%.2f  ceiling=%s  reason=%q\n",
			key.project, key.session,
			len(observations),
			strings.Join(lastDecision.SignalsFired, ","),
			lastDecision.Confidence,
			lastDecision.ActionCeiling,
			lastDecision.Reason,
		)

		// Assertions
		if *assertMode {
			sid := strings.ToLower(key.session)
			if strings.Contains(sid, "batch") && lastDecision.Confidence > *batchMax {
				fmt.Fprintf(os.Stderr, "FAIL: batch session %s/%s confidence %.2f > max %.2f\n",
					key.project, key.session, lastDecision.Confidence, *batchMax)
				failures++
			}
			if strings.Contains(sid, "runaway") && lastDecision.Confidence < *runawayMin {
				fmt.Fprintf(os.Stderr, "FAIL: runaway session %s/%s confidence %.2f < min %.2f\n",
					key.project, key.session, lastDecision.Confidence, *runawayMin)
				failures++
			}
		}
	}

	if *assertMode && failures > 0 {
		fmt.Fprintf(os.Stderr, "\n%d assertion(s) failed\n", failures)
		os.Exit(1)
	}
}
