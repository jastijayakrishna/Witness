package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hubbleops/hubbleops/internal/demopack"
	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/synthcorpus"
)

func runDemo(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "print JSON instead of the table")
	_ = fs.Parse(args)

	missed, err := renderDemoReport(os.Stdout, *jsonOut)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if missed > 0 {
		fmt.Fprintf(os.Stderr, "%d incident(s) NOT blocked — the detector has a gap\n", missed)
		os.Exit(1)
	}
}

// renderDemoReport replays the famous eight through the real in-memory pipeline
// and writes the report. Dollar figures are computed from the replayed streams'
// cost_usd — nothing is hardcoded. Returns how many incidents failed to block.
func renderDemoReport(w io.Writer, jsonOut bool) (int, error) {
	incidents, err := demopack.Incidents()
	if err != nil {
		return 0, fmt.Errorf("load demo pack: %w", err)
	}
	start := time.Now()
	type row struct {
		Incident string                    `json:"incident"`
		Result   synthcorpus.SessionResult `json:"result"`
	}
	var rows []row
	missed := 0
	totalEvents := 0
	for _, inc := range incidents {
		res, err := synthcorpus.ReplaySession(context.Background(), inc.Events, loop.DefaultConfig(), loop.NewMemoryActionStore())
		if err != nil {
			return 0, fmt.Errorf("replay %s: %w", inc.Label, err)
		}
		if res.Verdict != "block" {
			missed++
		}
		totalEvents += res.Events
		rows = append(rows, row{Incident: inc.SourceIncident, Result: res})
	}
	elapsed := time.Since(start)

	if jsonOut {
		return missed, json.NewEncoder(w).Encode(rows)
	}

	fmt.Fprintln(w, "HUBBLEOPS DEMO — famous incidents replayed through the real pipeline (synthetic replays)")
	fmt.Fprintln(w)
	for _, r := range rows {
		res := r.Result
		verdict := "MISSED"
		if res.Verdict == "block" {
			verdict = fmt.Sprintf("BLOCKED at event %d", res.FirstBlock)
		}
		fmt.Fprintf(w, "  %s\n", r.Incident)
		fmt.Fprintf(w, "    %s — signals: %s\n", verdict, joinOrNone(res.Signals))
		fmt.Fprintf(w, "    stream: %d events, $%.2f; saved by blocking: $%.2f\n\n",
			res.Events, res.TotalCostUSD, res.SavedCostUSD)
	}
	fmt.Fprintf(w, "Replayed %d events in %s through detector %s + %s. Synthetic corpus — not customer traffic.\n",
		totalEvents, elapsed.Round(time.Millisecond), loop.DetectorVersion, loop.ActionPolicyVersion)
	return missed, nil
}

func joinOrNone(signals []string) string {
	if len(signals) == 0 {
		return "(none)"
	}
	out := signals[0]
	for _, s := range signals[1:] {
		out += ", " + s
	}
	return out
}
