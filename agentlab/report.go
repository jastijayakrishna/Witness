package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/hubbleops/hubbleops/internal/receiptverify"
	"github.com/hubbleops/hubbleops/internal/shadowreport"
)

// SceneOutcome is one row of the final scoreboard.
type SceneOutcome struct {
	Scene      Scene
	Transcript *Transcript
	Achieved   string
	Detail     []string
	Skipped    string // non-empty = scene skipped (e.g. Gemini quota), with reason
}

func verifyLabWAL(lab *hubbleopsLab) (receiptverify.Report, error) {
	paths, err := filepath.Glob(filepath.Join(lab.walDir, "*.jsonl"))
	if err != nil {
		return receiptverify.Report{}, err
	}
	var records []shadowreport.WALRecord
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return receiptverify.Report{}, err
		}
		recs, readErr := shadowreport.ReadJSONL(f)
		f.Close()
		if readErr != nil {
			return receiptverify.Report{}, readErr
		}
		records = append(records, recs...)
	}
	return receiptverify.Verify(records), nil
}

func printTranscript(tr *Transcript) {
	for _, ev := range tr.Events {
		status := fmt.Sprintf("%d %s", ev.CheckStatus, ev.Action)
		mark := "·"
		switch {
		case ev.CheckStatus == http.StatusTooManyRequests, ev.CheckStatus == http.StatusUnprocessableEntity:
			mark = "✗ BLOCKED"
		case ev.CheckStatus == http.StatusConflict:
			mark = "⏸ HELD"
		case ev.Action == "duplicate":
			mark = "↩ REPLAYED"
		case ev.Action == "warn":
			mark = "⚠ WARNED"
		case ev.Executed:
			mark = "→ executed"
		}
		fmt.Printf("    ep%d t%-2d %-20s %-14s %s", ev.Episode, ev.Turn, ev.Tool, status, mark)
		if ev.Executed {
			fmt.Printf(" (%s)", ev.ResultClass)
		}
		if !ev.Executed && ev.Reason != "" {
			fmt.Printf("  %s", clip(ev.Reason, 70))
		}
		fmt.Println()
	}
	for _, n := range tr.Notes {
		fmt.Printf("    note: %s\n", n)
	}
}

func printScoreboard(outcomes []SceneOutcome, lab *hubbleopsLab, liveModel string) int {
	fmt.Println()
	fmt.Println("================== AGENTLAB SCOREBOARD ==================")
	if liveModel != "" {
		fmt.Printf("agent brain: live %s (model-chosen calls)\n", liveModel)
	} else {
		fmt.Println("agent brain: scripted fake planner (offline mode)")
	}
	fmt.Printf("hubbleops: real handler + auth + Lua ledger, enforce mode, lease=%s\n\n", labLease)

	mismatches := 0
	caught, missed, partial, clean := 0, 0, 0, 0
	for _, o := range outcomes {
		statusMark := "OK"
		if o.Skipped != "" {
			fmt.Printf("[SKIPPED] %-45s %s\n", o.Scene.Name, o.Skipped)
			continue
		}
		if o.Achieved != o.Scene.Expect {
			statusMark = "UNEXPECTED"
			mismatches++
		}
		switch o.Achieved {
		case VerdictCaught:
			caught++
		case VerdictMissed:
			missed++
		case VerdictPartial:
			partial++
		case VerdictClean:
			clean++
		}
		fmt.Printf("[%s] %-45s expected=%s achieved=%s\n", statusMark, o.Scene.Name, o.Scene.Expect, o.Achieved)
		for _, d := range o.Detail {
			fmt.Printf("         %s\n", d)
		}
	}

	fmt.Println()
	fmt.Printf("best case : %d/3 clean (false positives: %s)\n", clean, map[bool]string{true: "none", false: "SEE ABOVE"}[clean == 3])
	fmt.Printf("worst case: %d caught, %d partial, %d missed\n", caught, partial, missed)
	if missed > 0 || partial > 0 {
		fmt.Println("remaining known gaps (honest list):")
		fmt.Println("  - unkeyed duplicates (W6): warn-only until soft resource+args dedup ships")
		fmt.Println("  - read-tier session rotation: not velocity-limited (cost leak only, no side effects)")
	}

	report, err := verifyLabWAL(lab)
	if err != nil {
		fmt.Printf("\nreceipt verification: ERROR %v\n", err)
		mismatches++
	} else {
		fmt.Printf("\nreceipt verification: records=%d verified=%t hash_mismatches=%d chain_broken_at=%d\n",
			report.TotalRecords, report.Verified, report.HashMismatches, report.ChainBrokenAt)
		if !report.Verified {
			mismatches++
		}
	}
	fmt.Println("=========================================================")
	return mismatches
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
