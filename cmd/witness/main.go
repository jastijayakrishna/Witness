package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/witness-proxy/witness-proxy/internal/doctor"
	"github.com/witness-proxy/witness-proxy/internal/loop"
	"github.com/witness-proxy/witness-proxy/internal/loopeval"
	"github.com/witness-proxy/witness-proxy/internal/providerdoctor"
	"github.com/witness-proxy/witness-proxy/internal/receiptverify"
	"github.com/witness-proxy/witness-proxy/internal/shadowreport"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "doctor":
		runDoctor(os.Args[2:])
	case "provider-doctor":
		runProviderDoctor(os.Args[2:])
	case "eval":
		runEval(os.Args[2:])
	case "shadow-report":
		runShadowReport(os.Args[2:])
	case "verify-receipts":
		runVerifyReceipts(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func runDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	baseURL := fs.String("base-url", envOrDefault([]string{"WITNESS_BASE_URL", "WITNESS_URL"}, "http://localhost:8080"), "Witness base URL")
	project := fs.String("project", envOrDefault([]string{"WITNESS_PROJECT", "WITNESS_PROJECT_KEY"}, "witness-doctor"), "Witness project")
	apiKey := fs.String("api-key", envOrDefault([]string{"WITNESS_API_KEY", "WITNESS_PROJECT_KEY"}, ""), "Witness API key")
	timeout := fs.Duration("timeout", 2*time.Second, "per-check timeout")
	jsonOut := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 3*(*timeout))
	defer cancel()

	report := doctor.Run(ctx, doctor.Config{
		BaseURL: *baseURL,
		Project: *project,
		APIKey:  *apiKey,
		Timeout: *timeout,
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		fmt.Printf("Witness doctor\n")
		fmt.Printf("base_url: %s\n", report.BaseURL)
		for _, check := range report.Checks {
			status := "ok"
			if !check.OK {
				status = "fail"
			}
			if check.Detail != "" {
				fmt.Printf("[%s] %s: %s\n", status, check.Name, check.Detail)
			} else {
				fmt.Printf("[%s] %s\n", status, check.Name)
			}
		}
	}

	if !report.OK() {
		os.Exit(1)
	}
}

func runProviderDoctor(args []string) {
	loadDotEnv(".env")

	fs := flag.NewFlagSet("provider-doctor", flag.ExitOnError)
	provider := fs.String("provider", "gemini", "provider to test")
	model := fs.String("model", envOrDefault([]string{"WITNESS_LIVE_GEMINI_MODEL", "GEMINI_MODEL"}, "gemini-2.5-flash-lite"), "provider model to test")
	apiKey := fs.String("api-key", envOrDefault([]string{"GOOGLE_API_KEY", "GEMINI_API_KEY"}, ""), "provider API key")
	baseURL := fs.String("base-url", envOrDefault([]string{"GEMINI_BASE_URL"}, "https://generativelanguage.googleapis.com"), "provider base URL")
	timeout := fs.Duration("timeout", 10*time.Second, "per-check timeout")
	jsonOut := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)

	if *provider != "gemini" {
		fmt.Fprintf(os.Stderr, "unsupported provider %q; currently supported: gemini\n", *provider)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*(*timeout))
	defer cancel()

	report := providerdoctor.RunGemini(ctx, providerdoctor.Config{
		APIKey:  *apiKey,
		Model:   *model,
		BaseURL: *baseURL,
		Timeout: *timeout,
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		fmt.Printf("Witness provider doctor\n")
		fmt.Printf("provider: %s\n", report.Provider)
		fmt.Printf("model: %s\n", report.Model)
		fmt.Printf("base_url: %s\n", report.BaseURL)
		for _, check := range report.Checks {
			status := "ok"
			if !check.OK {
				status = "fail"
			}
			if check.Detail != "" {
				fmt.Printf("[%s] %s: %s\n", status, check.Name, check.Detail)
			} else {
				fmt.Printf("[%s] %s\n", status, check.Name)
			}
		}
	}

	if !report.OK() {
		os.Exit(1)
	}
}

func runShadowReport(args []string) {
	fs := flag.NewFlagSet("shadow-report", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)

	records, err := readShadowRecords(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	report := shadowreport.Build(records)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	}

	fmt.Printf("Witness shadow report\n")
	fmt.Printf("records=%d tool_events=%d action_receipts=%d\n", report.TotalRecords, report.ToolEvents, report.ActionReceipts)
	fmt.Printf("would_block=%d blocked=%d duplicate_side_effects=%d no_progress_events=%d\n",
		report.WouldBlock, report.Blocked, report.DuplicateSideEffects, report.NoProgressEvents)
	fmt.Printf("estimated_wasted_cost_usd=%.6f\n", report.EstimatedWastedCostUSD)
	if report.RecommendedFirstPolicy != "" {
		fmt.Printf("recommended_first_policy=%s\n", report.RecommendedFirstPolicy)
	}
	printCounts("top_tools", report.TopTools)
	printCounts("top_result_classes", report.TopResultClasses)
	if len(report.FalsePositiveReviewSet) > 0 {
		fmt.Printf("false_positive_review_set=%d\n", len(report.FalsePositiveReviewSet))
		for _, item := range report.FalsePositiveReviewSet {
			fmt.Printf("- decision_id=%s project=%s session=%s tool=%s action=%s result=%s reason=%s\n",
				item.DecisionID, item.Project, item.SessionID, item.ToolName, item.LoopAction, item.ResultClass, item.Reason)
		}
	}
}

func runVerifyReceipts(args []string) {
	fs := flag.NewFlagSet("verify-receipts", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "print JSON")
	receiptSecret := fs.String("receipt-secret", os.Getenv("WITNESS_RECEIPT_SIGNING_SECRET"), "receipt signing secret; defaults to WITNESS_RECEIPT_SIGNING_SECRET")
	requireSignatures := fs.Bool("require-signatures", false, "fail verification if any action receipt is unsigned")
	_ = fs.Parse(args)
	if *requireSignatures && *receiptSecret == "" {
		fmt.Fprintln(os.Stderr, "-require-signatures needs -receipt-secret or WITNESS_RECEIPT_SIGNING_SECRET")
		os.Exit(1)
	}

	records, err := readShadowRecords(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	report := receiptverify.VerifyWithOptions(records, receiptverify.Options{
		ReceiptSecret:     *receiptSecret,
		RequireSignatures: *requireSignatures,
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		fmt.Printf("Witness receipt verify\n")
		fmt.Printf("records=%d action_receipts=%d signed_receipts=%d unsigned_receipts=%d verified=%t\n",
			report.TotalRecords, report.ActionReceipts, report.SignedReceipts, report.UnsignedReceipts, report.Verified)
		fmt.Printf("missing_hashes=%d hash_mismatches=%d signature_mismatches=%d chain_broken_at=%d receipt_field_gaps=%d\n",
			report.MissingHashes, report.HashMismatches, report.SignatureMismatches, report.ChainBrokenAt, report.ReceiptFieldGaps)
		if report.LastRecordHash != "" {
			fmt.Printf("last_record_hash=%s\n", report.LastRecordHash)
		}
		if report.FirstGapDecisionID != "" {
			fmt.Printf("first_gap_decision_id=%s\n", report.FirstGapDecisionID)
		}
		if report.FirstSignatureMismatchDecisionID != "" {
			fmt.Printf("first_signature_mismatch_decision_id=%s\n", report.FirstSignatureMismatchDecisionID)
		}
		if report.Recommendation != "" {
			fmt.Printf("recommendation=%s\n", report.Recommendation)
		}
	}

	if !report.Verified {
		os.Exit(1)
	}
}

func runEval(args []string) {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "print JSON")
	assertMode := fs.Bool("assert", false, "exit non-zero if quality gates fail")
	anonymizeOut := fs.String("anonymize-out", "", "write privacy-safe JSONL copy")
	salt := fs.String("salt", os.Getenv("WITNESS_ANON_SALT"), "salt for anonymized IDs")
	maxFP := fs.Float64("max-fp-block-rate", 0, "maximum false positive block rate")
	maxMiss := fs.Float64("max-missed-runaway-rate", 0, "maximum missed runaway rate")
	minRecall := fs.Float64("min-runaway-recall", 1, "minimum runaway recall")
	minPrecision := fs.Float64("min-block-precision", 1, "minimum block precision")
	maxP95 := fs.Float64("max-p95-ms", 25, "maximum replay p95 decision latency in ms")
	_ = fs.Parse(args)

	events, err := readEvalEvents(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(events) == 0 {
		fmt.Fprintln(os.Stderr, "no trace events found")
		os.Exit(1)
	}

	if *anonymizeOut != "" {
		if *salt == "" {
			fmt.Fprintln(os.Stderr, "-salt or WITNESS_ANON_SALT is required with -anonymize-out")
			os.Exit(1)
		}
		f, err := os.Create(*anonymizeOut)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create anonymized output: %v\n", err)
			os.Exit(1)
		}
		if err := loopeval.WriteJSONL(f, loopeval.Anonymize(events, *salt)); err != nil {
			_ = f.Close()
			fmt.Fprintf(os.Stderr, "write anonymized output: %v\n", err)
			os.Exit(1)
		}
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close anonymized output: %v\n", err)
			os.Exit(1)
		}
	}

	report := loopeval.Evaluate(events, loop.DefaultConfig(), loopeval.GateConfig{
		MaxFalsePositiveBlockRate: *maxFP,
		MaxMissedRunawayRate:      *maxMiss,
		MinRunawayRecall:          *minRecall,
		MinBlockPrecision:         *minPrecision,
		MaxP95DecisionMs:          *maxP95,
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		fmt.Printf("Witness loop eval\n")
		fmt.Printf("traces=%d events=%d runaways=%d legit=%d\n", report.TotalTraces, report.TotalEvents, report.RunawayTraces, report.LegitTraces)
		fmt.Printf("recall=%.4f precision=%.4f fp_block_rate=%.4f missed_runaway_rate=%.4f\n",
			report.RunawayRecall, report.BlockPrecision, report.FalsePositiveBlockRate, report.MissedRunawayRate)
		fmt.Printf("cost_total_usd=%.4f saved_cost_usd=%.4f replay_p95_decision_ms=%.4f\n",
			report.TotalCostUSD, report.SavedCostUSD, report.ReplayP95DecisionLatencyMs)
		for _, failure := range report.GateFailures {
			fmt.Printf("[fail] %s\n", failure)
		}
	}

	if *assertMode && len(report.GateFailures) > 0 {
		os.Exit(1)
	}
}

func readEvalEvents(paths []string) ([]loopeval.Event, error) {
	if len(paths) == 0 {
		return loopeval.ReadJSONL(os.Stdin, "stdin")
	}
	var out []loopeval.Event
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		events, readErr := loopeval.ReadJSONL(f, path)
		closeErr := f.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", path, closeErr)
		}
		out = append(out, events...)
	}
	return out, nil
}

func readShadowRecords(paths []string) ([]walRecord, error) {
	if len(paths) == 0 {
		records, err := shadowreport.ReadJSONL(os.Stdin)
		return records, err
	}
	var out []walRecord
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		records, readErr := shadowreport.ReadJSONL(f)
		closeErr := f.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", path, closeErr)
		}
		out = append(out, records...)
	}
	return out, nil
}

type walRecord = shadowreport.WALRecord

func printCounts(label string, counts []shadowreport.Count) {
	if len(counts) == 0 {
		return
	}
	fmt.Printf("%s:\n", label)
	for _, count := range counts {
		fmt.Printf("- %s=%d\n", count.Name, count.Count)
	}
}

func envOrDefault(names []string, fallback string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return fallback
}

func loadDotEnv(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		name := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		if name != "" && value != "" && os.Getenv(name) == "" {
			_ = os.Setenv(name, value)
		}
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: witness doctor|provider-doctor|eval|shadow-report|verify-receipts [flags]")
}
