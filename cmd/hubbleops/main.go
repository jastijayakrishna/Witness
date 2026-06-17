package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/hubbleops/hubbleops/internal/config"
	"github.com/hubbleops/hubbleops/internal/doctor"
	"github.com/hubbleops/hubbleops/internal/evidencepack"
	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/loopeval"
	"github.com/hubbleops/hubbleops/internal/outcomeexport"
	"github.com/hubbleops/hubbleops/internal/receiptverify"
	"github.com/hubbleops/hubbleops/internal/shadowreport"
	"github.com/hubbleops/hubbleops/internal/storage"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "demo":
		runDemo(os.Args[2:])
	case "doctor":
		runDoctor(os.Args[2:])
	case "eval":
		runEval(os.Args[2:])
	case "shadow-report":
		runShadowReport(os.Args[2:])
	case "evidence-pack":
		runEvidencePack(os.Args[2:])
	case "verify-receipts":
		runVerifyReceipts(os.Args[2:])
	case "review-decision":
		runReviewDecision(os.Args[2:])
	case "export-outcomes":
		runExportOutcomes(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

type reviewDecisionConfig struct {
	BaseURL    string
	Project    string
	APIKey     string
	DecisionID string
	Label      string
	Role       string
	Notes      string
	Timeout    time.Duration
}

type reviewDecisionResult struct {
	DecisionID             string    `json:"decision_id"`
	Label                  string    `json:"label"`
	ReviewerSource         string    `json:"reviewer_source"`
	ReviewerRole           string    `json:"reviewer_role"`
	NotesFingerprint       string    `json:"notes_fingerprint,omitempty"`
	NotesStoredRaw         bool      `json:"notes_stored_raw"`
	RepeatedReviewBehavior string    `json:"repeated_review_behavior"`
	ReviewedAt             time.Time `json:"reviewed_at"`
}

func runReviewDecision(args []string) {
	fs := flag.NewFlagSet("review-decision", flag.ExitOnError)
	baseURL := fs.String("base-url", envOrDefault([]string{"HUBBLEOPS_BASE_URL", "HUBBLEOPS_URL"}, "http://localhost:8080"), "HubbleOps base URL")
	project := fs.String("project", envOrDefault([]string{"HUBBLEOPS_PROJECT", "HUBBLEOPS_PROJECT_KEY"}, ""), "HubbleOps project")
	apiKey := fs.String("api-key", envOrDefault([]string{"HUBBLEOPS_API_KEY", "HUBBLEOPS_PROJECT_KEY"}, ""), "HubbleOps API key")
	decisionID := fs.String("decision", "", "decision id to review")
	label := fs.String("label", "", "review label")
	role := fs.String("role", "unknown", "reviewer role: developer, sre, security, founder, unknown")
	notes := fs.String("notes", "", "optional notes; stored as a fingerprint by default")
	timeout := fs.Duration("timeout", 3*time.Second, "request timeout")
	jsonOut := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, err := submitDecisionReview(ctx, reviewDecisionConfig{
		BaseURL:    *baseURL,
		Project:    *project,
		APIKey:     *apiKey,
		DecisionID: *decisionID,
		Label:      *label,
		Role:       *role,
		Notes:      *notes,
		Timeout:    *timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "review-decision failed: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(result)
		return
	}
	fmt.Printf("HubbleOps decision review\n")
	fmt.Printf("decision_id=%s label=%s role=%s source=%s\n", result.DecisionID, result.Label, result.ReviewerRole, result.ReviewerSource)
	if result.NotesFingerprint != "" {
		fmt.Printf("notes_fingerprint=%s\n", result.NotesFingerprint)
	}
	fmt.Printf("repeated_review_behavior=%s\n", result.RepeatedReviewBehavior)
}

func submitDecisionReview(ctx context.Context, cfg reviewDecisionConfig) (reviewDecisionResult, error) {
	var result reviewDecisionResult
	if strings.TrimSpace(cfg.DecisionID) == "" {
		return result, fmt.Errorf("-decision is required")
	}
	if strings.TrimSpace(cfg.Label) == "" {
		return result, fmt.Errorf("-label is required")
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	if base == "" {
		return result, fmt.Errorf("-base-url is required")
	}
	body, err := json.Marshal(map[string]string{
		"label":         strings.TrimSpace(cfg.Label),
		"reviewer_role": strings.TrimSpace(cfg.Role),
		"notes":         cfg.Notes,
	})
	if err != nil {
		return result, fmt.Errorf("encode review: %w", err)
	}
	endpoint := base + "/v1/decisions/" + url.PathEscape(strings.TrimSpace(cfg.DecisionID)) + "/review"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return result, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.Project != "" {
		req.Header.Set("X-Project", cfg.Project)
	}
	if cfg.APIKey != "" {
		req.Header.Set("X-HubbleOps-API-Key", cfg.APIKey)
	}
	client := &http.Client{Timeout: cfg.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return result, fmt.Errorf("post review: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return result, fmt.Errorf("HubbleOps returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return result, fmt.Errorf("parse review response: %w", err)
	}
	return result, nil
}

func runExportOutcomes(args []string) {
	fs := flag.NewFlagSet("export-outcomes", flag.ExitOnError)
	project := fs.String("project", envOrDefault([]string{"HUBBLEOPS_PROJECT"}, ""), "project to export")
	sinceRaw := fs.String("since", "", "inclusive UTC day, e.g. 2026-01-01")
	outPath := fs.String("out", "", "output JSONL path")
	anonymize := fs.Bool("anonymize", true, "required; non-anonymized export is not supported")
	saltEnv := fs.String("salt-env", "HUBBLEOPS_ANON_SALT", "environment variable containing anonymization salt")
	includeCostExact := fs.Bool("include-cost-exact", false, "include exact estimated_cost_usd; default exports buckets only")
	reviewedOnly := fs.Bool("reviewed-only", false, "exclude decisions without a customer review label")
	configPath := fs.String("config", "configs/proxy.yaml", "HubbleOps config path")
	timeout := fs.Duration("timeout", 15*time.Second, "export timeout")
	_ = fs.Parse(args)

	if strings.TrimSpace(*project) == "" {
		fmt.Fprintln(os.Stderr, "-project is required")
		os.Exit(2)
	}
	since, err := parseExportSince(*sinceRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -since: %v\n", err)
		os.Exit(2)
	}
	if strings.TrimSpace(*outPath) == "" {
		fmt.Fprintln(os.Stderr, "-out is required")
		os.Exit(2)
	}
	if !*anonymize {
		fmt.Fprintln(os.Stderr, "non-anonymized outcome export is not supported")
		os.Exit(2)
	}
	salt := os.Getenv(strings.TrimSpace(*saltEnv))
	if strings.TrimSpace(salt) == "" {
		fmt.Fprintf(os.Stderr, "-salt-env %s is empty; set it to a customer-approved export salt\n", *saltEnv)
		os.Exit(2)
	}

	cfgPath := strings.TrimSpace(*configPath)
	if cfgPath != "" {
		if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
			cfgPath = ""
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.Postgres.DSN())
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect postgres: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	rows, err := storage.NewMoatStore(pool).ListActionDecisionOutcomesForExport(ctx, *project, since, *reviewedOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load outcomes: %v\n", err)
		os.Exit(1)
	}

	out, closeOut, err := createExportOutput(*outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create export output: %v\n", err)
		os.Exit(1)
	}
	count, writeErr := outcomeexport.WriteJSONL(out, rows, outcomeexport.Options{
		Anonymize:        *anonymize,
		Salt:             salt,
		IncludeCostExact: *includeCostExact,
		ReviewedOnly:     *reviewedOnly,
	})
	closeErr := closeOut()
	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "write export: %v\n", writeErr)
		os.Exit(1)
	}
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "close export output: %v\n", closeErr)
		os.Exit(1)
	}
	fmt.Printf("exported_outcomes=%d out=%s anonymized=true reviewed_only=%t include_cost_exact=%t\n",
		count, *outPath, *reviewedOnly, *includeCostExact)
}

func parseExportSince(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("date is required")
	}
	t, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("use YYYY-MM-DD: %w", err)
	}
	return t.UTC(), nil
}

func createExportOutput(path string) (io.Writer, func() error, error) {
	if path == "-" {
		return os.Stdout, func() error { return nil }, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

func runDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	baseURL := fs.String("base-url", envOrDefault([]string{"HUBBLEOPS_BASE_URL", "HUBBLEOPS_URL"}, "http://localhost:8080"), "HubbleOps base URL")
	project := fs.String("project", envOrDefault([]string{"HUBBLEOPS_PROJECT", "HUBBLEOPS_PROJECT_KEY"}, "hubbleops-doctor"), "HubbleOps project")
	apiKey := fs.String("api-key", envOrDefault([]string{"HUBBLEOPS_API_KEY", "HUBBLEOPS_PROJECT_KEY"}, ""), "HubbleOps API key")
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
		fmt.Printf("HubbleOps doctor\n")
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
	format := fs.String("format", "text", "output format: text, markdown, json")
	jsonOut := fs.Bool("json", false, "print JSON")
	_ = fs.Parse(args)
	if *jsonOut {
		*format = "json"
	}

	records, err := readShadowRecords(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	report := shadowreport.Build(records)

	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	case "markdown", "md":
		fmt.Print(shadowreport.Markdown(report))
		return
	case "text", "":
	default:
		fmt.Fprintf(os.Stderr, "unknown shadow-report format %q; use text, markdown, or json\n", *format)
		os.Exit(2)
	}

	fmt.Printf("HubbleOps shadow report\n")
	fmt.Printf("records=%d tool_events=%d total_action_decisions=%d\n", report.TotalRecords, report.ToolEvents, report.TotalActionDecisions)
	fmt.Printf("would_block_decisions=%d blocked=%d duplicate_side_effect_decisions=%d no_progress_decisions=%d budget_decisions=%d\n",
		report.WouldBlockDecisions, report.Blocked, report.DuplicateSideEffectDecisions, report.NoProgressDecisions, report.BudgetDecisions)
	fmt.Printf("estimated_cost_saved_usd=%.6f\n", report.EstimatedCostSavedUSD)
	fmt.Printf("unreviewed_decisions_count=%d recommended_review_sample=%d\n",
		report.UnreviewedDecisionsCount, len(report.RecommendedReviewSample))
	if report.RecommendedFirstPolicy != "" {
		fmt.Printf("recommended_first_policy=%s\n", report.RecommendedFirstPolicy)
	}
	printCounts("top_tools_by_risky_decisions", report.TopToolsByRiskyDecisions)
	printCounts("top_result_classes", report.TopResultClasses)
	if len(report.RecommendedReviewSample) > 0 {
		fmt.Printf("review_queue\n")
		for _, item := range report.RecommendedReviewSample {
			fmt.Printf("- decision_id=%s action_name=%s hubbleops_action=%s risk_class=%s result_class=%s estimated_cost_usd=%.6f estimated_risk=%s\n",
				item.DecisionID, item.ActionName, item.HubbleOpsAction, item.RiskClass, item.ResultClass, item.EstimatedCostUSD, item.EstimatedRisk)
			if item.Reason != "" {
				fmt.Printf("  reason=%s\n", item.Reason)
			}
			if item.EvidenceSummary != "" {
				fmt.Printf("  evidence_summary=%s\n", item.EvidenceSummary)
			}
			if item.ReviewCommand != "" {
				fmt.Printf("  label_command=%s\n", item.ReviewCommand)
			}
		}
	}
}

func runEvidencePack(args []string) {
	fs := flag.NewFlagSet("evidence-pack", flag.ExitOnError)
	format := fs.String("format", "markdown", "output format: markdown or json")
	sinceRaw := fs.String("since", "", "inclusive start day, YYYY-MM-DD")
	untilRaw := fs.String("until", "", "exclusive end day, YYYY-MM-DD")
	project := fs.String("project", "", "limit to a single project")
	receiptPublicKey := fs.String("receipt-public-key", os.Getenv("HUBBLEOPS_RECEIPT_PUBLIC_KEY"), "base64 Ed25519 receipt public key; verifies signatures without the signing secret")
	receiptSecret := fs.String("receipt-secret", os.Getenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET"), "receipt signing secret (operator path)")
	out := fs.String("out", "", "write the pack to this file instead of stdout")
	_ = fs.Parse(args)

	opts := evidencepack.Options{
		Project:          *project,
		ReceiptPublicKey: *receiptPublicKey,
		ReceiptSecret:    *receiptSecret,
	}
	if *sinceRaw != "" {
		since, err := parseExportSince(*sinceRaw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "since: %v\n", err)
			os.Exit(2)
		}
		opts.Since = since
	}
	if *untilRaw != "" {
		until, err := parseExportSince(*untilRaw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "until: %v\n", err)
			os.Exit(2)
		}
		// --until is given as a day; make it inclusive of that whole day.
		opts.Until = until.AddDate(0, 0, 1)
	}

	records, err := readShadowRecords(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pack := evidencepack.Build(records, opts)

	var rendered []byte
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		rendered, err = evidencepack.RenderJSON(pack)
		if err != nil {
			fmt.Fprintf(os.Stderr, "render json: %v\n", err)
			os.Exit(1)
		}
	case "markdown", "md", "":
		rendered = []byte(evidencepack.RenderMarkdown(pack))
	default:
		fmt.Fprintf(os.Stderr, "unknown evidence-pack format %q; use markdown or json\n", *format)
		os.Exit(2)
	}

	if *out == "" {
		fmt.Print(string(rendered))
	} else {
		w, closeFn, createErr := createExportOutput(*out)
		if createErr != nil {
			fmt.Fprintf(os.Stderr, "open %s: %v\n", *out, createErr)
			os.Exit(1)
		}
		if _, writeErr := w.Write(rendered); writeErr != nil {
			_ = closeFn()
			fmt.Fprintf(os.Stderr, "write %s: %v\n", *out, writeErr)
			os.Exit(1)
		}
		if closeErr := closeFn(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "close %s: %v\n", *out, closeErr)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "wrote evidence pack to %s\n", *out)
	}

	// Make integrity failures actionable: a non-verifying pack should not exit clean.
	if !pack.Integrity.Verified {
		os.Exit(1)
	}
}

func runVerifyReceipts(args []string) {
	fs := flag.NewFlagSet("verify-receipts", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "print JSON")
	receiptSecret := fs.String("receipt-secret", os.Getenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET"), "receipt signing secret; defaults to HUBBLEOPS_RECEIPT_SIGNING_SECRET")
	receiptPublicKey := fs.String("receipt-public-key", os.Getenv("HUBBLEOPS_RECEIPT_PUBLIC_KEY"), "base64 Ed25519 receipt public key; verify receipts without the signing secret")
	requireSignatures := fs.Bool("require-signatures", false, "fail verification if any action receipt is unsigned")
	_ = fs.Parse(args)
	if *requireSignatures && *receiptSecret == "" && *receiptPublicKey == "" {
		fmt.Fprintln(os.Stderr, "-require-signatures needs -receipt-public-key (or -receipt-secret / HUBBLEOPS_RECEIPT_SIGNING_SECRET)")
		os.Exit(1)
	}

	records, err := readShadowRecords(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	report := receiptverify.VerifyWithOptions(records, receiptverify.Options{
		ReceiptSecret:     *receiptSecret,
		ReceiptPublicKey:  *receiptPublicKey,
		RequireSignatures: *requireSignatures,
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		fmt.Printf("HubbleOps receipt verify\n")
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
	salt := fs.String("salt", os.Getenv("HUBBLEOPS_ANON_SALT"), "salt for anonymized IDs")
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
			fmt.Fprintln(os.Stderr, "-salt or HUBBLEOPS_ANON_SALT is required with -anonymize-out")
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
		fmt.Printf("HubbleOps loop eval\n")
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hubbleops demo|doctor|eval|shadow-report|evidence-pack|verify-receipts|review-decision|export-outcomes [flags]")
}
