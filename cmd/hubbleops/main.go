package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hubbleops/hubbleops/internal/action"
	"github.com/hubbleops/hubbleops/internal/actionreceipt"
	"github.com/hubbleops/hubbleops/internal/config"
	"github.com/hubbleops/hubbleops/internal/evidencepack"
	"github.com/hubbleops/hubbleops/internal/gate"
	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/policy"
	"github.com/hubbleops/hubbleops/internal/preflight"
	predeploy "github.com/hubbleops/hubbleops/internal/preflight/deploy"
	premigration "github.com/hubbleops/hubbleops/internal/preflight/migration"
	preterraform "github.com/hubbleops/hubbleops/internal/preflight/terraform"
	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/receiptverify"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}

	switch os.Args[1] {
	case "preflight":
		code := runPreflight(os.Args[2:])
		os.Exit(code)
	case "policy":
		os.Exit(runPolicy(os.Args[2:]))
	case "demo":
		code := runDemo(os.Args[2:])
		os.Exit(code)
	case "evidence-pack":
		runEvidencePack(os.Args[2:])
	case "verify-receipts":
		os.Exit(runVerifyReceipts(os.Args[2:]))
	default:
		usage()
		os.Exit(exitUsage)
	}
}

func runPolicy(args []string) int {
	if len(args) < 1 {
		policyUsage()
		return exitUsage
	}
	switch args[0] {
	case "validate":
		return runPolicyValidate(args[1:])
	default:
		policyUsage()
		return exitUsage
	}
}

func runPolicyValidate(args []string) int {
	fs := flag.NewFlagSet("policy validate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "policy validate requires one policy YAML path")
		return exitUsage
	}
	pol, err := policy.Load(fs.Arg(0))
	if err != nil {
		printPolicyError(err)
		return exitBlock
	}
	for _, warning := range pol.Warnings {
		fmt.Fprintln(os.Stderr, "warning: "+warning)
	}
	fmt.Printf("ok rules=%d\n", len(pol.Rules))
	return exitAllow
}

func printPolicyError(err error) {
	var validationErr policy.ValidationError
	if errors.As(err, &validationErr) {
		fmt.Fprintf(os.Stderr, "invalid policy %s\n", validationErr.Path)
		for _, problem := range validationErr.Problems {
			fmt.Fprintln(os.Stderr, problem)
		}
		return
	}
	fmt.Fprintln(os.Stderr, err)
}

type preflightFlags struct {
	Project                string
	SessionID              string
	Actor                  string
	HumanDelegator         string
	Environment            string
	Intent                 string
	IdempotencyKey         string
	ServiceRisk            string
	PolicyPath             string
	WALDir                 string
	ActionLedgerPath       string
	DuplicateWindowSeconds int
	ReceiptSecret          string
	ReceiptKeyID           string
	ReceiptSigner          string
	ReceiptKMSKeyID        string
	ReceiptKMSRegion       string
	ReceiptKMSEndpoint     string
	AnchorPath             string
	JSONOut                bool
}

func runPreflight(args []string) int {
	if len(args) < 1 {
		preflightUsage()
		return exitUsage
	}
	switch args[0] {
	case "terraform":
		return runPreflightTerraform(args[1:])
	case "migration":
		return runPreflightMigration(args[1:])
	case "deploy":
		return runPreflightDeploy(args[1:])
	case "deploy-result":
		return runPreflightDeployResult(args[1:])
	default:
		preflightUsage()
		return exitUsage
	}
}

// runPreflightDeployResult is the post-execution callback. After the real deploy runs, CI
// reports the outcome: a failure frees the idempotency key (so a legit retry is allowed
// rather than blocked as a duplicate for the whole window); a success leaves it committed.
func runPreflightDeployResult(args []string) int {
	fs, cfg := newPreflightFlagSet("preflight deploy-result")
	service := fs.String("service", "", "service that was deployed")
	artifact := fs.String("artifact", envOrDefault([]string{"HUBBLEOPS_DEPLOY_ARTIFACT", "GITHUB_SHA"}, ""), "deploy artifact, version, or commit")
	status := fs.String("status", "", "deploy result: success or failed")
	if code, ok := parsePreflightFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "preflight deploy-result takes flags only")
		return exitUsage
	}
	if err := validatePreflightIdentifiers(*cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	serviceName := strings.TrimSpace(*service)
	if serviceName == "" {
		fmt.Fprintln(os.Stderr, "-service is required")
		return exitUsage
	}
	if strings.TrimSpace(cfg.ActionLedgerPath) == "" {
		fmt.Fprintln(os.Stderr, "-action-ledger is required")
		return exitUsage
	}
	st := strings.ToLower(strings.TrimSpace(*status))
	if st != "success" && st != "failed" {
		fmt.Fprintln(os.Stderr, "-status must be success or failed")
		return exitUsage
	}
	pol, err := loadPolicy(cfg.PolicyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternalError
	}
	cfg.IdempotencyKey = strings.TrimSpace(cfg.IdempotencyKey)
	if cfg.IdempotencyKey == "" {
		cfg.IdempotencyKey = deriveDeployIdempotencyKey(*cfg, serviceName, *artifact)
	}

	req := baseRequest(*cfg)
	req.Action = "deploy.result"
	req.Target = serviceName
	req.Evidence = append(req.Evidence, "deploy_result="+st, "service_fingerprint="+privacy.FingerprintString(serviceName))
	if strings.TrimSpace(*artifact) != "" {
		req.Evidence = append(req.Evidence, "deploy_artifact_hash="+privacy.FingerprintString(*artifact))
	}

	var findings []preflight.Finding
	decision := gate.Decide(req, findings, pol)
	if st == "failed" {
		store := loop.NewFileActionStore(cfg.ActionLedgerPath)
		if err := store.Invalidate(context.Background(), req.Project, cfg.IdempotencyKey); err != nil {
			fmt.Fprintf(os.Stderr, "release deploy idempotency: %v\n", err)
			return exitInternalError
		}
		decision = withDecisionEvidence(decision, []string{"deploy_idempotency=released"})
	} else {
		decision = withDecisionEvidence(decision, []string{"deploy_idempotency=retained"})
	}
	return finishPreflight(req, decision, findings, *cfg)
}

func runPreflightTerraform(args []string) int {
	fs, cfg := newPreflightFlagSet("preflight terraform")
	if code, ok := parsePreflightFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "preflight terraform requires one terraform show -json plan file")
		return exitUsage
	}
	if err := validatePreflightIdentifiers(*cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}

	planPath := fs.Arg(0)
	data, err := os.ReadFile(planPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read terraform plan: %v\n", err)
		return exitInternalError
	}
	pol, err := loadPolicy(cfg.PolicyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternalError
	}
	var protected []string
	if pol != nil {
		protected = pol.ProtectedResources
	}
	findings, err := preterraform.Scan(strings.NewReader(string(data)), preterraform.Options{ProtectedResources: protected})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternalError
	}
	req := baseRequest(*cfg)
	req.Action = "terraform.plan"
	req.Evidence = append(req.Evidence, "terraform_plan_hash="+privacy.FingerprintBytes(data))
	targets := preflight.Targets(findings)
	if len(targets) == 1 {
		req.Target = targets[0]
	}
	if len(findings) > 0 {
		req.Action = findings[0].Action
	}

	decision := gate.Decide(req, findings, pol)
	return finishPreflight(req, decision, findings, *cfg)
}

func runPreflightMigration(args []string) int {
	fs, cfg := newPreflightFlagSet("preflight migration")
	if code, ok := parsePreflightFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "preflight migration requires at least one migration file or directory")
		return exitUsage
	}
	if err := validatePreflightIdentifiers(*cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	pol, err := loadPolicy(cfg.PolicyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternalError
	}
	findings, err := premigration.ScanPaths(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternalError
	}
	req := baseRequest(*cfg)
	req.Action = "migration.apply"
	req.Evidence = append(req.Evidence, "migration_input_hash="+privacy.FingerprintString(strings.Join(fs.Args(), "\x00")))
	targets := preflight.Targets(findings)
	if len(targets) == 1 {
		req.Target = targets[0]
	}
	if len(findings) > 0 {
		req.Action = findings[0].Action
	}

	decision := gate.Decide(req, findings, pol)
	return finishPreflight(req, decision, findings, *cfg)
}

func runPreflightDeploy(args []string) int {
	fs, cfg := newPreflightFlagSet("preflight deploy")
	service := fs.String("service", "", "service being deployed")
	artifact := fs.String("artifact", envOrDefault([]string{"HUBBLEOPS_DEPLOY_ARTIFACT", "GITHUB_SHA"}, ""), "deploy artifact, version, or commit; stored as a hash in receipts")
	if code, ok := parsePreflightFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "preflight deploy takes flags only; use -service for the service name")
		return exitUsage
	}
	if err := validatePreflightIdentifiers(*cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}
	serviceName := strings.TrimSpace(*service)
	if serviceName == "" {
		fmt.Fprintln(os.Stderr, "-service is required")
		return exitUsage
	}
	if strings.TrimSpace(cfg.ActionLedgerPath) == "" {
		fmt.Fprintln(os.Stderr, "-action-ledger is required for deploy idempotency")
		return exitUsage
	}
	pol, err := loadPolicy(cfg.PolicyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternalError
	}
	if strings.TrimSpace(cfg.ServiceRisk) == "" && pol != nil {
		cfg.ServiceRisk = pol.ServiceRisk(serviceName)
	}
	cfg.ServiceRisk = predeploy.NormalizeRisk(cfg.ServiceRisk)
	cfg.IdempotencyKey = strings.TrimSpace(cfg.IdempotencyKey)
	if cfg.IdempotencyKey == "" {
		cfg.IdempotencyKey = deriveDeployIdempotencyKey(*cfg, serviceName, *artifact)
	}

	req := baseRequest(*cfg)
	req.Action = predeploy.ActionRelease
	req.Target = serviceName
	req.ServiceRisk = cfg.ServiceRisk
	req.Evidence = append(req.Evidence,
		"deploy_action=release",
		"deploy_environment="+req.Environment,
		"service_risk="+cfg.ServiceRisk,
		"service_fingerprint="+privacy.FingerprintString(serviceName),
	)
	if strings.TrimSpace(*artifact) != "" {
		req.Evidence = append(req.Evidence, "deploy_artifact_hash="+privacy.FingerprintString(*artifact))
	}

	findings := predeploy.Scan(predeploy.Options{
		Service:     serviceName,
		Environment: req.Environment,
		ServiceRisk: cfg.ServiceRisk,
	})
	decision := gate.Decide(req, findings, pol)
	claim, duplicateDecision, duplicateFindings, err := claimDeployIdempotency(req, decision, findings, *cfg)
	if err != nil {
		block := deployLedgerErrorDecision(req, decision, findings, err)
		return finishPreflight(req, block, append(findings, deployLedgerFinding(req, err.Error())), *cfg)
	}
	if duplicateDecision != nil {
		return finishPreflight(req, *duplicateDecision, duplicateFindings, *cfg)
	}
	decision = withDecisionEvidence(decision, claim.Evidence)
	return finishPreflightWithHook(req, decision, findings, *cfg, func(written action.Decision) error {
		return reconcileDeployIdempotency(req, written, claim, *cfg)
	})
}

func newPreflightFlagSet(name string) (*flag.FlagSet, *preflightFlags) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfg := &preflightFlags{}
	fs.StringVar(&cfg.Project, "project", envOrDefault([]string{"HUBBLEOPS_PROJECT"}, "local"), "project identifier")
	fs.StringVar(&cfg.SessionID, "session", envOrDefault([]string{"HUBBLEOPS_SESSION_ID"}, "cli-"+time.Now().UTC().Format("20060102T150405Z")), "session identifier")
	fs.StringVar(&cfg.Actor, "actor", envOrDefault([]string{"HUBBLEOPS_ACTOR"}, "agent:local-cli"), "agent actor")
	fs.StringVar(&cfg.HumanDelegator, "human-delegator", os.Getenv("HUBBLEOPS_HUMAN_DELEGATOR"), "human delegator")
	fs.StringVar(&cfg.Environment, "env", envOrDefault([]string{"HUBBLEOPS_ENVIRONMENT", "HUBBLEOPS_ENV"}, "unknown"), "target environment")
	fs.StringVar(&cfg.Intent, "intent", "", "operator intent; stored as a hash in receipts")
	fs.StringVar(&cfg.IdempotencyKey, "idempotency-key", "", "stable idempotency key; stored as a hash in receipts")
	fs.StringVar(&cfg.ServiceRisk, "service-risk", "", "service risk tier for policy rules")
	fs.StringVar(&cfg.PolicyPath, "policy", defaultPolicyPath(), "YAML policy path")
	fs.StringVar(&cfg.WALDir, "wal-dir", envOrDefault([]string{"HUBBLEOPS_WAL_DIR"}, "data/wal"), "WAL directory for receipt output")
	fs.StringVar(&cfg.ActionLedgerPath, "action-ledger", envOrDefault([]string{"HUBBLEOPS_ACTION_LEDGER"}, "data/action-ledger.json"), "file-backed ActionStore ledger for deploy idempotency")
	fs.StringVar(&cfg.ActionLedgerPath, "ledger", cfg.ActionLedgerPath, "alias for -action-ledger")
	fs.IntVar(&cfg.DuplicateWindowSeconds, "duplicate-window-seconds", envIntOrDefault("HUBBLEOPS_DUPLICATE_WINDOW_SECONDS", 7*24*60*60), "deploy duplicate window in seconds")
	fs.StringVar(&cfg.ReceiptSecret, "receipt-secret", receiptSecretFromEnv(), "receipt signing secret")
	fs.StringVar(&cfg.ReceiptKeyID, "receipt-key-id", envOrDefault([]string{"HUBBLEOPS_RECEIPT_KEY_ID"}, "local"), "receipt key id")
	fs.StringVar(&cfg.ReceiptSigner, "receipt-signer", envOrDefault([]string{"HUBBLEOPS_RECEIPT_SIGNER"}, ""), "receipt signer: none, local, aws-kms (gcp-kms and vault-transit are planned, not yet implemented)")
	fs.StringVar(&cfg.ReceiptKMSKeyID, "receipt-kms-key-id", envOrDefault([]string{"HUBBLEOPS_RECEIPT_KMS_KEY_ID"}, ""), "AWS KMS asymmetric key id/arn for receipt signing")
	fs.StringVar(&cfg.ReceiptKMSRegion, "receipt-kms-region", envOrDefault([]string{"HUBBLEOPS_RECEIPT_KMS_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"}, ""), "AWS KMS region for receipt signing")
	fs.StringVar(&cfg.ReceiptKMSEndpoint, "receipt-kms-endpoint", envOrDefault([]string{"HUBBLEOPS_RECEIPT_KMS_ENDPOINT"}, ""), "optional AWS KMS endpoint override")
	fs.StringVar(&cfg.AnchorPath, "anchor", os.Getenv("HUBBLEOPS_WAL_ANCHOR"), "receipt checkpoint anchor path, file:// URL, stdout, or s3:// URL")
	fs.BoolVar(&cfg.JSONOut, "json", false, "print JSON")
	return fs, cfg
}

// parsePreflightFlags parses args (flags reordered ahead of positionals) and
// reports whether execution may continue. A flag error MUST stop the run:
// continuing with half-parsed defaults would burn the wrong project, session,
// or actor into a signed audit receipt. The flag package has already printed
// the error and usage to stderr when Parse fails.
func parsePreflightFlags(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(flagsFirst(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, false
		}
		return 2, false
	}
	return 0, true
}

func validatePreflightIdentifiers(cfg preflightFlags) error {
	// Reject reserved-but-stubbed signers before any scan or receipt work, so a
	// misconfigured run is a usage error rather than a per-run runtime failure.
	if err := config.CheckReceiptSignerImplemented(cfg.ReceiptSigner); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.Project) == "" {
		return fmt.Errorf("-project is required")
	}
	if strings.TrimSpace(cfg.SessionID) == "" {
		return fmt.Errorf("-session is required")
	}
	if strings.TrimSpace(cfg.Actor) == "" {
		return fmt.Errorf("-actor is required")
	}
	if strings.TrimSpace(cfg.WALDir) == "" {
		return fmt.Errorf("-wal-dir is required")
	}
	return nil
}

func baseRequest(cfg preflightFlags) action.Request {
	return action.Request{
		Project:        strings.TrimSpace(cfg.Project),
		SessionID:      strings.TrimSpace(cfg.SessionID),
		Actor:          strings.TrimSpace(cfg.Actor),
		HumanDelegator: strings.TrimSpace(cfg.HumanDelegator),
		Environment:    normalizeEnvironment(cfg.Environment),
		Intent:         cfg.Intent,
		IdempotencyKey: cfg.IdempotencyKey,
		ServiceRisk:    cfg.ServiceRisk,
		PolicyVersion:  action.PolicyVersion,
		CaptureMode:    privacy.CaptureModeFingerprint,
	}
}

type deployIdempotencyClaim struct {
	Store       *loop.ActionStore
	Observation loop.ActionObservation
	Evidence    []string
	ClaimNonce  string
}

func claimDeployIdempotency(req action.Request, baseDecision action.Decision, findings []preflight.Finding, cfg preflightFlags) (deployIdempotencyClaim, *action.Decision, []preflight.Finding, error) {
	store := loop.NewFileActionStore(cfg.ActionLedgerPath)
	obs := deployObservation(req, cfg)
	decision, err := store.Decide(context.Background(), obs)
	if err != nil {
		return deployIdempotencyClaim{}, nil, findings, err
	}
	claim := deployIdempotencyClaim{Store: store, Observation: obs, Evidence: decision.Evidence, ClaimNonce: decision.ClaimNonce}
	if decision.Outcome == loop.ActionOutcomeClaimed && decision.Decision.ActionCeiling != loop.ActionBlock {
		return claim, nil, findings, nil
	}
	block, allFindings := deployIdempotencyBlockDecision(req, baseDecision, findings, decision)
	return claim, &block, allFindings, nil
}

// reconcileDeployIdempotency settles the pending idempotency lease taken before the gate
// decision. Only an authorized (allow) deploy commits the key for the full duplicate
// window — it is cleared to run, so a later identical attempt is a true duplicate side
// effect. A deploy that needs approval or is blocked never executed, so its pending lease
// is released and a re-run re-evaluates from scratch instead of being masked as a
// duplicate.
func reconcileDeployIdempotency(req action.Request, decision action.Decision, claim deployIdempotencyClaim, cfg preflightFlags) error {
	if claim.Store == nil {
		return fmt.Errorf("action ledger is not configured")
	}
	if decision.Decision != action.DecisionAllow {
		return claim.Store.Release(context.Background(), req.Project, req.IdempotencyKey, claim.ClaimNonce)
	}
	return claim.Store.Commit(context.Background(), loop.ActionResult{
		Project:                req.Project,
		IdempotencyKey:         req.IdempotencyKey,
		ClaimNonce:             claim.ClaimNonce,
		ToolName:               req.Action,
		ActionRisk:             claim.Observation.ActionRisk,
		RawActionRisk:          claim.Observation.RawActionRisk,
		ResourceID:             claim.Observation.ResourceID,
		DecisionID:             decision.DecisionID,
		ResultClass:            receiptResultClass(decision.Decision),
		ResultFingerprint:      decision.ReceiptID,
		DuplicateWindowSeconds: cfg.DuplicateWindowSeconds,
	})
}

func deployObservation(req action.Request, cfg preflightFlags) loop.ActionObservation {
	risk := deployActionRisk(req.ServiceRisk, req.Environment)
	return loop.ActionObservation{
		Project:                req.Project,
		SessionID:              req.SessionID,
		StepID:                 "preflight-deploy",
		ToolName:               req.Action,
		ActionRisk:             risk,
		RawActionRisk:          risk,
		IdempotencyKey:         req.IdempotencyKey,
		AgentID:                req.Actor,
		UserID:                 req.HumanDelegator,
		ResourceID:             req.Environment + "/" + req.Target,
		DuplicateWindowSeconds: cfg.DuplicateWindowSeconds,
	}
}

func deployActionRisk(serviceRisk, env string) string {
	serviceRisk = predeploy.NormalizeRisk(serviceRisk)
	production := normalizeEnvironment(env) == "production"
	switch serviceRisk {
	case "tier_0", "tier0", "critical":
		return loop.ActionRiskDangerous
	case "tier_1", "tier1", "high":
		if production {
			return loop.ActionRiskDangerous
		}
		return loop.ActionRiskWrite
	default:
		return loop.ActionRiskWrite
	}
}

func deployIdempotencyBlockDecision(req action.Request, baseDecision action.Decision, findings []preflight.Finding, storeDecision loop.ActionDecision) (action.Decision, []preflight.Finding) {
	kind := preflight.KindDeployDuplicate
	next := []string{"use_existing_receipt", "open_review"}
	switch storeDecision.Outcome {
	case loop.ActionOutcomeInFlight:
		next = []string{"retry_later", "open_review"}
	case loop.ActionOutcomeMismatch:
		next = []string{"fix_idempotency_key", "open_review"}
	}
	finding := preflight.Finding{
		Source:    preflight.SourceDeploy,
		Kind:      kind,
		Action:    req.Action,
		Target:    req.Target,
		RiskScore: 100,
		RiskClass: action.RiskCritical,
		Evidence:  append([]string{"deploy_idempotency=" + firstNonEmpty(storeDecision.Outcome, "blocked")}, storeDecision.Evidence...),
		ChangeTags: []string{
			"deploy:idempotency",
			"idempotency:" + firstNonEmpty(storeDecision.Outcome, "blocked"),
		},
	}
	allFindings := append(append([]preflight.Finding{}, findings...), finding)
	decision := gate.Decide(req, allFindings, nil)
	decision.Decision = action.DecisionBlock
	decision.Reason = firstNonEmpty(storeDecision.Reason, storeDecision.Decision.Reason, "deploy idempotency check blocked this action")
	decision.RiskScore = 100
	decision.RiskClass = action.RiskCritical
	decision.RequiredApprovers = nil
	decision.AllowedNextActions = next
	decision.PolicyVersion = firstNonEmpty(baseDecision.PolicyVersion, action.PolicyVersion)
	decision.Evidence = appendUnique(baseDecision.Evidence, finding.Evidence...)
	decision.PolicyRuleID = baseDecision.PolicyRuleID
	decision.RequiresReceipt = true
	return decision, allFindings
}

func deployLedgerErrorDecision(req action.Request, baseDecision action.Decision, findings []preflight.Finding, err error) action.Decision {
	allFindings := append(append([]preflight.Finding{}, findings...), deployLedgerFinding(req, err.Error()))
	decision := gate.Decide(req, allFindings, nil)
	decision.Decision = action.DecisionBlock
	decision.Reason = "deploy idempotency ledger unavailable; blocking before release"
	decision.RiskScore = 100
	decision.RiskClass = action.RiskCritical
	decision.AllowedNextActions = []string{"fix_idempotency_ledger", "open_review"}
	decision.PolicyVersion = firstNonEmpty(baseDecision.PolicyVersion, action.PolicyVersion)
	decision.Evidence = appendUnique(baseDecision.Evidence, "deploy_idempotency=ledger_error", "ledger_error="+privacy.FingerprintString(err.Error()))
	decision.RequiresReceipt = true
	return decision
}

func deployLedgerFinding(req action.Request, evidence string) preflight.Finding {
	return preflight.Finding{
		Source:    preflight.SourceDeploy,
		Kind:      preflight.KindDeployLedgerError,
		Action:    req.Action,
		Target:    req.Target,
		RiskScore: 100,
		RiskClass: action.RiskCritical,
		Evidence: []string{
			"deploy_idempotency=ledger_error",
			"ledger_error=" + privacy.FingerprintString(evidence),
		},
		ChangeTags: []string{"deploy:idempotency", "idempotency:ledger_error"},
	}
}

func deriveDeployIdempotencyKey(cfg preflightFlags, service, artifact string) string {
	// Identity is project/env/service/artifact — NOT intent — so the preflight and the
	// deploy-result callback derive the same key for the same deploy.
	parts := []string{
		strings.TrimSpace(cfg.Project),
		normalizeEnvironment(cfg.Environment),
		strings.TrimSpace(service),
		strings.TrimSpace(artifact),
	}
	return "deploy:" + strings.TrimPrefix(privacy.FingerprintString(strings.Join(parts, "\x00")), "sha256:")
}

func receiptResultClass(decision string) string {
	switch decision {
	case action.DecisionBlock:
		return "blocked"
	case action.DecisionRequireApproval:
		return "requires_review"
	default:
		return "allowed"
	}
}

func appendUnique(base []string, values ...string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range append(append([]string{}, base...), values...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func withDecisionEvidence(decision action.Decision, evidence []string) action.Decision {
	decision.Evidence = appendUnique(decision.Evidence, evidence...)
	seen := map[string]struct{}{}
	for _, hash := range decision.EvidenceHashes {
		seen[hash] = struct{}{}
	}
	for _, item := range evidence {
		fp := privacy.FingerprintString(item)
		if _, ok := seen[fp]; ok {
			continue
		}
		seen[fp] = struct{}{}
		decision.EvidenceHashes = append(decision.EvidenceHashes, fp)
	}
	sort.Strings(decision.EvidenceHashes)
	return decision
}

func finishPreflight(req action.Request, decision action.Decision, findings []preflight.Finding, cfg preflightFlags) int {
	return finishPreflightWithHook(req, decision, findings, cfg, nil)
}

func finishPreflightWithHook(req action.Request, decision action.Decision, findings []preflight.Finding, cfg preflightFlags, afterReceipt func(action.Decision) error) int {
	decision, err := writePreflightReceipt(req, decision, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write preflight receipt: %v\n", err)
		return exitInternalError
	}
	if afterReceipt != nil {
		if err := afterReceipt(decision); err != nil {
			fmt.Fprintf(os.Stderr, "record deploy idempotency: %v\n", err)
			return exitInternalError
		}
	}
	if cfg.JSONOut {
		outputDecision := action.SanitizeForOutput(decision)
		outputFindings := preflight.SanitizeFindingsForOutput(findings)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			action.Decision
			Findings []preflight.Finding `json:"findings"`
		}{Decision: outputDecision, Findings: outputFindings})
	} else {
		printPreflightDecision(action.SanitizeForOutput(decision), len(findings))
	}
	switch decision.Decision {
	case action.DecisionBlock:
		return exitBlock
	case action.DecisionRequireApproval:
		return exitRequireApproval
	default:
		return exitAllow
	}
}

func writePreflightReceipt(req action.Request, decision action.Decision, cfg preflightFlags) (action.Decision, error) {
	anchor, err := anchorFromArg(cfg.AnchorPath)
	if err != nil {
		decision.ReceiptError = err.Error()
		return decision, err
	}
	receiptSigner, receiptSecret, err := configurePreflightReceiptSigner(cfg)
	if err != nil {
		decision.ReceiptError = err.Error()
		return decision, err
	}
	return actionreceipt.Write(req, decision, actionreceipt.Options{
		WALDir:        cfg.WALDir,
		ReceiptSecret: receiptSecret,
		ReceiptKeyID:  cfg.ReceiptKeyID,
		ReceiptSigner: receiptSigner,
		Anchor:        anchor,
	})
}

func configurePreflightReceiptSigner(cfg preflightFlags) (receipts.ReceiptSigner, string, error) {
	if err := config.CheckReceiptSignerImplemented(cfg.ReceiptSigner); err != nil {
		return nil, "", err
	}
	mode := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(cfg.ReceiptSigner, "_", "-")))
	if mode == "" {
		if strings.TrimSpace(cfg.ReceiptSecret) != "" {
			mode = config.ReceiptSignerLocal
		} else {
			mode = config.ReceiptSignerNone
		}
	}
	switch mode {
	case config.ReceiptSignerNone:
		return nil, "", nil
	case config.ReceiptSignerLocal:
		if strings.TrimSpace(cfg.ReceiptSecret) == "" {
			return nil, "", nil
		}
		return receipts.NewLocalSecretSigner(cfg.ReceiptKeyID, []byte(cfg.ReceiptSecret)), cfg.ReceiptSecret, nil
	case config.ReceiptSignerAWSKMS:
		if strings.TrimSpace(cfg.ReceiptKMSKeyID) == "" {
			return nil, "", fmt.Errorf("-receipt-kms-key-id is required when -receipt-signer=aws-kms")
		}
		if strings.TrimSpace(cfg.ReceiptKMSRegion) == "" {
			return nil, "", fmt.Errorf("-receipt-kms-region or AWS_REGION is required when -receipt-signer=aws-kms")
		}
		client := &receipts.AwsKmsHTTPClient{
			Region:          cfg.ReceiptKMSRegion,
			Endpoint:        cfg.ReceiptKMSEndpoint,
			AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
			HTTPClient:      &http.Client{Timeout: 15 * time.Second},
			Now:             time.Now,
		}
		return receipts.NewLazyAwsKmsSigner(cfg.ReceiptKeyID, cfg.ReceiptKMSKeyID, client), "", nil
	default:
		return nil, "", fmt.Errorf("unsupported receipt signer %q", cfg.ReceiptSigner)
	}
}

func printPreflightDecision(decision action.Decision, findingCount int) {
	fmt.Printf("HubbleOps preflight decision\n")
	fmt.Printf("decision=%s risk_score=%d risk_class=%s findings=%d receipt_id=%s\n",
		decision.Decision, decision.RiskScore, decision.RiskClass, findingCount, decision.ReceiptID)
	fmt.Printf("reason=%s\n", decision.Reason)
	if len(decision.RequiredApprovers) > 0 {
		fmt.Printf("required_approvers=%s\n", strings.Join(decision.RequiredApprovers, ","))
	}
	if decision.ReceiptError != "" {
		fmt.Printf("receipt_warning=%s\n", decision.ReceiptError)
	}
}

func runEvidencePack(args []string) {
	fs := flag.NewFlagSet("evidence-pack", flag.ExitOnError)
	format := fs.String("format", "markdown", "output format: markdown or json")
	sinceRaw := fs.String("since", "", "inclusive start day, YYYY-MM-DD")
	untilRaw := fs.String("until", "", "exclusive end day, YYYY-MM-DD")
	project := fs.String("project", "", "limit to a single project")
	receiptPublicKey := fs.String("receipt-public-key", os.Getenv("HUBBLEOPS_RECEIPT_PUBLIC_KEY"), "base64 Ed25519 receipt public key")
	receiptSecret := fs.String("receipt-secret", os.Getenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET"), "receipt signing secret")
	out := fs.String("out", "", "write the pack to this file instead of stdout")
	_ = fs.Parse(args)

	opts := evidencepack.Options{
		Project:          *project,
		ReceiptPublicKey: *receiptPublicKey,
		ReceiptSecret:    *receiptSecret,
	}
	if *sinceRaw != "" {
		since, err := parseDay(*sinceRaw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "since: %v\n", err)
			os.Exit(exitUsage)
		}
		opts.Since = since
	}
	if *untilRaw != "" {
		until, err := parseDay(*untilRaw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "until: %v\n", err)
			os.Exit(exitUsage)
		}
		opts.Until = until.AddDate(0, 0, 1)
	}

	records, err := readWALRecords(fs.Args())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(exitInternalError)
	}
	pack := evidencepack.Build(records, opts)

	var rendered []byte
	switch strings.ToLower(strings.TrimSpace(*format)) {
	case "json":
		rendered, err = evidencepack.RenderJSON(pack)
		if err != nil {
			fmt.Fprintf(os.Stderr, "render json: %v\n", err)
			os.Exit(exitInternalError)
		}
	case "markdown", "md", "":
		rendered = []byte(evidencepack.RenderMarkdown(pack))
	default:
		fmt.Fprintf(os.Stderr, "unknown evidence-pack format %q; use markdown or json\n", *format)
		os.Exit(exitUsage)
	}
	writeOutputOrExit(*out, rendered)
	if !pack.Integrity.Verified {
		os.Exit(exitBlock)
	}
}

func runVerifyReceipts(args []string) int {
	fs := flag.NewFlagSet("verify-receipts", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "print JSON")
	receiptSecret := fs.String("receipt-secret", receiptSecretFromEnv(), "receipt signing secret")
	receiptPublicKey := fs.String("receipt-public-key", os.Getenv("HUBBLEOPS_RECEIPT_PUBLIC_KEY"), "base64 Ed25519 receipt public key")
	receiptPublicKeys := fs.String("receipt-public-keys", os.Getenv("HUBBLEOPS_RECEIPT_PUBLIC_KEYS"), "comma-separated key_id=base64 public keys to verify across key rotation")
	requireSignatures := fs.Bool("require-signatures", false, "fail verification if any action receipt is unsigned")
	anchorRaw := fs.String("anchor", "", "checkpoint anchor path, file:// URL, or s3:// URL")
	legacy := fs.Bool("legacy", false, "allow legacy records without seq when no anchor is supplied")
	_ = fs.Parse(args)
	keySet := parseKeyPairs(*receiptPublicKeys)
	if *requireSignatures && *receiptSecret == "" && *receiptPublicKey == "" && len(keySet) == 0 {
		fmt.Fprintln(os.Stderr, "-require-signatures needs -receipt-public-key(s) or -receipt-secret")
		return exitUsage
	}
	anchor, err := anchorFromArg(*anchorRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitUsage
	}

	// Stream the WAL one record at a time so verification stays O(1) in memory regardless of
	// how large the log is.
	verifier, err := receiptverify.NewVerifier(receiptverify.Options{
		ReceiptSecret:     *receiptSecret,
		ReceiptPublicKey:  *receiptPublicKey,
		ReceiptPublicKeys: keySet,
		RequireSignatures: *requireSignatures,
		Legacy:            *legacy,
		Anchor:            anchor,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternalError
	}
	if err := streamWALInto(verifier, fs.Args()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return exitInternalError
	}
	report := verifier.Report()
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		fmt.Printf("HubbleOps receipt verify\n")
		fmt.Printf("records=%d action_receipts=%d signed_receipts=%d unsigned_receipts=%d verified=%t\n",
			report.TotalRecords, report.ActionReceipts, report.SignedReceipts, report.UnsignedReceipts, report.Verified)
		fmt.Printf("missing_hashes=%d hash_mismatches=%d signature_mismatches=%d chain_broken_at=%d receipt_field_gaps=%d missing_seq=%d seq_gaps=%d anchor_mismatches=%d anchor_signature_mismatches=%d max_seq=%d\n",
			report.MissingHashes, report.HashMismatches, report.SignatureMismatches, report.ChainBrokenAt, report.ReceiptFieldGaps,
			report.MissingSeq, report.SeqGaps, report.AnchorMismatches, report.AnchorSignatureMismatches, report.MaxSeq)
		if report.LastRecordHash != "" {
			fmt.Printf("last_record_hash=%s\n", report.LastRecordHash)
		}
		if report.AnchorSeq != 0 {
			fmt.Printf("anchor_seq=%d anchor_head_hash=%s\n", report.AnchorSeq, report.AnchorHeadHash)
		}
		if report.Recommendation != "" {
			fmt.Printf("recommendation=%s\n", report.Recommendation)
		}
	}
	if !report.Verified {
		return exitBlock
	}
	return exitAllow
}

func anchorFromArg(raw string) (wal.Anchor, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	switch {
	case raw == "stdout" || raw == "stdout://":
		return wal.StdoutAnchor{}, nil
	case strings.HasPrefix(raw, "file://"):
		return wal.NewFileAnchor(strings.TrimPrefix(raw, "file://")), nil
	case strings.HasPrefix(raw, "s3://"):
		return wal.NewS3ObjectLockAnchor(raw)
	default:
		return wal.NewFileAnchor(raw), nil
	}
}

// streamWALInto feeds WAL files (or stdin) through the verifier one record at a time, never
// materializing the whole log in memory.
func streamWALInto(v *receiptverify.Verifier, paths []string) error {
	if len(paths) == 0 {
		return v.AddStream(os.Stdin)
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		readErr := v.AddStream(f)
		closeErr := f.Close()
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", path, closeErr)
		}
	}
	return nil
}

func readWALRecords(paths []string) ([]wal.Record, error) {
	if len(paths) == 0 {
		return decodeRecords(os.Stdin)
	}
	var out []wal.Record
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}
		records, readErr := decodeRecords(f)
		closeErr := f.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", path, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", path, closeErr)
		}
		out = append(out, records...)
	}
	return out, nil
}

func decodeRecords(r io.Reader) ([]wal.Record, error) {
	dec := json.NewDecoder(r)
	var records []wal.Record
	for {
		var rec wal.Record
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				return records, nil
			}
			return nil, err
		}
		records = append(records, rec)
	}
}

func loadPolicy(path string) (*policy.Policy, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, nil
	}
	return policy.Load(path)
}

func defaultPolicyPath() string {
	if value := strings.TrimSpace(os.Getenv("HUBBLEOPS_POLICY")); value != "" {
		return value
	}
	if _, err := os.Stat(filepath.Join("configs", "policy.yaml")); err == nil {
		return filepath.Join("configs", "policy.yaml")
	}
	if _, err := os.Stat(filepath.Join("configs", "policy.yaml.example")); err == nil {
		return filepath.Join("configs", "policy.yaml.example")
	}
	return ""
}

func parseDay(raw string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}, fmt.Errorf("use YYYY-MM-DD: %w", err)
	}
	return t.UTC(), nil
}

func writeOutputOrExit(path string, data []byte) {
	if path == "" {
		fmt.Print(string(data))
		return
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
		os.Exit(exitInternalError)
	}
}

func normalizeEnvironment(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "prod":
		return "production"
	case "dev":
		return "development"
	case "":
		return "unknown"
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func envOrDefault(names []string, fallback string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return fallback
}

// receiptSecretFromEnv prefers a secret file over an inline env value so the signing secret
// need not appear on the command line.
func receiptSecretFromEnv() string {
	if s := strings.TrimSpace(os.Getenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET")); s != "" {
		return s
	}
	if path := strings.TrimSpace(os.Getenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET_FILE")); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// parseKeyPairs parses "key_id=base64,key_id2=base64" into a map for rotation verification.
func parseKeyPairs(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		kid, encoded, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			continue
		}
		if kid = strings.TrimSpace(kid); kid != "" {
			out[kid] = strings.TrimSpace(encoded)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func envIntOrDefault(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: hubbleops preflight|policy|demo|evidence-pack|verify-receipts [flags]")
}

func preflightUsage() {
	fmt.Fprintln(os.Stderr, "usage: hubbleops preflight terraform|migration|deploy [flags] <input>")
}

func policyUsage() {
	fmt.Fprintln(os.Stderr, "usage: hubbleops policy validate <policy.yaml>")
}

func flagsFirst(fs *flag.FlagSet, args []string) []string {
	var flags []string
	var positional []string
	// Bool flags never consume the next argument. Derive them from the FlagSet
	// so newly registered bool flags cannot silently desync the reordering.
	boolFlags := map[string]struct{}{}
	fs.VisitAll(func(f *flag.Flag) {
		if b, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && b.IsBoolFlag() {
			boolFlags[f.Name] = struct{}{}
		}
	})
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if idx := strings.Index(name, "="); idx >= 0 {
			name = name[:idx]
		}
		if _, ok := boolFlags[name]; ok || strings.Contains(arg, "=") {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}
