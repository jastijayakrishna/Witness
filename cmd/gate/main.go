package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/hubbleops/hubbleops/internal/actionreceipt"
	"github.com/hubbleops/hubbleops/internal/approval"
	"github.com/hubbleops/hubbleops/internal/config"
	"github.com/hubbleops/hubbleops/internal/githubapp"
	"github.com/hubbleops/hubbleops/internal/policy"
	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func main() {
	runtime, err := newGateRuntime(os.Args[1:])
	logGateRuntime(runtime)
	if err != nil {
		var validationErr config.ValidationError
		if errors.As(err, &validationErr) {
			log.Fatal().Err(err).Msg("unsafe gate configuration")
		}
		log.Fatal().Err(err).Msg("configure gate")
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			log.Error().Err(err).Msg("close gate runtime")
		}
	}()

	log.Info().Str("addr", runtime.addr).Msg("HubbleOps gate listening")
	if err := http.ListenAndServe(runtime.addr, runtime.server.routes()); err != nil {
		log.Fatal().Err(err).Msg("gate server stopped")
	}
}

type gateRuntime struct {
	addr                string
	server              *server
	warnings            []string
	redactedSummaryJSON string
}

func (r gateRuntime) Close() error {
	if r.server == nil {
		return nil
	}
	return r.server.close()
}

func newGateRuntime(args []string) (gateRuntime, error) {
	var runtime gateRuntime
	cfg, err := config.FromEnv()
	if err != nil {
		return runtime, err
	}
	applyGateCompatibilityEnv(cfg)

	policyDefault := cfg.Policy.Path
	if strings.TrimSpace(os.Getenv("HUBBLEOPS_POLICY")) == "" {
		if path := defaultPolicyPath(); path != "" {
			policyDefault = path
		}
	}

	// Flag errors and usage must reach the operator: with ContinueOnError the
	// flag package prints both to this output before Parse returns the error.
	fs := flag.NewFlagSet("hubbleops-gate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", envOrDefault("HUBBLEOPS_GATE_ADDR", ":8080"), "HTTP listen address")
	policyPath := fs.String("policy", policyDefault, "YAML policy path")
	walDir := fs.String("wal-dir", cfg.WAL.Dir, "WAL directory for receipt output")
	walSyncMode := fs.String("wal-sync-mode", cfg.WAL.SyncMode, "WAL fsync mode: batch or sync")
	receiptSecret := fs.String("receipt-secret", os.Getenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET"), "receipt signing secret")
	receiptKeyID := fs.String("receipt-key-id", envOrDefault("HUBBLEOPS_RECEIPT_KEY_ID", "local"), "receipt key id")
	receiptSignerMode := fs.String("receipt-signer", cfg.Receipts.Signer, "receipt signer: none, local, aws-kms (gcp-kms and vault-transit are planned, not yet implemented)")
	receiptKMSKeyID := fs.String("receipt-kms-key-id", cfg.Receipts.KMSKeyID, "AWS KMS asymmetric key id/arn for receipt signing")
	receiptKMSRegion := fs.String("receipt-kms-region", cfg.Receipts.KMSRegion, "AWS KMS region for receipt signing")
	receiptKMSEndpoint := fs.String("receipt-kms-endpoint", cfg.Receipts.KMSEndpoint, "optional AWS KMS endpoint override")
	approvalStore := fs.String("approval-store", envOrDefault("HUBBLEOPS_APPROVAL_STORE", "data/approvals.json"), "file-backed approval store path; empty disables approvals")
	slackWebhook := fs.String("slack-webhook-url", os.Getenv("HUBBLEOPS_SLACK_WEBHOOK_URL"), "optional Slack webhook URL for approval requests")
	webhookSecret := fs.String("github-webhook-secret", os.Getenv("GITHUB_WEBHOOK_SECRET"), "GitHub webhook secret")
	githubAppID := fs.String("github-app-id", os.Getenv("GITHUB_APP_ID"), "GitHub App id")
	githubPrivateKeyFile := fs.String("github-private-key-file", os.Getenv("GITHUB_APP_PRIVATE_KEY_FILE"), "GitHub App private key PEM file")
	githubAPIURL := fs.String("github-api-url", envOrDefault("GITHUB_API_URL", "https://api.github.com"), "GitHub API base URL")
	checkName := fs.String("github-check-name", envOrDefault("HUBBLEOPS_GITHUB_CHECK_NAME", "HubbleOps Action Firewall"), "GitHub check run name")
	if err := fs.Parse(args); err != nil {
		return runtime, err
	}

	// Prefer a secret file over the flag/env so the signing secret never appears on the
	// process command line or in shell history.
	if strings.TrimSpace(*receiptSecret) == "" {
		if path := strings.TrimSpace(os.Getenv("HUBBLEOPS_RECEIPT_SIGNING_SECRET_FILE")); path != "" {
			data, err := os.ReadFile(path)
			if err != nil {
				log.Fatal().Err(err).Msg("read receipt signing secret file")
			}
			*receiptSecret = strings.TrimSpace(string(data))
		}
	}

	cfg.Policy.Path = *policyPath
	cfg.WAL.Dir = *walDir
	cfg.WAL.SyncMode = *walSyncMode
	cfg.Receipts.Signer = *receiptSignerMode
	cfg.Receipts.KMSKeyID = *receiptKMSKeyID
	cfg.Receipts.KMSRegion = *receiptKMSRegion
	cfg.Receipts.KMSEndpoint = *receiptKMSEndpoint
	secrets := config.RuntimeSecrets{ReceiptSigningSecretSet: strings.TrimSpace(*receiptSecret) != ""}
	result, err := cfg.Validate(secrets)
	runtime.addr = *addr
	runtime.warnings = result.Warnings
	runtime.redactedSummaryJSON = cfg.RedactedSummaryJSON(secrets)
	if err != nil {
		return runtime, err
	}

	pol, err := loadPolicy(cfg.Policy.Path)
	if err != nil {
		return runtime, fmt.Errorf("load policy: %w", err)
	}
	if pol != nil {
		for _, warning := range pol.Warnings {
			runtime.warnings = append(runtime.warnings, "policy: "+warning)
		}
	}
	githubClient, err := newGitHubClient(*githubAppID, *githubPrivateKeyFile, *githubAPIURL)
	if err != nil {
		return runtime, fmt.Errorf("configure GitHub App: %w", err)
	}
	var approvals *approval.Service
	if strings.TrimSpace(*approvalStore) != "" {
		var notifier approval.Notifier
		if strings.TrimSpace(*slackWebhook) != "" {
			notifier = approval.SlackNotifier{WebhookURL: *slackWebhook}
		}
		approvals = approval.NewService(approval.NewFileStore(*approvalStore), notifier)
	}
	gateAuthCfg, err := loadGateAuth(cfg.Auth)
	if err != nil {
		return runtime, fmt.Errorf("configure gate auth: %w", err)
	}
	receiptSigner, receiptSecretForWriter, err := configureReceiptSigner(cfg, *receiptKeyID, *receiptSecret)
	if err != nil {
		return runtime, fmt.Errorf("configure receipt signer: %w", err)
	}
	// Fail closed: a configured GitHub App without a webhook secret would accept any
	// unsigned webhook (see VerifyWebhook). Refuse to start in that state.
	if githubClient != nil && strings.TrimSpace(*webhookSecret) == "" {
		return runtime, fmt.Errorf("GITHUB_WEBHOOK_SECRET is required when the GitHub App is configured")
	}
	receiptOpts := actionreceipt.Options{
		WALDir:        cfg.WAL.Dir,
		WALSyncMode:   cfg.WAL.SyncMode,
		ReceiptSecret: receiptSecretForWriter,
		ReceiptKeyID:  *receiptKeyID,
		ReceiptSigner: receiptSigner,
	}
	receiptWALOptions := actionreceipt.WALOptions(receiptOpts)
	receiptWAL, err := wal.NewWriterWithOptions(receiptOpts.WALDir, receiptWALOptions)
	if err != nil {
		return runtime, fmt.Errorf("configure receipt WAL: %w", err)
	}
	log.Info().
		Str("wal_dir", receiptOpts.WALDir).
		Str("sync_mode", receiptWALOptions.SyncMode).
		Msg("gate receipt WAL writer initialized")
	runtime.server = &server{
		policy:        pol,
		receiptOpts:   receiptOpts,
		receiptWriter: actionreceipt.NewWriter(receiptWAL, receiptOpts),
		receiptConfig: cfg.Receipts,
		approvals:     approvals,
		github:        githubClient,
		auth:          gateAuthCfg,
		webhookSecret: *webhookSecret,
		checkName:     *checkName,
	}
	return runtime, nil
}

func configureReceiptSigner(cfg *config.Config, receiptKeyID, receiptSecret string) (receipts.ReceiptSigner, string, error) {
	// Reserved-but-stubbed signers (gcp-kms, vault-transit) fail every receipt
	// write at runtime; refuse them here so the gate never starts with one.
	if err := config.CheckReceiptSignerImplemented(cfg.Receipts.Signer); err != nil {
		return nil, "", err
	}
	mode := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(cfg.Receipts.Signer, "_", "-")))
	if mode == "" {
		if strings.TrimSpace(receiptSecret) != "" {
			mode = config.ReceiptSignerLocal
		} else {
			mode = config.ReceiptSignerNone
		}
	}
	switch mode {
	case config.ReceiptSignerNone:
		return nil, "", nil
	case config.ReceiptSignerLocal:
		if strings.TrimSpace(receiptSecret) == "" {
			return nil, "", nil
		}
		return receipts.NewLocalSecretSigner(receiptKeyID, []byte(receiptSecret)), receiptSecret, nil
	case config.ReceiptSignerAWSKMS:
		client := &receipts.AwsKmsHTTPClient{
			Region:          cfg.Receipts.KMSRegion,
			Endpoint:        cfg.Receipts.KMSEndpoint,
			AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
			HTTPClient:      &http.Client{Timeout: 15 * time.Second},
			Now:             time.Now,
		}
		return receipts.NewLazyAwsKmsSigner(receiptKeyID, cfg.Receipts.KMSKeyID, client), "", nil
	default:
		return nil, "", fmt.Errorf("unsupported receipt signer %q", cfg.Receipts.Signer)
	}
}

func logGateRuntime(runtime gateRuntime) {
	for _, warning := range runtime.warnings {
		log.Warn().Str("warning", warning).Msg("HubbleOps config warning")
	}
	if strings.TrimSpace(runtime.redactedSummaryJSON) != "" {
		log.Info().RawJSON("config", []byte(runtime.redactedSummaryJSON)).Msg("HubbleOps gate config")
	}
}

func applyGateCompatibilityEnv(cfg *config.Config) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("HUBBLEOPS_GATE_AUTH_DISABLED")), "true") {
		cfg.Auth.Enabled = false
	}
}

func newGitHubClient(appID, privateKeyFile, apiURL string) (*githubapp.Client, error) {
	privateKey := []byte(strings.ReplaceAll(os.Getenv("GITHUB_APP_PRIVATE_KEY"), `\n`, "\n"))
	if len(strings.TrimSpace(string(privateKey))) == 0 && strings.TrimSpace(privateKeyFile) != "" {
		data, err := os.ReadFile(privateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("read GitHub private key: %w", err)
		}
		privateKey = data
	}
	if strings.TrimSpace(appID) == "" && len(strings.TrimSpace(string(privateKey))) == 0 {
		return nil, nil
	}
	if strings.TrimSpace(appID) == "" || len(strings.TrimSpace(string(privateKey))) == 0 {
		return nil, fmt.Errorf("both GitHub App id and private key are required")
	}
	return &githubapp.Client{AppID: appID, PrivateKey: privateKey, BaseURL: apiURL}, nil
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

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
