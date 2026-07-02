package actionreceipt

import (
	"fmt"
	"strings"

	"github.com/hubbleops/hubbleops/internal/action"
	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

type Options struct {
	WALDir        string
	WALSyncMode   string
	ReceiptSecret string
	ReceiptKeyID  string
	ReceiptSigner receipts.ReceiptSigner
	Anchor        wal.Anchor
}

type Writer struct {
	walWriter *wal.Writer
	signer    receipts.ReceiptSigner
	opts      Options
}

func NewWriter(walWriter *wal.Writer, opts Options) *Writer {
	return &Writer{
		walWriter: walWriter,
		signer:    signerFromOptions(opts),
		opts:      opts,
	}
}

func NewOneShotWriter(opts Options) (*Writer, error) {
	writer, err := wal.NewWriterWithOptions(opts.WALDir, WALOptions(opts))
	if err != nil {
		return nil, err
	}
	return NewWriter(writer, opts), nil
}

func WALOptions(opts Options) wal.WriterOptions {
	signer := signerFromOptions(opts)
	var checkpointSigner wal.CheckpointSigner
	if signer != nil {
		checkpointSigner = signer.SignCheckpoint
	}
	syncMode := strings.TrimSpace(opts.WALSyncMode)
	if syncMode == "" {
		syncMode = wal.SyncModeSync
	}
	return wal.WriterOptions{
		SyncMode:         syncMode,
		Anchor:           opts.Anchor,
		CheckpointSigner: checkpointSigner,
	}
}

func Write(req action.Request, decision action.Decision, opts Options) (action.Decision, error) {
	writer, err := NewOneShotWriter(opts)
	if err != nil {
		decision.ReceiptError = err.Error()
		return decision, err
	}
	defer writer.Close()
	return writer.Write(req, decision)
}

func (w *Writer) Write(req action.Request, decision action.Decision) (action.Decision, error) {
	decision.ReceiptAttempted = true
	if w == nil || w.walWriter == nil {
		err := fmt.Errorf("receipt writer is not configured")
		decision.ReceiptError = err.Error()
		return decision, err
	}
	rec := wal.Record{
		Project:             privateReceiptIdentifier(req.Project),
		Provider:            "_preflight",
		Model:               "preflight",
		PromptHash:          privacy.FingerprintString(req.Action + "|" + req.Target + "|" + strings.Join(decision.EvidenceHashes, ",")),
		StatusCode:          200,
		SessionID:           privateReceiptIdentifier(req.SessionID),
		ToolSignature:       safeReceiptIdentifier(req.Action),
		ArgsFingerprint:     decision.IdempotencyKeyHash,
		DecisionStage:       "preflight",
		LoopAction:          decision.Decision,
		LoopConfidence:      float64(decision.RiskScore) / 100,
		TrajectoryID:        privateReceiptIdentifier(req.SessionID),
		DetectorVersion:     "preflight",
		PolicyVersion:       decision.PolicyVersion,
		Framework:           "unknown",
		ImmediateOutcome:    ImmediateOutcome(decision.Decision),
		DecisionID:          decision.DecisionID,
		AgentID:             privateReceiptIdentifier(req.Actor),
		UserID:              privateReceiptIdentifier(req.HumanDelegator),
		ActionRisk:          decision.RiskClass,
		IdempotencyKeyHash:  decision.IdempotencyKeyHash,
		ResourceFingerprint: decision.TargetFingerprint,
		DecisionReason:      safeReceiptText(decision.Reason),
		DecisionEvidence:    safeDecisionEvidence(decision.Evidence),
		Actor:               privateReceiptIdentifier(req.Actor),
		HumanDelegator:      privateReceiptIdentifier(req.HumanDelegator),
		Action:              safeReceiptIdentifier(req.Action),
		Target:              privateReceiptIdentifier(req.Target),
		Environment:         safeReceiptIdentifier(req.Environment),
		IntentHash:          decision.IntentHash,
		EvidenceHashes:      decision.EvidenceHashes,
		BlastRadius:         decision.BlastRadius,
		RiskScore:           decision.RiskScore,
		Decision:            decision.Decision,
		RequiredApprovers:   safeReceiptIdentifiers(decision.RequiredApprovers),
		Approvals:           safeReceiptIdentifiers(decision.Approvals),
	}

	var sign wal.SignRecordFunc
	if w.signer != nil {
		sign = w.signer.SignRecord
	} else if decision.Decision == action.DecisionBlock {
		decision.ReceiptError = "receipt signer is not set; wrote unsigned block receipt"
	}

	if err := w.walWriter.WriteSigned(rec, sign); err != nil {
		decision.ReceiptError = err.Error()
		return decision, err
	}
	return decision, nil
}

func (w *Writer) Close() error {
	if w == nil || w.walWriter == nil {
		return nil
	}
	return w.walWriter.Close()
}

func signerFromOptions(opts Options) receipts.ReceiptSigner {
	if opts.ReceiptSigner != nil {
		return opts.ReceiptSigner
	}
	if opts.ReceiptSecret != "" {
		return receipts.NewLocalSecretSigner(opts.ReceiptKeyID, []byte(opts.ReceiptSecret))
	}
	return nil
}

func ImmediateOutcome(decision string) string {
	switch decision {
	case action.DecisionBlock:
		return "blocked"
	case action.DecisionRequireApproval:
		return "needs_review"
	case action.DecisionAllow:
		return "allowed"
	default:
		return fmt.Sprintf("decision:%s", decision)
	}
}

var safeEvidenceKeys = map[string]struct{}{
	"action_risk":                  {},
	"approval_id":                  {},
	"approval_source":              {},
	"approval_status":              {},
	"claim":                        {},
	"codeowner_fingerprint":        {},
	"codeowners":                   {},
	"deploy_action":                {},
	"deploy_artifact_hash":         {},
	"deploy_environment":           {},
	"deploy_idempotency":           {},
	"deletion_protection_disabled": {},
	"duplicate_window":             {},
	"file_fingerprint":             {},
	"force_destroy_enabled":        {},
	"github_event":                 {},
	"github_file_fingerprint":      {},
	"github_file_status":           {},
	"github_head_sha_fingerprint":  {},
	"github_linked_ticket":         {},
	"github_pr_fingerprint":        {},
	"github_pr_number":             {},
	"github_repo_fingerprint":      {},
	"iam_wildcard_policy":          {},
	"idempotency_key":              {},
	"ledger_error":                 {},
	"lease":                        {},
	"mass_destroy_count":           {},
	"migration_contains":           {},
	"protected_resource":           {},
	"public_ingress":               {},
	"resource_fingerprint":         {},
	"resource_type":                {},
	"reviewer_fingerprint":         {},
	"s3_public_access":             {},
	"s3_versioning_disabled":       {},
	"service_fingerprint":          {},
	"service_risk":                 {},
	"skip_final_snapshot_enabled":  {},
	"source":                       {},
	"storage_shrink":               {},
	"terraform_action":             {},
}

func safeDecisionEvidence(evidence []string) string {
	var out []string
	seen := map[string]struct{}{}
	for _, item := range evidence {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		safe := safeEvidenceItem(item)
		if safe == "" {
			continue
		}
		if _, ok := seen[safe]; ok {
			continue
		}
		seen[safe] = struct{}{}
		out = append(out, safe)
	}
	return strings.Join(out, "; ")
}

func safeEvidenceItem(item string) string {
	key, value, ok := strings.Cut(item, "=")
	if !ok {
		return "evidence_fingerprint=" + privacy.FingerprintString(item)
	}
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	if _, ok := safeEvidenceKeys[key]; ok && isSafeEvidenceValue(value) {
		return key + "=" + value
	}
	return "evidence_fingerprint=" + privacy.FingerprintString(item)
}

func isSafeEvidenceValue(value string) bool {
	if value == "" || len(value) > 160 || privacy.ContainsSensitiveText(value) {
		return false
	}
	if privacy.IsFingerprint(value) || privacy.IsSafeLabel(value) {
		return true
	}
	return hasOnlySafeIdentifierChars(value)
}

func safeReceiptIdentifiers(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		safe := safeReceiptIdentifier(value)
		if safe != "" {
			out = append(out, safe)
		}
	}
	return out
}

func safeReceiptIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) > 160 || privacy.ContainsSensitiveText(value) || !hasOnlySafeIdentifierChars(value) || hasUnsafeAtSign(value) {
		return fingerprintMarker(value)
	}
	return value
}

func privateReceiptIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "fingerprint:sha256:") || privacy.IsFingerprint(value) {
		return value
	}
	return fingerprintMarker(value)
}

func safeReceiptText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) > 512 || privacy.ContainsSensitiveText(value) || containsLineBreakOrControl(value) {
		return fingerprintMarker(value)
	}
	return value
}

func hasOnlySafeIdentifierChars(value string) bool {
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == ':' || r == '/' || r == '#' || r == '-' || r == '@':
		default:
			return false
		}
	}
	return true
}

func hasUnsafeAtSign(value string) bool {
	at := strings.IndexByte(value, '@')
	return at > 0
}

func containsLineBreakOrControl(value string) bool {
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func fingerprintMarker(value string) string {
	return "fingerprint:" + privacy.FingerprintString(value)
}
