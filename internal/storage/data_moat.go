package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/hubbleops/hubbleops/internal/privacy"
)

var (
	ErrDuplicateDecisionID = errors.New("duplicate decision_id")
	ErrNotFound            = errors.New("not found")
	ErrRawSensitiveData    = errors.New("raw sensitive data is not allowed in data moat records")
)

type moatDB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type MoatStore struct {
	db moatDB
}

func NewMoatStore(db moatDB) *MoatStore {
	return &MoatStore{db: db}
}

type ActionDecisionOutcome struct {
	ID                     int64
	Project                string
	SessionID              string
	TrajectoryID           string
	DecisionID             string
	ReceiptID              string
	ActionName             string
	ActionType             string
	ActionRisk             string
	ToolSignatureHash      string
	IdempotencyKeyHash     string
	ResourceFingerprint    string
	ArgsFingerprint        string
	ResultFingerprint      string
	ResultClass            string
	StateDeltaHash         string
	HubbleOpsAction          string
	DecisionReason         string
	EvidenceJSON           []byte
	PolicyVersion          string
	DetectorVersion        string
	EstimatedCostUSD       *float64
	EstimatedRiskPrevented *float64
	// Semantic capture fields. These are low-cardinality categories captured at
	// decision time because they cannot be reconstructed later from fingerprints.
	// Empty means "not captured"; otherwise they must be canonical taxonomy values.
	Environment   string
	RecipientType string
	OperationType string
	CreatedAt     time.Time
}

type ActionDecisionReview struct {
	ID                    int64
	Project               string
	DecisionID            string
	Label                 string
	ReviewerSource        string
	ReviewerRole          string
	NotesFingerprint      string
	NotesRaw              string
	PolicyChangeSuggested bool
	ReviewedAt            time.Time
}

type ActionDecisionOutcomeExport struct {
	Outcome     ActionDecisionOutcome
	ReviewLabel string
}

type PolicyLearningEvent struct {
	ID               int64
	Project          string
	SourceDecisionID string
	ToolTemplate     string
	OldPolicyHash    string
	NewPolicyHash    string
	ChangeType       string
	Reason           string
	CreatedAt        time.Time
}

func (s *MoatStore) InsertActionDecisionOutcome(ctx context.Context, outcome ActionDecisionOutcome) (ActionDecisionOutcome, error) {
	if s == nil || s.db == nil {
		return outcome, fmt.Errorf("moat store db unavailable")
	}
	if err := validateOutcome(outcome); err != nil {
		return outcome, err
	}
	evidence := outcome.EvidenceJSON
	if len(evidence) == 0 {
		evidence = []byte("[]")
	}

	err := s.db.QueryRow(ctx, `
INSERT INTO action_decision_outcomes (
    project, session_id, trajectory_id, decision_id, receipt_id,
    action_name, action_type, action_risk, tool_signature_hash,
    idempotency_key_hash, resource_fingerprint, args_fingerprint,
    result_fingerprint, result_class, state_delta_hash, hubbleops_action,
    decision_reason, evidence_json, policy_version, detector_version,
    estimated_cost_usd, estimated_risk_prevented,
    environment, recipient_type, operation_type
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8, $9,
    $10, $11, $12,
    $13, $14, $15, $16,
    $17, $18::jsonb, $19, $20,
    $21, $22,
    $23, $24, $25
) RETURNING id, created_at`,
		outcome.Project,
		outcome.SessionID,
		nullableString(outcome.TrajectoryID),
		outcome.DecisionID,
		nullableString(outcome.ReceiptID),
		outcome.ActionName,
		outcome.ActionType,
		outcome.ActionRisk,
		nullableString(outcome.ToolSignatureHash),
		nullableString(outcome.IdempotencyKeyHash),
		nullableString(outcome.ResourceFingerprint),
		nullableString(outcome.ArgsFingerprint),
		nullableString(outcome.ResultFingerprint),
		outcome.ResultClass,
		nullableString(outcome.StateDeltaHash),
		outcome.HubbleOpsAction,
		outcome.DecisionReason,
		evidence,
		outcome.PolicyVersion,
		outcome.DetectorVersion,
		nullableFloat(outcome.EstimatedCostUSD),
		nullableFloat(outcome.EstimatedRiskPrevented),
		nullableString(outcome.Environment),
		nullableString(outcome.RecipientType),
		nullableString(outcome.OperationType),
	).Scan(&outcome.ID, &outcome.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return outcome, ErrDuplicateDecisionID
		}
		return outcome, fmt.Errorf("insert action decision outcome: %w", err)
	}
	outcome.EvidenceJSON = evidence
	return outcome, nil
}

func (s *MoatStore) GetActionDecisionOutcome(ctx context.Context, project, decisionID string) (ActionDecisionOutcome, error) {
	var outcome ActionDecisionOutcome
	if s == nil || s.db == nil {
		return outcome, fmt.Errorf("moat store db unavailable")
	}
	if strings.TrimSpace(project) == "" || strings.TrimSpace(decisionID) == "" {
		return outcome, fmt.Errorf("project and decision_id are required")
	}
	row := s.db.QueryRow(ctx, selectOutcomeSQL()+` WHERE project = $1 AND decision_id = $2`, project, decisionID)
	if err := scanOutcome(row, &outcome); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return outcome, ErrNotFound
		}
		return outcome, fmt.Errorf("get action decision outcome: %w", err)
	}
	return outcome, nil
}

func (s *MoatStore) GetActionDecisionOutcomeByDecisionID(ctx context.Context, decisionID string) (ActionDecisionOutcome, error) {
	var outcome ActionDecisionOutcome
	if s == nil || s.db == nil {
		return outcome, fmt.Errorf("moat store db unavailable")
	}
	if strings.TrimSpace(decisionID) == "" {
		return outcome, fmt.Errorf("decision_id is required")
	}
	row := s.db.QueryRow(ctx, selectOutcomeSQL()+` WHERE decision_id = $1`, decisionID)
	if err := scanOutcome(row, &outcome); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return outcome, ErrNotFound
		}
		return outcome, fmt.Errorf("get action decision outcome by decision_id: %w", err)
	}
	return outcome, nil
}

func (s *MoatStore) AddActionDecisionReview(ctx context.Context, review ActionDecisionReview) (ActionDecisionReview, error) {
	if s == nil || s.db == nil {
		return review, fmt.Errorf("moat store db unavailable")
	}
	if err := validateReview(review); err != nil {
		return review, err
	}
	if review.ReviewedAt.IsZero() {
		review.ReviewedAt = time.Now().UTC()
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO action_decision_reviews (
    project, decision_id, label, reviewer_source, reviewer_role,
    notes_fingerprint, notes_raw, policy_change_suggested, reviewed_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, reviewed_at`,
		review.Project,
		review.DecisionID,
		review.Label,
		review.ReviewerSource,
		nullableString(review.ReviewerRole),
		nullableString(review.NotesFingerprint),
		nullableString(review.NotesRaw),
		review.PolicyChangeSuggested,
		review.ReviewedAt,
	).Scan(&review.ID, &review.ReviewedAt)
	if err != nil {
		return review, fmt.Errorf("add action decision review: %w", err)
	}
	return review, nil
}

func (s *MoatStore) ListUnreviewedDecisions(ctx context.Context, project string, limit int) ([]ActionDecisionOutcome, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("moat store db unavailable")
	}
	if strings.TrimSpace(project) == "" {
		return nil, fmt.Errorf("project is required")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(ctx, selectOutcomeSQL()+`
 WHERE project = $1
   AND NOT EXISTS (
       SELECT 1 FROM action_decision_reviews r
       WHERE r.project = action_decision_outcomes.project
         AND r.decision_id = action_decision_outcomes.decision_id
   )
 ORDER BY created_at DESC
 LIMIT $2`, project, limit)
	if err != nil {
		return nil, fmt.Errorf("list unreviewed decisions: %w", err)
	}
	defer rows.Close()

	var out []ActionDecisionOutcome
	for rows.Next() {
		var outcome ActionDecisionOutcome
		if err := scanOutcome(rows, &outcome); err != nil {
			return nil, fmt.Errorf("scan unreviewed decision: %w", err)
		}
		out = append(out, outcome)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unreviewed decisions: %w", err)
	}
	return out, nil
}

func (s *MoatStore) CountUnreviewedDecisions(ctx context.Context) (int, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("moat store db unavailable")
	}
	var count int64
	err := s.db.QueryRow(ctx, `
SELECT COUNT(*)
FROM action_decision_outcomes o
WHERE NOT EXISTS (
    SELECT 1 FROM action_decision_reviews r
    WHERE r.project = o.project
      AND r.decision_id = o.decision_id
)`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count unreviewed decisions: %w", err)
	}
	return int(count), nil
}

func (s *MoatStore) ListActionDecisionOutcomesForExport(ctx context.Context, project string, since time.Time, reviewedOnly bool) ([]ActionDecisionOutcomeExport, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("moat store db unavailable")
	}
	if strings.TrimSpace(project) == "" {
		return nil, fmt.Errorf("project is required")
	}
	if since.IsZero() {
		return nil, fmt.Errorf("since is required")
	}
	rows, err := s.db.Query(ctx, `
SELECT
    o.id, o.project, o.session_id, o.trajectory_id, o.decision_id, o.receipt_id,
    o.action_name, o.action_type, o.action_risk, o.tool_signature_hash,
    o.idempotency_key_hash, o.resource_fingerprint, o.args_fingerprint,
    o.result_fingerprint, o.result_class, o.state_delta_hash, o.hubbleops_action,
    o.decision_reason, o.evidence_json, o.policy_version, o.detector_version,
    o.estimated_cost_usd, o.estimated_risk_prevented,
    o.environment, o.recipient_type, o.operation_type, o.created_at,
    latest_review.label
FROM action_decision_outcomes o
LEFT JOIN LATERAL (
    SELECT r.label
    FROM action_decision_reviews r
    WHERE r.project = o.project
      AND r.decision_id = o.decision_id
    ORDER BY r.reviewed_at DESC, r.id DESC
    LIMIT 1
) latest_review ON TRUE
WHERE o.project = $1
  AND o.created_at >= $2
  AND ($3::boolean = FALSE OR latest_review.label IS NOT NULL)
ORDER BY o.created_at ASC, o.id ASC`, project, since, reviewedOnly)
	if err != nil {
		return nil, fmt.Errorf("list action decision outcomes for export: %w", err)
	}
	defer rows.Close()

	var out []ActionDecisionOutcomeExport
	for rows.Next() {
		var item ActionDecisionOutcomeExport
		if err := scanExportOutcome(rows, &item); err != nil {
			return nil, fmt.Errorf("scan action decision outcome export: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate action decision outcome exports: %w", err)
	}
	return out, nil
}

func (s *MoatStore) InsertPolicyLearningEvent(ctx context.Context, event PolicyLearningEvent) (PolicyLearningEvent, error) {
	if s == nil || s.db == nil {
		return event, fmt.Errorf("moat store db unavailable")
	}
	if err := validatePolicyLearningEvent(event); err != nil {
		return event, err
	}
	err := s.db.QueryRow(ctx, `
INSERT INTO policy_learning_events (
    project, source_decision_id, tool_template, old_policy_hash,
    new_policy_hash, change_type, reason
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, created_at`,
		event.Project,
		event.SourceDecisionID,
		nullableString(event.ToolTemplate),
		nullableString(event.OldPolicyHash),
		nullableString(event.NewPolicyHash),
		event.ChangeType,
		event.Reason,
	).Scan(&event.ID, &event.CreatedAt)
	if err != nil {
		return event, fmt.Errorf("insert policy learning event: %w", err)
	}
	return event, nil
}

func validateOutcome(outcome ActionDecisionOutcome) error {
	required := map[string]string{
		"project":          outcome.Project,
		"session_id":       outcome.SessionID,
		"decision_id":      outcome.DecisionID,
		"action_name":      outcome.ActionName,
		"action_type":      outcome.ActionType,
		"action_risk":      outcome.ActionRisk,
		"hubbleops_action":   outcome.HubbleOpsAction,
		"policy_version":   outcome.PolicyVersion,
		"detector_version": outcome.DetectorVersion,
	}
	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", field)
		}
	}
	if !allowedValue(outcome.HubbleOpsAction, []string{"allow", "shadow", "warn", "block"}) {
		return fmt.Errorf("invalid hubbleops_action %q", outcome.HubbleOpsAction)
	}
	if err := validateSemanticField("environment", outcome.Environment, []string{"production", "staging", "development", "test", "unknown"}); err != nil {
		return err
	}
	if err := validateSemanticField("recipient_type", outcome.RecipientType, []string{"internal", "external_customer", "external_vendor", "self", "none", "unknown"}); err != nil {
		return err
	}
	if err := validateSemanticField("operation_type", outcome.OperationType, []string{"create", "read", "update", "delete", "send", "execute", "unknown"}); err != nil {
		return err
	}
	if err := validateEvidenceJSON(outcome.EvidenceJSON); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"tool_signature_hash":  outcome.ToolSignatureHash,
		"idempotency_key_hash": outcome.IdempotencyKeyHash,
		"resource_fingerprint": outcome.ResourceFingerprint,
		"args_fingerprint":     outcome.ArgsFingerprint,
		"result_fingerprint":   outcome.ResultFingerprint,
		"state_delta_hash":     outcome.StateDeltaHash,
	} {
		if err := validateFingerprint(name, value); err != nil {
			return err
		}
	}
	return nil
}

func validateReview(review ActionDecisionReview) error {
	if strings.TrimSpace(review.Project) == "" {
		return fmt.Errorf("project is required")
	}
	if strings.TrimSpace(review.DecisionID) == "" {
		return fmt.Errorf("decision_id is required")
	}
	if !allowedValue(review.Label, []string{"true_positive", "false_positive", "benign_retry", "needs_review", "unsafe_but_allowed", "missed_runaway"}) {
		return fmt.Errorf("invalid review label %q", review.Label)
	}
	if !allowedValue(review.ReviewerSource, []string{"human", "api", "import", "system"}) {
		return fmt.Errorf("invalid reviewer_source %q", review.ReviewerSource)
	}
	if strings.TrimSpace(review.ReviewerRole) != "" && !allowedValue(review.ReviewerRole, []string{"developer", "sre", "security", "founder", "unknown"}) {
		return fmt.Errorf("invalid reviewer_role %q", review.ReviewerRole)
	}
	if err := validateFingerprint("notes_fingerprint", review.NotesFingerprint); err != nil {
		return err
	}
	return nil
}

func validatePolicyLearningEvent(event PolicyLearningEvent) error {
	if strings.TrimSpace(event.Project) == "" {
		return fmt.Errorf("project is required")
	}
	if strings.TrimSpace(event.SourceDecisionID) == "" {
		return fmt.Errorf("source_decision_id is required")
	}
	if !allowedValue(event.ChangeType, []string{"threshold_change", "idempotency_key_change", "risk_reclass", "allowlist", "blocklist", "duplicate_window_change"}) {
		return fmt.Errorf("invalid change_type %q", event.ChangeType)
	}
	for name, value := range map[string]string{
		"old_policy_hash": event.OldPolicyHash,
		"new_policy_hash": event.NewPolicyHash,
	} {
		if err := validateFingerprint(name, value); err != nil {
			return err
		}
	}
	return nil
}

// validateSemanticField enforces that low-cardinality category fields are either
// empty (not captured) or one of the canonical taxonomy values. This keeps the
// column queryable and prevents raw free-text from leaking into the moat dataset.
func validateSemanticField(name, value string, allowed []string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if !allowedValue(value, allowed) {
		return fmt.Errorf("invalid %s %q", name, value)
	}
	return nil
}

func validateFingerprint(name, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.ContainsAny(value, "{}[]\"' \n\r\t@") {
		return fmt.Errorf("%w: %s must be a hash/fingerprint, not raw content", ErrRawSensitiveData, name)
	}
	if !privacy.IsFingerprint(value) {
		return fmt.Errorf("%w: %s must use sha256:<64hex>, <16+hex>, fp:<value>, or hash:<value>", ErrRawSensitiveData, name)
	}
	return nil
}

func validateEvidenceJSON(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	if !json.Valid(raw) {
		return fmt.Errorf("evidence_json must be valid JSON")
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("parse evidence_json: %w", err)
	}
	return rejectRawEvidenceKeys(parsed)
}

func rejectRawEvidenceKeys(value any) error {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			if err := rejectRawEvidenceKeys(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, child := range typed {
			if privacy.IsRawSensitiveKey(key) {
				return fmt.Errorf("%w: evidence_json contains raw-sensitive key %q", ErrRawSensitiveData, key)
			}
			if err := rejectRawEvidenceKeys(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func allowedValue(value string, allowed []string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullableFloat(value *float64) any {
	if value == nil {
		return nil
	}
	return *value
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

type rowScanner interface {
	Scan(dest ...any) error
}

func selectOutcomeSQL() string {
	return `SELECT
    id, project, session_id, trajectory_id, decision_id, receipt_id,
    action_name, action_type, action_risk, tool_signature_hash,
    idempotency_key_hash, resource_fingerprint, args_fingerprint,
    result_fingerprint, result_class, state_delta_hash, hubbleops_action,
    decision_reason, evidence_json, policy_version, detector_version,
    estimated_cost_usd, estimated_risk_prevented,
    environment, recipient_type, operation_type, created_at
FROM action_decision_outcomes`
}

func scanOutcome(row rowScanner, outcome *ActionDecisionOutcome) error {
	var trajectoryID, receiptID, toolSignatureHash, idempotencyKeyHash sql.NullString
	var resourceFingerprint, argsFingerprint, resultFingerprint, stateDeltaHash sql.NullString
	var environment, recipientType, operationType sql.NullString
	var estimatedCost, estimatedRisk sql.NullFloat64
	if err := row.Scan(
		&outcome.ID,
		&outcome.Project,
		&outcome.SessionID,
		&trajectoryID,
		&outcome.DecisionID,
		&receiptID,
		&outcome.ActionName,
		&outcome.ActionType,
		&outcome.ActionRisk,
		&toolSignatureHash,
		&idempotencyKeyHash,
		&resourceFingerprint,
		&argsFingerprint,
		&resultFingerprint,
		&outcome.ResultClass,
		&stateDeltaHash,
		&outcome.HubbleOpsAction,
		&outcome.DecisionReason,
		&outcome.EvidenceJSON,
		&outcome.PolicyVersion,
		&outcome.DetectorVersion,
		&estimatedCost,
		&estimatedRisk,
		&environment,
		&recipientType,
		&operationType,
		&outcome.CreatedAt,
	); err != nil {
		return err
	}
	outcome.TrajectoryID = trajectoryID.String
	outcome.ReceiptID = receiptID.String
	outcome.ToolSignatureHash = toolSignatureHash.String
	outcome.IdempotencyKeyHash = idempotencyKeyHash.String
	outcome.ResourceFingerprint = resourceFingerprint.String
	outcome.ArgsFingerprint = argsFingerprint.String
	outcome.ResultFingerprint = resultFingerprint.String
	outcome.StateDeltaHash = stateDeltaHash.String
	outcome.Environment = environment.String
	outcome.RecipientType = recipientType.String
	outcome.OperationType = operationType.String
	if estimatedCost.Valid {
		outcome.EstimatedCostUSD = &estimatedCost.Float64
	}
	if estimatedRisk.Valid {
		outcome.EstimatedRiskPrevented = &estimatedRisk.Float64
	}
	return nil
}

func scanExportOutcome(row rowScanner, item *ActionDecisionOutcomeExport) error {
	var trajectoryID, receiptID, toolSignatureHash, idempotencyKeyHash sql.NullString
	var resourceFingerprint, argsFingerprint, resultFingerprint, stateDeltaHash sql.NullString
	var environment, recipientType, operationType sql.NullString
	var estimatedCost, estimatedRisk sql.NullFloat64
	var reviewLabel sql.NullString
	outcome := &item.Outcome
	if err := row.Scan(
		&outcome.ID,
		&outcome.Project,
		&outcome.SessionID,
		&trajectoryID,
		&outcome.DecisionID,
		&receiptID,
		&outcome.ActionName,
		&outcome.ActionType,
		&outcome.ActionRisk,
		&toolSignatureHash,
		&idempotencyKeyHash,
		&resourceFingerprint,
		&argsFingerprint,
		&resultFingerprint,
		&outcome.ResultClass,
		&stateDeltaHash,
		&outcome.HubbleOpsAction,
		&outcome.DecisionReason,
		&outcome.EvidenceJSON,
		&outcome.PolicyVersion,
		&outcome.DetectorVersion,
		&estimatedCost,
		&estimatedRisk,
		&environment,
		&recipientType,
		&operationType,
		&outcome.CreatedAt,
		&reviewLabel,
	); err != nil {
		return err
	}
	outcome.TrajectoryID = trajectoryID.String
	outcome.ReceiptID = receiptID.String
	outcome.ToolSignatureHash = toolSignatureHash.String
	outcome.IdempotencyKeyHash = idempotencyKeyHash.String
	outcome.ResourceFingerprint = resourceFingerprint.String
	outcome.ArgsFingerprint = argsFingerprint.String
	outcome.ResultFingerprint = resultFingerprint.String
	outcome.StateDeltaHash = stateDeltaHash.String
	outcome.Environment = environment.String
	outcome.RecipientType = recipientType.String
	outcome.OperationType = operationType.String
	if estimatedCost.Valid {
		outcome.EstimatedCostUSD = &estimatedCost.Float64
	}
	if estimatedRisk.Valid {
		outcome.EstimatedRiskPrevented = &estimatedRisk.Float64
	}
	item.ReviewLabel = reviewLabel.String
	return nil
}
