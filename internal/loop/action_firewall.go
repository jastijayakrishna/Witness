package loop

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	ActionPolicyVersion = "action-firewall/2"

	ActionRiskRead      = "read"
	ActionRiskWrite     = "write"
	ActionRiskDangerous = "dangerous"

	SignalDuplicateSideEffect       = "duplicate_side_effect"
	SignalMissingIdempotency        = "missing_idempotency_key"
	SignalPolicyAmountExceeded      = "policy_amount_exceeded"
	SignalMissingSafetyPrecondition = "missing_safety_precondition"
	SignalRecipientOutOfPolicy      = "recipient_out_of_policy"
	SignalInvalidCapability         = "invalid_capability"
)

const defaultDuplicateWindow = 24 * time.Hour

type ActionStore struct {
	ledger           actionLedger
	capabilitySecret []byte
}

func NewActionStore(rdb *redis.Client) *ActionStore {
	return &ActionStore{ledger: redisActionLedger{rdb: rdb}}
}

func NewPostgresActionStore(pool *pgxpool.Pool) *ActionStore {
	return &ActionStore{ledger: postgresActionLedger{pool: pool}}
}

func NewMemoryActionStore() *ActionStore {
	return &ActionStore{ledger: newMemoryActionLedger()}
}

type ActionObservation struct {
	Project                string
	SessionID              string
	StepID                 string
	ToolName               string
	ActionRisk             string
	IdempotencyKey         string
	AgentID                string
	UserID                 string
	ResourceID             string
	AmountCents            int64
	MaxAmountCents         int64
	BackupID               string
	Recipient              string
	AllowedDomain          string
	CapabilityToken        string
	DuplicateWindowSeconds int
	UnixMillis             int64
}

type ActionDecision struct {
	Decision Decision
	Reason   string
	Evidence []string
}

func (as *ActionStore) Decide(ctx context.Context, obs ActionObservation) (ActionDecision, error) {
	if as == nil || as.ledger == nil {
		return ActionDecision{}, fmt.Errorf("action ledger is not configured")
	}
	risk := NormalizeActionRisk(obs.ActionRisk)
	decisionTime := actionTime(obs.UnixMillis)
	capabilityVerified := false
	var cap Capability
	if obs.CapabilityToken != "" {
		verified, err := VerifyCapability(as.capabilitySecret, obs.CapabilityToken, obs, decisionTime)
		if err != nil {
			return blockActionDecision(
				SignalInvalidCapability,
				"capability token is invalid or outside its scope",
				[]string{"capability=invalid", "reason=" + err.Error()},
				0.98,
				obs.SessionID,
			), nil
		}
		capabilityVerified = true
		cap = verified
	}
	if decision, ok := enforceAmountPolicy(obs, cap, capabilityVerified); ok {
		return decision, nil
	}
	if decision, ok := enforceRecipientPolicy(obs); ok {
		return decision, nil
	}
	if risk == ActionRiskRead {
		return ActionDecision{Decision: allowActionDecision("no idempotency policy fired", obs.SessionID)}, nil
	}
	if obs.IdempotencyKey == "" {
		action := ActionWarn
		confidence := 0.60
		reason := "side-effect action is missing an idempotency key"
		if risk == ActionRiskDangerous {
			action = ActionBlock
			confidence = 0.85
			reason = "dangerous action is missing an idempotency key"
		}
		evidence := []string{"action_risk=" + risk, "idempotency_key=missing"}
		return ActionDecision{
			Decision: Decision{
				SignalsFired:     []string{SignalMissingIdempotency},
				Confidence:       confidence,
				ActionCeiling:    action,
				DetectorVersion:  DetectorVersion,
				Reason:           reason,
				HadSession:       obs.SessionID != "",
				PolicyVersion:    ActionPolicyVersion,
				DecisionEvidence: evidence,
			},
			Reason:   reason,
			Evidence: evidence,
		}, nil
	}
	if risk == ActionRiskDangerous && obs.BackupID == "" && !capabilityVerified {
		return blockActionDecision(
			SignalMissingSafetyPrecondition,
			"dangerous action requires a backup_id or a valid scoped capability",
			[]string{"action_risk=" + risk, "backup_id=missing", "capability=missing"},
			0.95,
			obs.SessionID,
		), nil
	}

	window := duplicateWindow(obs.DuplicateWindowSeconds)
	key := actionKey(obs.Project, obs.IdempotencyKey)
	nowMillis := obs.UnixMillis
	if nowMillis == 0 {
		nowMillis = time.Now().UnixMilli()
	}
	record := map[string]any{
		"project":         obs.Project,
		"session_id":      obs.SessionID,
		"tool_name":       obs.ToolName,
		"action_risk":     risk,
		"idempotency_key": obs.IdempotencyKey,
		"agent_id":        obs.AgentID,
		"user_id":         obs.UserID,
		"resource_id":     obs.ResourceID,
		"amount_cents":    obs.AmountCents,
		"step_id":         obs.StepID,
		"first_seen_ms":   nowMillis,
	}
	data, _ := json.Marshal(record)
	claimed, previous, err := as.ledger.Claim(ctx, key, data, window)
	if err != nil {
		return ActionDecision{}, fmt.Errorf("claim action idempotency: %w", err)
	}
	if claimed {
		evidence := []string{"idempotency_key=first_seen", "duplicate_window=" + window.String()}
		if capabilityVerified {
			evidence = append(evidence, "capability=valid")
		}
		if obs.ResourceID != "" {
			evidence = append(evidence, "resource_id="+obs.ResourceID)
		}
		return ActionDecision{
			Decision: Decision{
				ActionCeiling:    ActionNone,
				DetectorVersion:  DetectorVersion,
				Reason:           "first action with this idempotency key",
				HadSession:       obs.SessionID != "",
				PolicyVersion:    ActionPolicyVersion,
				DecisionEvidence: evidence,
			},
			Reason:   "first action with this idempotency key",
			Evidence: evidence,
		}, nil
	}

	evidence := []string{
		"idempotency_key=repeated",
		"action_risk=" + risk,
		"duplicate_window=" + window.String(),
	}
	if previous != "" {
		evidence = append(evidence, "previous_action="+summarizeActionRecord(previous))
	}
	reason := "duplicate side-effect blocked: idempotency key was already seen"
	return ActionDecision{
		Decision: Decision{
			SignalsFired:     []string{SignalDuplicateSideEffect},
			Confidence:       1.0,
			ActionCeiling:    ActionBlock,
			DetectorVersion:  DetectorVersion,
			Reason:           reason,
			HadSession:       obs.SessionID != "",
			PolicyVersion:    ActionPolicyVersion,
			DecisionEvidence: evidence,
		},
		Reason:   reason,
		Evidence: evidence,
	}, nil
}

func enforceAmountPolicy(obs ActionObservation, cap Capability, capabilityVerified bool) (ActionDecision, bool) {
	if obs.AmountCents <= 0 {
		return ActionDecision{}, false
	}
	if obs.MaxAmountCents > 0 && obs.AmountCents > obs.MaxAmountCents {
		return blockActionDecision(
			SignalPolicyAmountExceeded,
			"action amount exceeds declared policy maximum",
			[]string{
				fmt.Sprintf("amount_cents=%d", obs.AmountCents),
				fmt.Sprintf("max_amount_cents=%d", obs.MaxAmountCents),
			},
			0.99,
			obs.SessionID,
		), true
	}
	if capabilityVerified && cap.MaxAmountCents > 0 && obs.AmountCents > cap.MaxAmountCents {
		return blockActionDecision(
			SignalPolicyAmountExceeded,
			"action amount exceeds capability maximum",
			[]string{
				fmt.Sprintf("amount_cents=%d", obs.AmountCents),
				fmt.Sprintf("capability_max_amount_cents=%d", cap.MaxAmountCents),
			},
			0.99,
			obs.SessionID,
		), true
	}
	return ActionDecision{}, false
}

func enforceRecipientPolicy(obs ActionObservation) (ActionDecision, bool) {
	if obs.Recipient == "" || obs.AllowedDomain == "" {
		return ActionDecision{}, false
	}
	recipientDomain := emailDomain(obs.Recipient)
	allowedDomain := strings.ToLower(strings.TrimSpace(obs.AllowedDomain))
	if recipientDomain == "" || !strings.EqualFold(recipientDomain, allowedDomain) {
		return blockActionDecision(
			SignalRecipientOutOfPolicy,
			"recipient is outside the declared allowed domain",
			[]string{"recipient_domain=" + firstNonEmptyString(recipientDomain, "invalid"), "allowed_domain=" + allowedDomain},
			0.96,
			obs.SessionID,
		), true
	}
	return ActionDecision{}, false
}

func blockActionDecision(signal, reason string, evidence []string, confidence float64, sessionID string) ActionDecision {
	return ActionDecision{
		Decision: Decision{
			SignalsFired:     []string{signal},
			Confidence:       confidence,
			ActionCeiling:    ActionBlock,
			DetectorVersion:  DetectorVersion,
			Reason:           reason,
			HadSession:       sessionID != "",
			PolicyVersion:    ActionPolicyVersion,
			DecisionEvidence: evidence,
		},
		Reason:   reason,
		Evidence: evidence,
	}
}

func (as *ActionStore) WithCapabilitySecret(secret string) *ActionStore {
	if as == nil {
		return nil
	}
	secret = strings.TrimSpace(secret)
	if secret != "" {
		as.capabilitySecret = []byte(secret)
	}
	return as
}

func actionTime(unixMillis int64) time.Time {
	if unixMillis <= 0 {
		return time.Now().UTC()
	}
	return time.UnixMilli(unixMillis).UTC()
}

func emailDomain(recipient string) string {
	recipient = strings.TrimSpace(strings.ToLower(recipient))
	at := strings.LastIndex(recipient, "@")
	if at < 0 || at == len(recipient)-1 {
		return ""
	}
	return recipient[at+1:]
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func NormalizeActionRisk(risk string) string {
	risk = strings.ToLower(strings.TrimSpace(risk))
	switch risk {
	case "", "readonly", "read_only", "low":
		return ActionRiskRead
	case "side_effect", "customer_visible", "money_movement", "write", "medium", "high":
		return ActionRiskWrite
	case "danger", "dangerous", "critical", "destructive":
		return ActionRiskDangerous
	default:
		return risk
	}
}

func allowActionDecision(reason, sessionID string) Decision {
	return Decision{
		ActionCeiling:   ActionNone,
		DetectorVersion: DetectorVersion,
		Reason:          reason,
		HadSession:      sessionID != "",
		PolicyVersion:   ActionPolicyVersion,
	}
}

func duplicateWindow(seconds int) time.Duration {
	if seconds <= 0 {
		return defaultDuplicateWindow
	}
	return time.Duration(seconds) * time.Second
}

func actionKey(project, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(project + "\x00" + idempotencyKey))
	return fmt.Sprintf("action:idempotency:%x", sum[:])
}

func summarizeActionRecord(raw string) string {
	var rec map[string]any
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		if len(raw) > 120 {
			return raw[:120]
		}
		return raw
	}
	parts := []string{}
	for _, key := range []string{"tool_name", "step_id", "session_id", "first_seen_ms"} {
		if value, ok := rec[key]; ok && value != "" {
			parts = append(parts, fmt.Sprintf("%s=%v", key, value))
		}
	}
	return strings.Join(parts, ",")
}

type actionLedger interface {
	Claim(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, string, error)
}

type redisActionLedger struct {
	rdb *redis.Client
}

func (l redisActionLedger) Claim(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, string, error) {
	if l.rdb == nil {
		return false, "", fmt.Errorf("redis client is nil")
	}
	claimed, err := l.rdb.SetNX(ctx, key, value, ttl).Result()
	if err != nil {
		return false, "", err
	}
	if claimed {
		return true, "", nil
	}
	previous, err := l.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	return false, previous, nil
}

type postgresActionLedger struct {
	pool *pgxpool.Pool
}

func (l postgresActionLedger) Claim(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, string, error) {
	if l.pool == nil {
		return false, "", fmt.Errorf("postgres pool is nil")
	}
	expiresAt := time.Now().Add(ttl)
	tx, err := l.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, "", err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "DELETE FROM action_ledger WHERE action_key = $1 AND expires_at <= now()", key); err != nil {
		return false, "", err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO action_ledger (action_key, first_record, expires_at)
		VALUES ($1, $2::jsonb, $3)
		ON CONFLICT (action_key) DO NOTHING
	`, key, string(value), expiresAt)
	if err != nil {
		return false, "", err
	}
	if tag.RowsAffected() == 1 {
		if err := tx.Commit(ctx); err != nil {
			return false, "", err
		}
		return true, "", nil
	}

	var previous string
	if err := tx.QueryRow(ctx, "SELECT first_record::text FROM action_ledger WHERE action_key = $1", key).Scan(&previous); err != nil {
		return false, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, "", err
	}
	return false, previous, nil
}

type memoryActionLedger struct {
	mu    sync.Mutex
	items map[string]memoryActionItem
}

type memoryActionItem struct {
	value     string
	expiresAt time.Time
}

func newMemoryActionLedger() *memoryActionLedger {
	return &memoryActionLedger{items: make(map[string]memoryActionItem)}
}

func (l *memoryActionLedger) Claim(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, string, error) {
	select {
	case <-ctx.Done():
		return false, "", ctx.Err()
	default:
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if item, ok := l.items[key]; ok {
		if item.expiresAt.IsZero() || item.expiresAt.After(now) {
			return false, item.value, nil
		}
		delete(l.items, key)
	}
	expiresAt := time.Time{}
	if ttl > 0 {
		expiresAt = now.Add(ttl)
	}
	l.items[key] = memoryActionItem{value: string(value), expiresAt: expiresAt}
	return true, "", nil
}
