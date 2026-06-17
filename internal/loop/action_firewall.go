package loop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
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
	// ActionPolicyVersion /3 introduced the two-phase (pending-lease -> committed)
	// idempotency protocol: a side effect is claimed under a short lease before it runs
	// and only promoted to the full duplicate window once it provably committed. This is
	// duplicate *suppression* with crash-safe reconciliation, not a distributed
	// transaction — see docs.
	// /4 hardens that protocol: releases must prove lease ownership with the claim
	// nonce, the duplicate window for fail-closed risks is floored server-side, and the
	// Redis commit is a single atomic script.
	ActionPolicyVersion = "action-firewall/4"

	ActionRiskRead      = "read"
	ActionRiskWrite     = "write"
	ActionRiskDangerous = "dangerous"

	SignalDuplicateSideEffect         = "duplicate_side_effect"
	SignalIdempotencyKeyReuseMismatch = "idempotency_key_reuse_mismatch"
	SignalMissingIdempotency          = "missing_idempotency_key"
	SignalPolicyAmountExceeded        = "policy_amount_exceeded"
	SignalMissingSafetyPrecondition   = "missing_safety_precondition"
	SignalRecipientOutOfPolicy        = "recipient_out_of_policy"
	SignalInvalidCapability           = "invalid_capability"
	SignalActionFirewallUnavailable   = "action_firewall_unavailable"
	SignalActionInFlight              = "action_in_flight"

	// ActionOutcome* describe what the two-phase ledger did with a claim. They let the
	// HTTP layer tell apart a benign concurrent retry (in-flight), a committed duplicate
	// that must be replayed rather than re-executed, and a contradictory reuse.
	ActionOutcomeClaimed         = "claimed"
	ActionOutcomeInFlight        = "in_flight"
	ActionOutcomeCommittedReplay = "committed_replay"
	ActionOutcomeMismatch        = "mismatch"
)

const (
	defaultDuplicateWindow = 24 * time.Hour
	// defaultActionLease is how long a *pending* claim is held before the side effect
	// is confirmed. It must outlast a normal tool execution but stay short so that a
	// crash between claim and execution frees the key quickly: the effect provably
	// never committed, so a retry must be allowed rather than blocked for the full
	// duplicate window. Tunable per-store via WithLease.
	defaultActionLease = 2 * time.Minute
)

type ActionStore struct {
	ledger           actionLedger
	capabilitySecret []byte
	lease            time.Duration
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

// WithLease overrides the pending-claim lease duration (default 2m). A zero or
// negative value keeps the default.
func (as *ActionStore) WithLease(lease time.Duration) *ActionStore {
	if as != nil && lease > 0 {
		as.lease = lease
	}
	return as
}

func (as *ActionStore) leaseDuration() time.Duration {
	if as == nil || as.lease <= 0 {
		return defaultActionLease
	}
	return as.lease
}

type ActionObservation struct {
	Project                string
	SessionID              string
	StepID                 string
	ToolName               string
	ActionRisk             string
	// RawActionRisk is the client-declared risk label before any server-side floor was
	// applied. Fail-closed semantics (window floor, hold-on-ambiguous) key on both: the
	// raw label catches an honest "money_movement", the floored one catches a client lie.
	RawActionRisk          string
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
	// Outcome is one of ActionOutcome* for claim-stage decisions; empty for policy
	// blocks (amount/recipient/capability/missing-key) and reads. The HTTP layer uses
	// it to pick the right status: 200+replay for a committed duplicate, 409 for an
	// in-flight retry, 422 for a contradictory reuse.
	Outcome string
	// Replay carries the recorded outcome of the original committed action and is set
	// only when Outcome == ActionOutcomeCommittedReplay.
	Replay *ActionReplay
	// ClaimNonce proves ownership of the pending lease acquired by this decision. It is
	// set only when Outcome == ActionOutcomeClaimed; the result path must echo it on
	// Release so a late failure callback cannot free a lease it does not own.
	ClaimNonce string
}

// ActionReplay is the recorded result of the first, already-committed attempt for an
// idempotency key. It is what the firewall returns instead of executing a duplicate
// side effect a second time.
type ActionReplay struct {
	DecisionID        string          `json:"decision_id,omitempty"`
	ResultClass       string          `json:"result_class,omitempty"`
	ResultFingerprint string          `json:"result_fingerprint,omitempty"`
	Result            json.RawMessage `json:"result,omitempty"`
	FirstSeenMillis   int64           `json:"first_seen_millis,omitempty"`
	CommittedMillis   int64           `json:"committed_millis,omitempty"`
}

// ActionResult is the post-execution outcome the result path hands back to the ledger
// so a pending claim is promoted to committed (on success) or released (on failure).
type ActionResult struct {
	Project                string
	IdempotencyKey         string
	ToolName               string
	ActionRisk             string
	RawActionRisk          string
	ResourceID             string
	AmountCents            int64
	Recipient              string
	DecisionID             string
	ResultClass            string
	ResultFingerprint      string
	Result                 json.RawMessage
	DuplicateWindowSeconds int
	UnixMillis             int64
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

	window := duplicateWindow(obs.DuplicateWindowSeconds, firstNonEmptyString(obs.RawActionRisk, obs.ActionRisk), risk)
	lease := as.leaseDuration()
	key := actionKey(obs.Project, obs.IdempotencyKey)
	nowMillis := obs.UnixMillis
	if nowMillis == 0 {
		nowMillis = time.Now().UnixMilli()
	}
	currentFP := actionRequestFingerprint(obs, risk)
	nonce := newClaimNonce()
	record := map[string]any{
		"project":              obs.Project,
		"session_id":           obs.SessionID,
		"tool_name":            obs.ToolName,
		"action_risk":          risk,
		"idempotency_key_hash": actionValueFingerprint(obs.IdempotencyKey),
		"agent_id":             obs.AgentID,
		"user_id":              obs.UserID,
		"resource_fingerprint": actionValueFingerprint(obs.ResourceID),
		"amount_cents":         obs.AmountCents,
		"step_id":              obs.StepID,
		"first_seen_ms":        nowMillis,
		"request_fingerprint":  currentFP,
		"claim_nonce":          nonce,
	}
	data, _ := json.Marshal(record)
	// Phase 1: claim a short PENDING lease, not the full duplicate window. The window
	// is only committed once the side effect provably succeeds (ActionStore.Commit),
	// so a crash between this claim and execution frees the key when the lease expires
	// instead of silently blocking every retry for 24h.
	status, previous, err := as.ledger.Claim(ctx, key, data, lease, nonce)
	if err != nil {
		return ActionDecision{}, fmt.Errorf("claim action idempotency: %w", err)
	}
	if status == claimStatusClaimed {
		evidence := []string{"idempotency_key=first_seen", "claim=pending", "lease=" + lease.String(), "duplicate_window=" + window.String()}
		if capabilityVerified {
			evidence = append(evidence, "capability=valid")
		}
		if obs.ResourceID != "" {
			evidence = append(evidence, "resource_fingerprint="+actionValueFingerprint(obs.ResourceID))
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
			Reason:     "first action with this idempotency key",
			Evidence:   evidence,
			Outcome:    ActionOutcomeClaimed,
			ClaimNonce: nonce,
		}, nil
	}

	// An existing record is present. A reuse with a *different* payload is a client bug
	// or tampering regardless of whether the prior attempt is in-flight or committed, so
	// check that first and surface it as a contradiction (422), never a benign replay.
	var prev map[string]any
	if previous != "" {
		_ = json.Unmarshal([]byte(previous), &prev)
		if prevFP, _ := prev["request_fingerprint"].(string); prevFP != "" && prevFP != currentFP {
			d := blockActionDecision(
				SignalIdempotencyKeyReuseMismatch,
				"idempotency key reused with a different action payload",
				[]string{
					"idempotency_key=reused_with_different_payload",
					"stored_fingerprint=" + prevFP,
					"incoming_fingerprint=" + currentFP,
				},
				1.0,
				obs.SessionID,
			)
			d.Outcome = ActionOutcomeMismatch
			return d, nil
		}
	}

	if status == claimStatusInFlight {
		// The first attempt with this key is still within its pending lease — the side
		// effect may be running right now. Re-executing would risk a duplicate, so tell
		// the caller it is in flight and to retry; it is not a permanent block.
		evidence := []string{"idempotency_key=in_flight", "action_risk=" + risk, "lease=" + lease.String()}
		reason := "action with this idempotency key is already in flight; retry shortly"
		return ActionDecision{
			Decision: Decision{
				SignalsFired:     []string{SignalActionInFlight},
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
			Outcome:  ActionOutcomeInFlight,
		}, nil
	}

	// status == claimStatusCommitted: the first attempt already committed. Replay its
	// recorded outcome instead of running the side effect again.
	evidence := []string{
		"idempotency_key=committed",
		"action_risk=" + risk,
		"duplicate_window=" + window.String(),
	}
	if previous != "" {
		evidence = append(evidence, "previous_action="+summarizeActionRecord(previous))
	}
	reason := "duplicate side-effect: replaying recorded outcome of the original committed action"
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
		Outcome:  ActionOutcomeCommittedReplay,
		Replay:   replayFromRecord(prev),
	}, nil
}

// Commit promotes a pending claim to committed for the full duplicate window and records
// the result so a later duplicate can be replayed. It is called from the result path only
// for a successful side effect; a failed one calls Release instead so a retry is allowed.
func (as *ActionStore) Commit(ctx context.Context, res ActionResult) error {
	if as == nil || as.ledger == nil {
		return fmt.Errorf("action ledger is not configured")
	}
	if res.IdempotencyKey == "" {
		return nil
	}
	risk := NormalizeActionRisk(res.ActionRisk)
	window := duplicateWindow(res.DuplicateWindowSeconds, firstNonEmptyString(res.RawActionRisk, res.ActionRisk), risk)
	key := actionKey(res.Project, res.IdempotencyKey)
	nowMillis := res.UnixMillis
	if nowMillis == 0 {
		nowMillis = time.Now().UnixMilli()
	}
	record := map[string]any{
		"project":              res.Project,
		"tool_name":            res.ToolName,
		"action_risk":          risk,
		"idempotency_key_hash": actionValueFingerprint(res.IdempotencyKey),
		"resource_fingerprint": actionValueFingerprint(res.ResourceID),
		"amount_cents":         res.AmountCents,
		"committed_ms":         nowMillis,
		"request_fingerprint":  actionResultFingerprint(res, risk),
		"decision_id":          res.DecisionID,
		"result_class":         res.ResultClass,
		"result_fingerprint":   res.ResultFingerprint,
	}
	if len(res.Result) > 0 {
		record["result"] = json.RawMessage(res.Result)
	}
	data, _ := json.Marshal(record)
	return as.ledger.Commit(ctx, key, data, window)
}

// Release drops a pending claim so a known-failed action is immediately retryable rather
// than waiting out the lease. The nonce must be the ClaimNonce returned when the lease
// was acquired: a release that cannot prove ownership is a no-op, so a late failure
// callback from an earlier attempt cannot free a newer attempt's live lease.
func (as *ActionStore) Release(ctx context.Context, project, idempotencyKey, nonce string) error {
	if as == nil || as.ledger == nil {
		return fmt.Errorf("action ledger is not configured")
	}
	if idempotencyKey == "" {
		return nil
	}
	return as.ledger.Release(ctx, actionKey(project, idempotencyKey), nonce)
}

// newClaimNonce returns an unguessable per-claim ownership token. It is not a secret in
// the cryptographic sense — it only has to be unique enough that a stale callback can
// never accidentally (or deliberately) match a lease it did not acquire.
func newClaimNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("t%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func replayFromRecord(rec map[string]any) *ActionReplay {
	if rec == nil {
		return nil
	}
	replay := &ActionReplay{}
	if v, ok := rec["decision_id"].(string); ok {
		replay.DecisionID = v
	}
	if v, ok := rec["result_class"].(string); ok {
		replay.ResultClass = v
	}
	if v, ok := rec["result_fingerprint"].(string); ok {
		replay.ResultFingerprint = v
	}
	if v, ok := rec["result"]; ok {
		if raw, err := json.Marshal(v); err == nil && string(raw) != "null" {
			replay.Result = raw
		}
	}
	replay.FirstSeenMillis = recordMillis(rec, "first_seen_ms")
	replay.CommittedMillis = recordMillis(rec, "committed_ms")
	return replay
}

func recordMillis(rec map[string]any, key string) int64 {
	switch v := rec[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
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

// actionRiskRank orders risk classes so a floor can only ever raise, never lower,
// the effective risk. Unknown/custom classes rank above read so they are not
// silently treated as harmless.
func actionRiskRank(risk string) int {
	switch NormalizeActionRisk(risk) {
	case ActionRiskRead:
		return 0
	case ActionRiskWrite:
		return 1
	case ActionRiskDangerous:
		return 2
	default:
		return 1
	}
}

// FloorRisk applies a server-side minimum risk class to a client-supplied label.
// The client can raise the risk but never downgrade below the floor the operator
// classified for this tool, so a refund sent as risk:"read" still engages the
// idempotency/dedup firewall. This is a per-tool floor, not a rules engine.
func FloorRisk(client, floor string) string {
	client = NormalizeActionRisk(client)
	if strings.TrimSpace(floor) == "" {
		return client
	}
	if actionRiskRank(floor) > actionRiskRank(client) {
		return NormalizeActionRisk(floor)
	}
	return client
}

// FailClosedRisk reports whether an action's declared risk is high-stakes enough
// that HubbleOps should fail CLOSED (block) when it cannot complete a check or
// durably record the decision — rather than letting the side effect through.
// It keys on the raw label so "money_movement" is caught even though it
// normalizes to the write tier for loop-detection purposes.
func FailClosedRisk(risk string) bool {
	switch strings.ToLower(strings.TrimSpace(risk)) {
	case "money_movement", "danger", "dangerous", "critical", "destructive":
		return true
	}
	return NormalizeActionRisk(risk) == ActionRiskDangerous
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

// Action disposition tells the result path how to reconcile a pending claim:
// commit it (the side effect succeeded), release it (it failed, so a retry is allowed),
// or hold it (ambiguous/in-progress — let the lease decide).
const (
	ActionDispositionCommit  = "commit"
	ActionDispositionRelease = "release"
	ActionDispositionHold    = "hold"
)

// ResultClassDisposition maps a post-execution result class to a ledger disposition. Only
// a clearly successful action commits the full duplicate window; a clearly failed one is
// released so it can be retried; anything ambiguous is held so the short lease — not a
// 24h block — governs retryability.
func ResultClassDisposition(resultClass string) string {
	switch strings.ToLower(strings.TrimSpace(resultClass)) {
	case "success", "empty", "ok":
		return ActionDispositionCommit
	case "timeout", "not_found", "permission_error", "schema_error", "unknown_error", "error", "failed", "rate_limited":
		return ActionDispositionRelease
	default:
		return ActionDispositionHold
	}
}

// ResultDisposition is the risk-aware disposition. An ambiguous failure
// (timeout, generic 5xx/unknown error) does NOT prove the side effect never
// committed — the request may have executed before the connection died. For
// fail-closed actions (dangerous / money movement) the pending lease is HELD so
// a blind retry is suppressed until the lease expires or the outcome is
// verified, instead of being released into a potential double execution.
// Provably-not-executed classes (rate limited, not found, permission, schema)
// stay immediately retryable for every risk tier.
func ResultDisposition(resultClass, rawRisk, flooredRisk string) string {
	disposition := ResultClassDisposition(resultClass)
	if disposition != ActionDispositionRelease {
		return disposition
	}
	switch normalizeResultClass(resultClass) {
	case ResultTimeout, ResultUnknownError:
		if FailClosedRisk(rawRisk) || NormalizeActionRisk(flooredRisk) == ActionRiskDangerous {
			return ActionDispositionHold
		}
	}
	return disposition
}

// duplicateWindow resolves the committed-record TTL. The window is client-tunable for
// low-stakes writes, but for fail-closed risks (money movement, dangerous — by raw label
// or by server floor) it is a server-side guarantee: a client value below the default
// is floored so a buggy or adversarial caller cannot collapse its own dedup window.
func duplicateWindow(seconds int, rawRisk, risk string) time.Duration {
	window := defaultDuplicateWindow
	if seconds > 0 {
		window = time.Duration(seconds) * time.Second
	}
	if (FailClosedRisk(rawRisk) || FailClosedRisk(risk)) && window < defaultDuplicateWindow {
		return defaultDuplicateWindow
	}
	return window
}

func actionKey(project, idempotencyKey string) string {
	sum := sha256.Sum256([]byte(project + "\x00" + idempotencyKey))
	return fmt.Sprintf("action:idempotency:%x", sum[:])
}

func actionValueFingerprint(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", sum[:])
}

// actionRequestFingerprint binds an idempotency key to the payload it was first
// used with. Reusing the same key with a different tool, risk, resource, amount,
// or recipient domain is a client bug or tampering, not a safe replay, so the
// duplicate path compares this fingerprint instead of trusting the key alone.
func actionRequestFingerprint(obs ActionObservation, risk string) string {
	return actionFingerprintParts(obs.ToolName, risk, obs.ResourceID, obs.AmountCents, obs.Recipient)
}

// actionResultFingerprint recomputes the request fingerprint from the post-execution
// result observation so a committed record carries the same binding the claim did, and a
// later duplicate is still checked for payload mismatch.
func actionResultFingerprint(res ActionResult, risk string) string {
	return actionFingerprintParts(res.ToolName, risk, res.ResourceID, res.AmountCents, res.Recipient)
}

func actionFingerprintParts(tool, risk, resourceID string, amountCents int64, recipient string) string {
	parts := []string{
		"tool=" + tool,
		"risk=" + risk,
		"resource=" + actionValueFingerprint(resourceID),
		fmt.Sprintf("amount=%d", amountCents),
		"recipient=" + emailDomain(recipient),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("sha256:%x", sum[:])
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

// claimStatus is the result of attempting to claim a pending lease.
type claimStatus int

const (
	// claimStatusClaimed: a fresh pending lease was acquired — no live record existed,
	// or a prior pending lease had expired (so the prior side effect provably never
	// committed and a retry is allowed).
	claimStatusClaimed claimStatus = iota
	// claimStatusInFlight: a live pending lease already exists; the first attempt may
	// still be running.
	claimStatusInFlight
	// claimStatusCommitted: a committed record already exists within the duplicate
	// window; the action is a true duplicate and must be replayed, not re-executed.
	claimStatusCommitted
)

const (
	ledgerStatePending   = "pending"
	ledgerStateCommitted = "committed"
)

type actionLedger interface {
	// Claim attempts to acquire a fresh PENDING lease for key, owned by nonce. When a
	// live pending lease or a committed record already exists it returns the
	// corresponding status and the stored record JSON in previous.
	Claim(ctx context.Context, key string, pending []byte, lease time.Duration, nonce string) (claimStatus, string, error)
	// Commit promotes key to COMMITTED with the full window and stores the result record.
	// It is idempotent and must succeed even if the pending lease already expired.
	Commit(ctx context.Context, key string, committed []byte, window time.Duration) error
	// Release drops a pending lease so a known-failed action is immediately retryable. It
	// must not remove a committed record, and it must not remove a pending lease whose
	// stored owner nonce does not match the caller's (a lease claimed without a nonce —
	// a legacy record — remains releasable by anyone).
	Release(ctx context.Context, key, nonce string) error
}

type redisActionLedger struct {
	rdb *redis.Client
}

// claimScript acquires a pending lease iff no record exists, otherwise reports whether the
// existing record is pending (in-flight) or committed. State is tracked as a hash field so
// the lease TTL on the key handles expiry without any JSON parsing in Lua.
var claimScript = redis.NewScript(`
local state = redis.call('HGET', KEYS[1], 'state')
if not state then
  redis.call('HSET', KEYS[1], 'state', 'pending', 'record', ARGV[1], 'nonce', ARGV[3])
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
  return {'claimed', ''}
end
local rec = redis.call('HGET', KEYS[1], 'record')
if state == 'committed' then return {'committed', rec} end
return {'pending', rec}
`)

// releaseScript drops the key only while it is still pending AND the caller proves
// ownership with the nonce minted at claim time, so a late failure callback can neither
// delete another attempt's committed record nor free a newer attempt's live lease.
// A pending record with no stored nonce (written before ownership existed) stays
// releasable by anyone.
var releaseScript = redis.NewScript(`
if redis.call('HGET', KEYS[1], 'state') == 'pending' then
  local owner = redis.call('HGET', KEYS[1], 'nonce')
  if (not owner) or owner == '' or owner == ARGV[1] then
    return redis.call('DEL', KEYS[1])
  end
end
return 0
`)

func (l redisActionLedger) Claim(ctx context.Context, key string, pending []byte, lease time.Duration, nonce string) (claimStatus, string, error) {
	if l.rdb == nil {
		return claimStatusClaimed, "", fmt.Errorf("redis client is nil")
	}
	res, err := claimScript.Run(ctx, l.rdb, []string{key}, pending, lease.Milliseconds(), nonce).Result()
	if err != nil {
		return claimStatusClaimed, "", err
	}
	return parseClaimResult(res)
}

// commitScript promotes the key to committed and sets the full-window TTL in one atomic
// step. Doing this as two client calls (HSET then PEXPIRE) left a crash window in which
// the committed record kept the short pending-lease TTL, silently collapsing the 24h
// duplicate window to ~2 minutes for that key. The claim's ownership nonce is dropped:
// a committed record is never releasable, so retaining it would only mislead.
var commitScript = redis.NewScript(`
redis.call('HSET', KEYS[1], 'state', 'committed', 'record', ARGV[1])
redis.call('HDEL', KEYS[1], 'nonce')
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 1
`)

func (l redisActionLedger) Commit(ctx context.Context, key string, committed []byte, window time.Duration) error {
	if l.rdb == nil {
		return fmt.Errorf("redis client is nil")
	}
	return commitScript.Run(ctx, l.rdb, []string{key}, committed, window.Milliseconds()).Err()
}

func (l redisActionLedger) Release(ctx context.Context, key, nonce string) error {
	if l.rdb == nil {
		return fmt.Errorf("redis client is nil")
	}
	return releaseScript.Run(ctx, l.rdb, []string{key}, nonce).Err()
}

func parseClaimResult(res any) (claimStatus, string, error) {
	arr, ok := res.([]any)
	if !ok || len(arr) < 1 {
		return claimStatusClaimed, "", fmt.Errorf("unexpected claim script result: %v", res)
	}
	label, _ := arr[0].(string)
	previous := ""
	if len(arr) > 1 {
		previous, _ = arr[1].(string)
	}
	switch label {
	case "claimed":
		return claimStatusClaimed, "", nil
	case "committed":
		return claimStatusCommitted, previous, nil
	default:
		return claimStatusInFlight, previous, nil
	}
}

type postgresActionLedger struct {
	pool *pgxpool.Pool
}

func (l postgresActionLedger) Claim(ctx context.Context, key string, pending []byte, lease time.Duration, nonce string) (claimStatus, string, error) {
	if l.pool == nil {
		return claimStatusClaimed, "", fmt.Errorf("postgres pool is nil")
	}
	expiresAt := time.Now().Add(lease)
	tx, err := l.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return claimStatusClaimed, "", err
	}
	defer tx.Rollback(ctx)

	// Expired rows (lapsed pending leases and lapsed committed windows alike) are cleared
	// so the key is re-claimable.
	if _, err := tx.Exec(ctx, "DELETE FROM action_ledger WHERE action_key = $1 AND expires_at <= now()", key); err != nil {
		return claimStatusClaimed, "", err
	}
	tag, err := tx.Exec(ctx, `
		INSERT INTO action_ledger (action_key, first_record, state, expires_at)
		VALUES ($1, $2::jsonb, 'pending', $3)
		ON CONFLICT (action_key) DO NOTHING
	`, key, string(pending), expiresAt)
	if err != nil {
		return claimStatusClaimed, "", err
	}
	if tag.RowsAffected() == 1 {
		if err := tx.Commit(ctx); err != nil {
			return claimStatusClaimed, "", err
		}
		return claimStatusClaimed, "", nil
	}

	var previous, state string
	if err := tx.QueryRow(ctx, "SELECT first_record::text, state FROM action_ledger WHERE action_key = $1", key).Scan(&previous, &state); err != nil {
		return claimStatusClaimed, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return claimStatusClaimed, "", err
	}
	if state == ledgerStateCommitted {
		return claimStatusCommitted, previous, nil
	}
	return claimStatusInFlight, previous, nil
}

func (l postgresActionLedger) Commit(ctx context.Context, key string, committed []byte, window time.Duration) error {
	if l.pool == nil {
		return fmt.Errorf("postgres pool is nil")
	}
	expiresAt := time.Now().Add(window)
	_, err := l.pool.Exec(ctx, `
		INSERT INTO action_ledger (action_key, first_record, state, expires_at)
		VALUES ($1, $2::jsonb, 'committed', $3)
		ON CONFLICT (action_key) DO UPDATE
		SET first_record = EXCLUDED.first_record, state = 'committed', expires_at = EXCLUDED.expires_at
	`, key, string(committed), expiresAt)
	return err
}

// Release deletes the pending row only when the caller's nonce matches the one stored in
// the pending record at claim time (kept inside first_record so no schema change is
// needed). Rows written before ownership existed carry no nonce and stay releasable.
func (l postgresActionLedger) Release(ctx context.Context, key, nonce string) error {
	if l.pool == nil {
		return fmt.Errorf("postgres pool is nil")
	}
	_, err := l.pool.Exec(ctx, `
		DELETE FROM action_ledger
		WHERE action_key = $1 AND state = 'pending'
		  AND (COALESCE(first_record->>'claim_nonce', '') = '' OR first_record->>'claim_nonce' = $2)
	`, key, nonce)
	return err
}

type memoryActionLedger struct {
	mu    sync.Mutex
	items map[string]memoryActionItem
}

type memoryActionItem struct {
	value     string
	state     string
	nonce     string
	expiresAt time.Time
}

func newMemoryActionLedger() *memoryActionLedger {
	return &memoryActionLedger{items: make(map[string]memoryActionItem)}
}

func (l *memoryActionLedger) Claim(ctx context.Context, key string, pending []byte, lease time.Duration, nonce string) (claimStatus, string, error) {
	select {
	case <-ctx.Done():
		return claimStatusClaimed, "", ctx.Err()
	default:
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if item, ok := l.items[key]; ok {
		if item.expiresAt.IsZero() || item.expiresAt.After(now) {
			if item.state == ledgerStateCommitted {
				return claimStatusCommitted, item.value, nil
			}
			return claimStatusInFlight, item.value, nil
		}
		delete(l.items, key)
	}
	expiresAt := time.Time{}
	if lease > 0 {
		expiresAt = now.Add(lease)
	}
	l.items[key] = memoryActionItem{value: string(pending), state: ledgerStatePending, nonce: nonce, expiresAt: expiresAt}
	return claimStatusClaimed, "", nil
}

func (l *memoryActionLedger) Commit(ctx context.Context, key string, committed []byte, window time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	expiresAt := time.Time{}
	if window > 0 {
		expiresAt = now.Add(window)
	}
	l.items[key] = memoryActionItem{value: string(committed), state: ledgerStateCommitted, expiresAt: expiresAt}
	return nil
}

func (l *memoryActionLedger) Release(ctx context.Context, key, nonce string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if item, ok := l.items[key]; ok && item.state == ledgerStatePending && (item.nonce == "" || item.nonce == nonce) {
		delete(l.items, key)
	}
	return nil
}
