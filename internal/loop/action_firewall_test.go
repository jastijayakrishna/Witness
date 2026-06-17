package loop

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newActionTestStore(t *testing.T) *ActionStore {
	t.Helper()
	return NewMemoryActionStore()
}

// commitObs promotes a pending claim to committed the way the result path does, so tests
// can exercise the duplicate-replay path that only opens after a side effect succeeds.
func commitObs(t *testing.T, store *ActionStore, obs ActionObservation, result string) {
	t.Helper()
	if err := store.Commit(context.Background(), ActionResult{
		Project:        obs.Project,
		IdempotencyKey: obs.IdempotencyKey,
		ToolName:       obs.ToolName,
		ActionRisk:     obs.ActionRisk,
		ResourceID:     obs.ResourceID,
		AmountCents:    obs.AmountCents,
		Recipient:      obs.Recipient,
		DecisionID:     "dec_original",
		ResultClass:    "success",
		Result:         []byte(result),
		UnixMillis:     obs.UnixMillis,
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func TestActionStoreBlocksDuplicateSideEffect(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-1",
		StepID:         "refund-1",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_1:invoice_9:5000",
		AgentID:        "agent-1",
		UserID:         "user-1",
		UnixMillis:     1_000,
	}

	first, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("first decide: %v", err)
	}
	if first.Decision.ActionCeiling != ActionNone {
		t.Fatalf("first action ceiling=%s want none", first.Decision.ActionCeiling)
	}
	if first.Outcome != ActionOutcomeClaimed {
		t.Fatalf("first outcome=%q want %q", first.Outcome, ActionOutcomeClaimed)
	}
	if first.Decision.PolicyVersion != ActionPolicyVersion {
		t.Fatalf("policy=%q want %q", first.Decision.PolicyVersion, ActionPolicyVersion)
	}

	// The side effect succeeds and is committed for the full duplicate window.
	commitObs(t, store, obs, `{"refunded":true}`)

	// A later attempt with the same committed key replays the recorded outcome instead
	// of running the refund again.
	obs.StepID = "refund-2"
	obs.UnixMillis = 2_000
	second, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("second decide: %v", err)
	}
	if second.Decision.ActionCeiling != ActionBlock {
		t.Fatalf("duplicate action ceiling=%s want block", second.Decision.ActionCeiling)
	}
	if second.Outcome != ActionOutcomeCommittedReplay {
		t.Fatalf("duplicate outcome=%q want %q", second.Outcome, ActionOutcomeCommittedReplay)
	}
	if second.Decision.Confidence != 1.0 {
		t.Fatalf("confidence=%f want 1.0", second.Decision.Confidence)
	}
	if !hasSignal(second.Decision, SignalDuplicateSideEffect) {
		t.Fatalf("signals=%v missing %s", second.Decision.SignalsFired, SignalDuplicateSideEffect)
	}
	if second.Replay == nil || string(second.Replay.Result) != `{"refunded":true}` {
		t.Fatalf("replay did not carry the original result: %+v", second.Replay)
	}
	if second.Replay.DecisionID != "dec_original" {
		t.Fatalf("replay decision_id=%q want dec_original", second.Replay.DecisionID)
	}
	if !strings.Contains(strings.Join(second.Decision.DecisionEvidence, " "), "previous_action=") {
		t.Fatalf("evidence missing previous action: %v", second.Decision.DecisionEvidence)
	}
}

func TestActionStoreReportsInFlightWhileFirstAttemptRuns(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-1",
		StepID:         "refund-1",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_1:invoice_9:5000",
		UnixMillis:     1_000,
	}
	if first, err := store.Decide(ctx, obs); err != nil || first.Outcome != ActionOutcomeClaimed {
		t.Fatalf("first decide outcome=%q err=%v", first.Outcome, err)
	}

	// No commit yet: the first refund is still running. A concurrent retry must be told
	// it is in flight, not blocked as a permanent duplicate.
	obs.StepID = "refund-2"
	obs.UnixMillis = 1_500
	second, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("second decide: %v", err)
	}
	if second.Outcome != ActionOutcomeInFlight {
		t.Fatalf("outcome=%q want %q", second.Outcome, ActionOutcomeInFlight)
	}
	if !hasSignal(second.Decision, SignalActionInFlight) {
		t.Fatalf("signals=%v missing %s", second.Decision.SignalsFired, SignalActionInFlight)
	}
	if hasSignal(second.Decision, SignalDuplicateSideEffect) {
		t.Fatalf("in-flight must not be reported as a committed duplicate: %v", second.Decision.SignalsFired)
	}
}

// TestActionStoreReclaimsAfterExpiredPendingLease is the crash-gap regression: if a
// process dies between claiming and executing, the pending lease expires and a retry is
// allowed because the side effect provably never committed.
func TestActionStoreReclaimsAfterExpiredPendingLease(t *testing.T) {
	store := newActionTestStore(t).WithLease(10 * time.Millisecond)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-1",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_1:invoice_9:5000",
		UnixMillis:     1_000,
	}
	if first, err := store.Decide(ctx, obs); err != nil || first.Outcome != ActionOutcomeClaimed {
		t.Fatalf("first decide outcome=%q err=%v", first.Outcome, err)
	}
	// Simulate the crash: the side effect never ran and never committed; the lease lapses.
	time.Sleep(25 * time.Millisecond)
	retry, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("retry decide: %v", err)
	}
	if retry.Outcome != ActionOutcomeClaimed {
		t.Fatalf("retry outcome=%q want %q (a crashed attempt must be retryable)", retry.Outcome, ActionOutcomeClaimed)
	}
	if retry.Decision.ActionCeiling != ActionNone {
		t.Fatalf("retry ceiling=%s want none", retry.Decision.ActionCeiling)
	}
}

func TestActionStoreReleaseAllowsImmediateRetry(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-1",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_1:invoice_9:5000",
		UnixMillis:     1_000,
	}
	first, err := store.Decide(ctx, obs)
	if err != nil || first.Outcome != ActionOutcomeClaimed {
		t.Fatalf("first decide outcome=%q err=%v", first.Outcome, err)
	}
	// The side effect failed; the result path releases the pending claim it owns.
	if err := store.Release(ctx, obs.Project, obs.IdempotencyKey, first.ClaimNonce); err != nil {
		t.Fatalf("release: %v", err)
	}
	retry, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("retry decide: %v", err)
	}
	if retry.Outcome != ActionOutcomeClaimed {
		t.Fatalf("retry outcome=%q want %q after release", retry.Outcome, ActionOutcomeClaimed)
	}
}

// TestActionStoreClaimReturnsOwnershipNonce: every successful claim carries a fresh
// nonce so the result path can prove it is releasing its own lease, not someone else's.
func TestActionStoreClaimReturnsOwnershipNonce(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-nonce",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_1:invoice_1",
		UnixMillis:     1_000,
	}
	first, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if first.Outcome != ActionOutcomeClaimed {
		t.Fatalf("outcome=%q want claimed", first.Outcome)
	}
	if first.ClaimNonce == "" {
		t.Fatalf("claimed decision must carry a claim nonce")
	}

	obs.IdempotencyKey = "refund:cust_1:invoice_2"
	second, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("second decide: %v", err)
	}
	if second.ClaimNonce == "" || second.ClaimNonce == first.ClaimNonce {
		t.Fatalf("claim nonces must be unique per claim: first=%q second=%q", first.ClaimNonce, second.ClaimNonce)
	}
}

// TestActionStoreReleaseRequiresMatchingNonce is the late-callback race regression:
// attempt A claims and its lease lapses; attempt B claims fresh; A's slow failure
// callback then tries to release. Without ownership, A frees B's live lease and a
// concurrent retry races B into a double execution.
func TestActionStoreReleaseRequiresMatchingNonce(t *testing.T) {
	store := newActionTestStore(t).WithLease(10 * time.Millisecond)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-race",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_1:invoice_9:5000",
		UnixMillis:     1_000,
	}
	attemptA, err := store.Decide(ctx, obs)
	if err != nil || attemptA.Outcome != ActionOutcomeClaimed {
		t.Fatalf("attempt A outcome=%q err=%v", attemptA.Outcome, err)
	}
	// A's lease lapses (slow execution); B re-claims the key.
	time.Sleep(25 * time.Millisecond)
	attemptB, err := store.Decide(ctx, obs)
	if err != nil || attemptB.Outcome != ActionOutcomeClaimed {
		t.Fatalf("attempt B outcome=%q err=%v", attemptB.Outcome, err)
	}

	// A's late failure callback must NOT free B's live lease.
	if err := store.Release(ctx, obs.Project, obs.IdempotencyKey, attemptA.ClaimNonce); err != nil {
		t.Fatalf("release with stale nonce: %v", err)
	}
	stillHeld, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("decide after stale release: %v", err)
	}
	if stillHeld.Outcome != ActionOutcomeInFlight {
		t.Fatalf("outcome=%q want in_flight (stale release must not drop another attempt's lease)", stillHeld.Outcome)
	}

	// B's own failure callback, carrying B's nonce, releases as before.
	if err := store.Release(ctx, obs.Project, obs.IdempotencyKey, attemptB.ClaimNonce); err != nil {
		t.Fatalf("release with owning nonce: %v", err)
	}
	retry, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("retry decide: %v", err)
	}
	if retry.Outcome != ActionOutcomeClaimed {
		t.Fatalf("outcome=%q want claimed after owner release", retry.Outcome)
	}
}

// A release with no nonce (legacy caller) must not drop a lease that was claimed with
// ownership: failing open here would reintroduce the race for every old client.
func TestActionStoreReleaseWithoutNonceDoesNotDropOwnedLease(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-legacy",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_2:invoice_1",
		UnixMillis:     1_000,
	}
	if first, err := store.Decide(ctx, obs); err != nil || first.Outcome != ActionOutcomeClaimed {
		t.Fatalf("decide outcome=%q err=%v", first.Outcome, err)
	}
	if err := store.Release(ctx, obs.Project, obs.IdempotencyKey, ""); err != nil {
		t.Fatalf("release: %v", err)
	}
	still, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("decide after empty-nonce release: %v", err)
	}
	if still.Outcome != ActionOutcomeInFlight {
		t.Fatalf("outcome=%q want in_flight (empty-nonce release must not drop an owned lease)", still.Outcome)
	}
}

// TestActionStoreReleaseDoesNotDropCommittedRecord guards against a late failure result
// for one attempt wiping the committed record of another.
func TestActionStoreReleaseDoesNotDropCommittedRecord(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-1",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_1:invoice_9:5000",
		UnixMillis:     1_000,
	}
	first, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	commitObs(t, store, obs, `{"refunded":true}`)
	if err := store.Release(ctx, obs.Project, obs.IdempotencyKey, first.ClaimNonce); err != nil {
		t.Fatalf("release: %v", err)
	}
	again, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("decide after release: %v", err)
	}
	if again.Outcome != ActionOutcomeCommittedReplay {
		t.Fatalf("outcome=%q want committed_replay (release must not drop committed record)", again.Outcome)
	}
}

// TestActionStoreFloorsDuplicateWindowForFailClosedRisk: the duplicate window is a
// server-side guarantee for money movement / dangerous actions. A buggy or adversarial
// client sending duplicate_window_seconds=1 must not be able to collapse the window and
// neuter dedup for its own actions.
func TestActionStoreFloorsDuplicateWindowForFailClosedRisk(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	obs := ActionObservation{
		Project:                "proj",
		SessionID:              "sess-floor",
		ToolName:               "refund_customer",
		ActionRisk:             "money_movement",
		IdempotencyKey:         "refund:cust_1:invoice_9:5000",
		DuplicateWindowSeconds: 1,
		UnixMillis:             1_000,
	}
	first, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if first.Outcome != ActionOutcomeClaimed {
		t.Fatalf("outcome=%q want claimed", first.Outcome)
	}
	evidence := strings.Join(first.Evidence, " ")
	if !strings.Contains(evidence, "duplicate_window=24h0m0s") {
		t.Fatalf("evidence=%q want floored duplicate_window=24h0m0s", evidence)
	}

	// Commit with the same 1s client window; the committed record must outlive it.
	if err := store.Commit(ctx, ActionResult{
		Project:                obs.Project,
		IdempotencyKey:         obs.IdempotencyKey,
		ToolName:               obs.ToolName,
		ActionRisk:             obs.ActionRisk,
		ResultClass:            "success",
		DuplicateWindowSeconds: 1,
		UnixMillis:             1_500,
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	dup, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("duplicate decide: %v", err)
	}
	if dup.Outcome != ActionOutcomeCommittedReplay {
		t.Fatalf("outcome=%q want committed_replay (1s client window must be floored for money movement)", dup.Outcome)
	}
}

// A floored risk of dangerous must also engage the window floor even when the raw label
// was downgraded by the client and only the server-side tool floor raised it.
func TestActionStoreFloorsDuplicateWindowForServerFlooredDangerousRisk(t *testing.T) {
	store := newActionTestStore(t)
	first, err := store.Decide(context.Background(), ActionObservation{
		Project:                "proj",
		SessionID:              "sess-floor-2",
		ToolName:               "delete_account",
		ActionRisk:             "dangerous",
		RawActionRisk:          "read", // client lied; operator floor raised it
		IdempotencyKey:         "delete:acct_1",
		BackupID:               "backup_1",
		DuplicateWindowSeconds: 1,
		UnixMillis:             1_000,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	evidence := strings.Join(first.Evidence, " ")
	if !strings.Contains(evidence, "duplicate_window=24h0m0s") {
		t.Fatalf("evidence=%q want floored duplicate_window=24h0m0s", evidence)
	}
}

// Plain write-tier actions keep honoring the client window: short-lived dedup for
// low-stakes actions is a legitimate use case the floor must not break.
func TestActionStoreHonorsClientWindowForWriteRisk(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	obs := ActionObservation{
		Project:                "proj",
		SessionID:              "sess-write-window",
		ToolName:               "update_note",
		ActionRisk:             "write",
		IdempotencyKey:         "note:cust_1:v1",
		DuplicateWindowSeconds: 1,
		UnixMillis:             1_000,
	}
	if first, err := store.Decide(ctx, obs); err != nil || first.Outcome != ActionOutcomeClaimed {
		t.Fatalf("first decide outcome=%q err=%v", first.Outcome, err)
	}
	if err := store.Commit(ctx, ActionResult{
		Project:                obs.Project,
		IdempotencyKey:         obs.IdempotencyKey,
		ToolName:               obs.ToolName,
		ActionRisk:             obs.ActionRisk,
		ResultClass:            "success",
		DuplicateWindowSeconds: 1,
		UnixMillis:             1_500,
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)
	retry, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("retry decide: %v", err)
	}
	if retry.Outcome != ActionOutcomeClaimed {
		t.Fatalf("outcome=%q want claimed (write-tier client window must be honored)", retry.Outcome)
	}
}

func TestActionStoreBlocksIdempotencyKeyReuseWithDifferentPayload(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-1",
		StepID:         "refund-1",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_1:invoice_9",
		AmountCents:    5000,
		UnixMillis:     1_000,
	}

	first, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("first decide: %v", err)
	}
	if first.Decision.ActionCeiling != ActionNone {
		t.Fatalf("first action ceiling=%s want none", first.Decision.ActionCeiling)
	}

	// Same key, different amount: this is a contradictory replay, not a benign one.
	obs.StepID = "refund-2"
	obs.AmountCents = 9999
	obs.UnixMillis = 2_000
	mismatch, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("mismatch decide: %v", err)
	}
	if mismatch.Decision.ActionCeiling != ActionBlock {
		t.Fatalf("mismatch action ceiling=%s want block", mismatch.Decision.ActionCeiling)
	}
	if !hasSignal(mismatch.Decision, SignalIdempotencyKeyReuseMismatch) {
		t.Fatalf("signals=%v missing %s", mismatch.Decision.SignalsFired, SignalIdempotencyKeyReuseMismatch)
	}
	if hasSignal(mismatch.Decision, SignalDuplicateSideEffect) {
		t.Fatalf("mismatch must not be reported as a benign duplicate: %v", mismatch.Decision.SignalsFired)
	}
}

func TestActionStoreTreatsIdenticalReplayAsBenignDuplicate(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-1",
		StepID:         "refund-1",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_1:invoice_9",
		AmountCents:    5000,
		ResourceID:     "invoice_9",
		UnixMillis:     1_000,
	}
	if first, err := store.Decide(ctx, obs); err != nil || first.Decision.ActionCeiling != ActionNone {
		t.Fatalf("first decide=%+v err=%v", first.Decision, err)
	}

	// The first attempt commits, then the same key with the same payload is replayed.
	commitObs(t, store, obs, `{"refunded":true}`)
	obs.StepID = "refund-2"
	obs.UnixMillis = 2_000
	dup, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("duplicate decide: %v", err)
	}
	if !hasSignal(dup.Decision, SignalDuplicateSideEffect) {
		t.Fatalf("signals=%v want %s", dup.Decision.SignalsFired, SignalDuplicateSideEffect)
	}
	if hasSignal(dup.Decision, SignalIdempotencyKeyReuseMismatch) {
		t.Fatalf("identical replay must not fire mismatch signal: %v", dup.Decision.SignalsFired)
	}
}

func TestActionStoreLedgerDoesNotStoreRawEffectIdentifiers(t *testing.T) {
	store := newActionTestStore(t)
	rawKey := "email:customer@example.com:welcome"
	rawResource := "crm_contact_customer@example.com"
	_, err := store.Decide(context.Background(), ActionObservation{
		Project:        "proj",
		SessionID:      "sess-privacy",
		StepID:         "email-1",
		ToolName:       "send_email",
		ActionRisk:     "customer_visible",
		IdempotencyKey: rawKey,
		ResourceID:     rawResource,
		UnixMillis:     1_000,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}

	ledger, ok := store.ledger.(*memoryActionLedger)
	if !ok {
		t.Fatalf("ledger type %T is not inspectable", store.ledger)
	}
	for _, item := range ledger.items {
		if strings.Contains(item.value, rawKey) || strings.Contains(item.value, rawResource) || strings.Contains(item.value, "customer@example.com") {
			t.Fatalf("ledger stored raw sensitive effect identifier: %s", item.value)
		}
		if !strings.Contains(item.value, "idempotency_key_hash") || !strings.Contains(item.value, "resource_fingerprint") {
			t.Fatalf("ledger missing privacy-safe fingerprints: %s", item.value)
		}
	}
}

func TestActionStoreIsolatesIdempotencyByProject(t *testing.T) {
	store := newActionTestStore(t)
	ctx := context.Background()
	base := ActionObservation{
		Project:        "project-a",
		SessionID:      "sess-1",
		ToolName:       "send_email",
		ActionRisk:     "customer_visible",
		IdempotencyKey: "email:cust_1:subject:body",
		UnixMillis:     1_000,
	}
	if first, err := store.Decide(ctx, base); err != nil || first.Decision.ActionCeiling != ActionNone {
		t.Fatalf("first project-a decide=%+v err=%v", first.Decision, err)
	}

	base.Project = "project-b"
	second, err := store.Decide(ctx, base)
	if err != nil {
		t.Fatalf("project-b decide: %v", err)
	}
	if second.Decision.ActionCeiling != ActionNone {
		t.Fatalf("project-b ceiling=%s want none", second.Decision.ActionCeiling)
	}
}

func TestActionStoreAllowsReadWithoutIdempotencyKey(t *testing.T) {
	store := newActionTestStore(t)
	decision, err := store.Decide(context.Background(), ActionObservation{
		Project:    "proj",
		SessionID:  "sess-1",
		ToolName:   "search_docs",
		ActionRisk: "read",
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision.ActionCeiling != ActionNone {
		t.Fatalf("action ceiling=%s want none", decision.Decision.ActionCeiling)
	}
}

func TestActionStoreWarnsWriteActionWithoutIdempotencyKey(t *testing.T) {
	store := newActionTestStore(t)
	decision, err := store.Decide(context.Background(), ActionObservation{
		Project:    "proj",
		SessionID:  "sess-1",
		ToolName:   "send_email",
		ActionRisk: "write",
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision.ActionCeiling != ActionWarn {
		t.Fatalf("action ceiling=%s want warn", decision.Decision.ActionCeiling)
	}
	if !hasSignal(decision.Decision, SignalMissingIdempotency) {
		t.Fatalf("signals=%v missing %s", decision.Decision.SignalsFired, SignalMissingIdempotency)
	}
}

func TestActionStoreBlocksDangerousActionWithoutIdempotencyKey(t *testing.T) {
	store := newActionTestStore(t)
	decision, err := store.Decide(context.Background(), ActionObservation{
		Project:    "proj",
		SessionID:  "sess-1",
		ToolName:   "delete_account",
		ActionRisk: "dangerous",
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision.ActionCeiling != ActionBlock {
		t.Fatalf("action ceiling=%s want block", decision.Decision.ActionCeiling)
	}
	if !hasSignal(decision.Decision, SignalMissingIdempotency) {
		t.Fatalf("signals=%v missing %s", decision.Decision.SignalsFired, SignalMissingIdempotency)
	}
}

func TestActionStoreBlocksAmountAboveDeclaredLimit(t *testing.T) {
	store := newActionTestStore(t)
	decision, err := store.Decide(context.Background(), ActionObservation{
		Project:        "proj",
		SessionID:      "sess-amount",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:invoice_9:7500",
		AmountCents:    7500,
		MaxAmountCents: 5000,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision.ActionCeiling != ActionBlock {
		t.Fatalf("action ceiling=%s want block", decision.Decision.ActionCeiling)
	}
	if !hasSignal(decision.Decision, SignalPolicyAmountExceeded) {
		t.Fatalf("signals=%v missing %s", decision.Decision.SignalsFired, SignalPolicyAmountExceeded)
	}
}

func TestActionStoreBlocksRecipientOutsideAllowedDomain(t *testing.T) {
	store := newActionTestStore(t)
	decision, err := store.Decide(context.Background(), ActionObservation{
		Project:        "proj",
		SessionID:      "sess-email",
		ToolName:       "send_email",
		ActionRisk:     "customer_visible",
		IdempotencyKey: "email:user:notice",
		Recipient:      "customer@external.example",
		AllowedDomain:  "company.example",
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision.ActionCeiling != ActionBlock {
		t.Fatalf("action ceiling=%s want block", decision.Decision.ActionCeiling)
	}
	if !hasSignal(decision.Decision, SignalRecipientOutOfPolicy) {
		t.Fatalf("signals=%v missing %s", decision.Decision.SignalsFired, SignalRecipientOutOfPolicy)
	}
}

func TestActionStoreRequiresSafetyPreconditionForDangerousIdempotentAction(t *testing.T) {
	store := newActionTestStore(t)
	decision, err := store.Decide(context.Background(), ActionObservation{
		Project:        "proj",
		SessionID:      "sess-danger",
		ToolName:       "delete_account",
		ActionRisk:     "dangerous",
		IdempotencyKey: "delete:acct_1",
		ResourceID:     "acct_1",
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision.ActionCeiling != ActionBlock {
		t.Fatalf("action ceiling=%s want block", decision.Decision.ActionCeiling)
	}
	if !hasSignal(decision.Decision, SignalMissingSafetyPrecondition) {
		t.Fatalf("signals=%v missing %s", decision.Decision.SignalsFired, SignalMissingSafetyPrecondition)
	}

	allowed, err := store.Decide(context.Background(), ActionObservation{
		Project:        "proj",
		SessionID:      "sess-danger",
		ToolName:       "delete_account",
		ActionRisk:     "dangerous",
		IdempotencyKey: "delete:acct_2",
		ResourceID:     "acct_2",
		BackupID:       "backup_123",
	})
	if err != nil {
		t.Fatalf("decide allowed: %v", err)
	}
	if allowed.Decision.ActionCeiling != ActionNone {
		t.Fatalf("action ceiling=%s want none", allowed.Decision.ActionCeiling)
	}
}

func TestActionStoreAllowsDangerousActionWithScopedCapability(t *testing.T) {
	secret := []byte("test-capability-secret")
	token, err := IssueCapability(secret, Capability{
		Project:     "proj",
		AgentID:     "agent-1",
		ActionName:  "delete_account",
		ResourceID:  "acct_1",
		ExpiresUnix: time.Now().Add(time.Hour).Unix(),
		Nonce:       "nonce-1",
	})
	if err != nil {
		t.Fatalf("issue capability: %v", err)
	}
	store := newActionTestStore(t).WithCapabilitySecret(string(secret))
	decision, err := store.Decide(context.Background(), ActionObservation{
		Project:         "proj",
		SessionID:       "sess-cap",
		ToolName:        "delete_account",
		ActionRisk:      "dangerous",
		IdempotencyKey:  "delete:acct_1",
		ResourceID:      "acct_1",
		AgentID:         "agent-1",
		CapabilityToken: token,
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision.ActionCeiling != ActionNone {
		t.Fatalf("action ceiling=%s want none evidence=%v", decision.Decision.ActionCeiling, decision.Decision.DecisionEvidence)
	}
}

func TestActionStoreBlocksInvalidCapability(t *testing.T) {
	store := newActionTestStore(t).WithCapabilitySecret("test-capability-secret")
	decision, err := store.Decide(context.Background(), ActionObservation{
		Project:         "proj",
		SessionID:       "sess-bad-cap",
		ToolName:        "delete_account",
		ActionRisk:      "dangerous",
		IdempotencyKey:  "delete:acct_1",
		ResourceID:      "acct_1",
		CapabilityToken: "witcap_v1.invalid.invalid",
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if decision.Decision.ActionCeiling != ActionBlock {
		t.Fatalf("action ceiling=%s want block", decision.Decision.ActionCeiling)
	}
	if !hasSignal(decision.Decision, SignalInvalidCapability) {
		t.Fatalf("signals=%v missing %s", decision.Decision.SignalsFired, SignalInvalidCapability)
	}
}

// TestRedisLedgerCommitIsOneAtomicWrite: commit must move the key to its committed shape
// (state, record, full-window TTL, no leftover claim nonce) in a single script. The old
// two-call commit (HSET then PEXPIRE) could crash in between, leaving a committed record
// that silently expired with the 2-minute lease instead of the 24h duplicate window.
func TestRedisLedgerCommitIsOneAtomicWrite(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	store := NewActionStore(rdb)
	ctx := context.Background()
	obs := ActionObservation{
		Project:        "proj",
		SessionID:      "sess-atomic",
		ToolName:       "refund_customer",
		ActionRisk:     "money_movement",
		IdempotencyKey: "refund:cust_1:invoice_9:5000",
		UnixMillis:     1_000,
	}
	if first, err := store.Decide(ctx, obs); err != nil || first.Outcome != ActionOutcomeClaimed {
		t.Fatalf("decide outcome=%q err=%v", first.Outcome, err)
	}
	if err := store.Commit(ctx, ActionResult{
		Project:        obs.Project,
		IdempotencyKey: obs.IdempotencyKey,
		ToolName:       obs.ToolName,
		ActionRisk:     obs.ActionRisk,
		ResultClass:    "success",
		UnixMillis:     2_000,
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	key := actionKey(obs.Project, obs.IdempotencyKey)
	if state := mr.HGet(key, "state"); state != ledgerStateCommitted {
		t.Fatalf("state=%q want committed", state)
	}
	// The pending claim's ownership nonce must not survive into the committed record.
	if nonce := mr.HGet(key, "nonce"); nonce != "" {
		t.Fatalf("committed record still carries claim nonce %q", nonce)
	}
	// The TTL must be the full duplicate window, not the short pending lease.
	if ttl := mr.TTL(key); ttl < 23*time.Hour {
		t.Fatalf("committed TTL=%s want ~24h duplicate window", ttl)
	}
}

func TestNormalizeActionRisk(t *testing.T) {
	tests := map[string]string{
		"":                 ActionRiskRead,
		"readonly":         ActionRiskRead,
		"customer_visible": ActionRiskWrite,
		"money_movement":   ActionRiskWrite,
		"critical":         ActionRiskDangerous,
		"custom":           "custom",
	}
	for in, want := range tests {
		if got := NormalizeActionRisk(in); got != want {
			t.Fatalf("NormalizeActionRisk(%q)=%q want %q", in, got, want)
		}
	}
}
