package loop

import (
	"context"
	"strings"
	"testing"
	"time"
)

func newActionTestStore(t *testing.T) *ActionStore {
	t.Helper()
	return NewMemoryActionStore()
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
	if first.Decision.PolicyVersion != ActionPolicyVersion {
		t.Fatalf("policy=%q want %q", first.Decision.PolicyVersion, ActionPolicyVersion)
	}

	obs.StepID = "refund-2"
	obs.UnixMillis = 2_000
	second, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("second decide: %v", err)
	}
	if second.Decision.ActionCeiling != ActionBlock {
		t.Fatalf("duplicate action ceiling=%s want block", second.Decision.ActionCeiling)
	}
	if second.Decision.Confidence != 1.0 {
		t.Fatalf("confidence=%f want 1.0", second.Decision.Confidence)
	}
	if !hasSignal(second.Decision, SignalDuplicateSideEffect) {
		t.Fatalf("signals=%v missing %s", second.Decision.SignalsFired, SignalDuplicateSideEffect)
	}
	if !strings.Contains(strings.Join(second.Decision.DecisionEvidence, " "), "previous_action=") {
		t.Fatalf("evidence missing previous action: %v", second.Decision.DecisionEvidence)
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
