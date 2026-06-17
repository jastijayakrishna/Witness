package loop

// Pins the ambiguous-failure ledger semantics surfaced by the synthetic corpus:
// a 502/timeout on a money-movement action does NOT prove the side effect
// failed — the pending lease must be HELD so a blind retry is suppressed until
// the lease expires or the outcome is verified (the A17/A18 double-refund shape).

import (
	"context"
	"testing"
)

func TestAmbiguousFailureHoldsDangerousLease(t *testing.T) {
	if got := ResultDisposition("unknown_error", "dangerous", ActionRiskDangerous); got != ActionDispositionHold {
		t.Fatalf("ambiguous failure on dangerous action: disposition=%s want hold", got)
	}
	if got := ResultDisposition("timeout", "money_movement", ActionRiskWrite); got != ActionDispositionHold {
		t.Fatalf("timeout on money movement: disposition=%s want hold", got)
	}
}

func TestProvableFailureStillReleases(t *testing.T) {
	// Provably-not-executed outcomes stay retryable even for dangerous actions.
	for _, class := range []string{"rate_limited", "not_found", "permission_error", "schema_error"} {
		if got := ResultDisposition(class, "dangerous", ActionRiskDangerous); got != ActionDispositionRelease {
			t.Fatalf("%s on dangerous action: disposition=%s want release", class, got)
		}
	}
	// Ambiguous failures on ordinary writes keep the forgiving behavior.
	if got := ResultDisposition("unknown_error", "write", ActionRiskWrite); got != ActionDispositionRelease {
		t.Fatalf("unknown_error on plain write: disposition=%s want release", got)
	}
}

func TestAmbiguousRetryBlockedInFlight(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryActionStore()
	obs := ActionObservation{
		Project: "p", SessionID: "s", ToolName: "charge_card",
		ActionRisk: "dangerous", IdempotencyKey: "chg-1",
		AmountCents: 4999, MaxAmountCents: 50_000, BackupID: "n/a", UnixMillis: 1000,
	}
	first, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("first decide: %v", err)
	}
	if first.Decision.ActionCeiling != ActionNone {
		t.Fatalf("first attempt should claim: %+v", first.Decision)
	}
	// 502 → ambiguous → HOLD: the caller must NOT release the lease.
	if ResultDisposition("unknown_error", "dangerous", ActionRiskDangerous) != ActionDispositionHold {
		t.Fatalf("expected hold disposition for ambiguous failure")
	}
	second, err := store.Decide(ctx, obs)
	if err != nil {
		t.Fatalf("second decide: %v", err)
	}
	if second.Decision.ActionCeiling != ActionBlock || second.Outcome != ActionOutcomeInFlight {
		t.Fatalf("blind retry after ambiguous failure must block in-flight: %+v outcome=%s",
			second.Decision, second.Outcome)
	}
}
