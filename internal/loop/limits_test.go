package loop

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// forEachLimitBackend runs the same scenario against the memory and Redis
// backends so their semantics can never drift apart.
func forEachLimitBackend(t *testing.T, cfg LimitsConfig, fn func(t *testing.T, store *LimitStore)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) {
		fn(t, NewMemoryLimitStore(cfg))
	})
	t.Run("redis", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { rdb.Close() })
		fn(t, NewLimitStore(rdb, cfg))
	})
}

func limitObs(agent, tool, risk string, amountCents int64, atMillis int64) LimitObservation {
	return LimitObservation{
		Project:     "proj",
		AgentKey:    agent,
		SessionID:   "sess-" + agent,
		ToolName:    tool,
		Risk:        NormalizeActionRisk(risk),
		RawRisk:     risk,
		AmountCents: amountCents,
		UnixMillis:  atMillis,
	}
}

func mustAllow(t *testing.T, store *LimitStore, obs LimitObservation) {
	t.Helper()
	decision, fired, err := store.Check(context.Background(), obs)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if fired {
		t.Fatalf("limit fired unexpectedly: %s %v", decision.Reason, decision.Evidence)
	}
}

func mustBlock(t *testing.T, store *LimitStore, obs LimitObservation, signal string) ActionDecision {
	t.Helper()
	decision, fired, err := store.Check(context.Background(), obs)
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !fired {
		t.Fatalf("limit did not fire (want %s)", signal)
	}
	if decision.Decision.ActionCeiling != ActionBlock {
		t.Fatalf("ceiling=%s want block", decision.Decision.ActionCeiling)
	}
	if !hasSignal(decision.Decision, signal) {
		t.Fatalf("signals=%v missing %s", decision.Decision.SignalsFired, signal)
	}
	return decision
}

// ---------- cumulative amount caps ----------

func cumulativeCfg(scope string) LimitsConfig {
	return LimitsConfig{
		Cumulative: []CumulativeRule{{
			Name:           "cap",
			Scope:          scope,
			WindowSeconds:  3600,
			MaxAmountCents: 10_000,
		}},
	}
}

// The W8 regression: per-action caps pass each $49 refund; the cumulative cap
// must stop the third one even though every action is individually compliant
// and individually keyed.
func TestCumulativeCapBlocksDrainAcrossDistinctActions(t *testing.T) {
	forEachLimitBackend(t, cumulativeCfg("agent"), func(t *testing.T, store *LimitStore) {
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 4_900, 1_000))
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 4_900, 2_000))
		mustBlock(t, store, limitObs("agent-a", "refund", "money_movement", 4_900, 3_000), SignalCumulativeAmountExceeded)
	})
}

func TestCumulativeCapIsScopedPerAgent(t *testing.T) {
	forEachLimitBackend(t, cumulativeCfg("agent"), func(t *testing.T, store *LimitStore) {
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 9_000, 1_000))
		// A different agent key has its own bucket.
		mustAllow(t, store, limitObs("agent-b", "refund", "money_movement", 9_000, 2_000))
		mustBlock(t, store, limitObs("agent-a", "refund", "money_movement", 2_000, 3_000), SignalCumulativeAmountExceeded)
	})
}

// A blocked attempt must not consume cap: after a rejected $49 the agent can
// still spend the genuine remainder.
func TestCumulativeBlockedAttemptDoesNotConsume(t *testing.T) {
	forEachLimitBackend(t, cumulativeCfg("agent"), func(t *testing.T, store *LimitStore) {
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 9_900, 1_000))
		mustBlock(t, store, limitObs("agent-a", "refund", "money_movement", 4_900, 2_000), SignalCumulativeAmountExceeded)
		// 100 cents of headroom remain; an attempt within it is allowed.
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 100, 3_000))
	})
}

func TestCumulativeWindowResets(t *testing.T) {
	forEachLimitBackend(t, cumulativeCfg("agent"), func(t *testing.T, store *LimitStore) {
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 9_900, 1_000))
		// Next fixed window: the bucket starts fresh.
		nextWindow := int64(3_600_000 + 1_000)
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 9_900, nextWindow))
	})
}

func TestCumulativeScopeResource(t *testing.T) {
	cfg := cumulativeCfg("resource")
	forEachLimitBackend(t, cfg, func(t *testing.T, store *LimitStore) {
		a := limitObs("agent-a", "refund", "money_movement", 9_000, 1_000)
		a.ResourceID = "cust_1"
		mustAllow(t, store, a)
		b := limitObs("agent-b", "refund", "money_movement", 9_000, 2_000) // different agent, same resource
		b.ResourceID = "cust_1"
		mustBlock(t, store, b, SignalCumulativeAmountExceeded)
		c := limitObs("agent-a", "refund", "money_movement", 9_000, 3_000)
		c.ResourceID = "cust_2"
		mustAllow(t, store, c)
	})
}

func TestCumulativeIgnoresZeroAmountAndToolMismatch(t *testing.T) {
	cfg := LimitsConfig{Cumulative: []CumulativeRule{{
		Name: "refunds-only", Tool: "refund", Scope: "agent", WindowSeconds: 3600, MaxAmountCents: 1_000,
	}}}
	forEachLimitBackend(t, cfg, func(t *testing.T, store *LimitStore) {
		// Different tool: rule does not apply.
		mustAllow(t, store, limitObs("agent-a", "send_payout", "money_movement", 5_000, 1_000))
		// No amount: nothing to count.
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 0, 2_000))
		mustBlock(t, store, limitObs("agent-a", "refund", "money_movement", 1_500, 3_000), SignalCumulativeAmountExceeded)
	})
}

// ---------- velocity limits ----------

func velocityCfg(minRisk string, max int) LimitsConfig {
	return LimitsConfig{Velocity: []VelocityRule{{
		Name: "rate", MinRisk: minRisk, Scope: "agent", WindowSeconds: 60, MaxActions: max,
	}}}
}

// The W7 regression: session rotation must not shed the counter, because the
// scope is the server-derived agent key, not the session.
func TestVelocityBlocksRapidSideEffectsAcrossSessions(t *testing.T) {
	forEachLimitBackend(t, velocityCfg("write", 3), func(t *testing.T, store *LimitStore) {
		for i := int64(0); i < 3; i++ {
			obs := limitObs("agent-a", "check_status", "write", 0, 1_000+i)
			obs.SessionID = string(rune('a' + i)) // rotating sessions
			mustAllow(t, store, obs)
		}
		fourth := limitObs("agent-a", "check_status", "write", 0, 1_004)
		fourth.SessionID = "fresh-session"
		mustBlock(t, store, fourth, SignalVelocityExceeded)
	})
}

func TestVelocityIgnoresReadTier(t *testing.T) {
	forEachLimitBackend(t, velocityCfg("write", 2), func(t *testing.T, store *LimitStore) {
		for i := int64(0); i < 5; i++ {
			mustAllow(t, store, limitObs("agent-a", "search", "read", 0, 1_000+i))
		}
	})
}

func TestVelocityMinRiskDangerousOnlyCountsDangerous(t *testing.T) {
	forEachLimitBackend(t, velocityCfg("dangerous", 1), func(t *testing.T, store *LimitStore) {
		mustAllow(t, store, limitObs("agent-a", "update_note", "write", 0, 1_000))
		mustAllow(t, store, limitObs("agent-a", "update_note", "write", 0, 1_001))
		mustAllow(t, store, limitObs("agent-a", "delete_account", "dangerous", 0, 1_002))
		mustBlock(t, store, limitObs("agent-a", "delete_account", "dangerous", 0, 1_003), SignalVelocityExceeded)
	})
}

func TestVelocityWindowResets(t *testing.T) {
	forEachLimitBackend(t, velocityCfg("write", 1), func(t *testing.T, store *LimitStore) {
		mustAllow(t, store, limitObs("agent-a", "update_note", "write", 0, 1_000))
		mustBlock(t, store, limitObs("agent-a", "update_note", "write", 0, 2_000), SignalVelocityExceeded)
		mustAllow(t, store, limitObs("agent-a", "update_note", "write", 0, 61_000))
	})
}

// ---------- circuit breaker ----------

func breakerCfg() LimitsConfig {
	return LimitsConfig{Breaker: BreakerRule{Trips: 3, WindowSeconds: 600, CooldownSeconds: 900}}
}

// After repeated firewall trips the agent is quarantined: fail-closed-risk
// actions are blocked until the cooldown passes, without touching other agents.
func TestBreakerOpensAfterTripsAndQuarantinesFailClosedRisk(t *testing.T) {
	forEachLimitBackend(t, breakerCfg(), func(t *testing.T, store *LimitStore) {
		ctx := context.Background()
		for i := int64(0); i < 3; i++ {
			if err := store.RecordTrip(ctx, "proj", "agent-a", 1_000+i); err != nil {
				t.Fatalf("record trip: %v", err)
			}
		}
		mustBlock(t, store, limitObs("agent-a", "refund", "money_movement", 1_000, 2_000), SignalCircuitBreakerOpen)
		mustBlock(t, store, limitObs("agent-a", "delete_account", "dangerous", 0, 2_001), SignalCircuitBreakerOpen)
		// Plain writes keep flowing: quarantine is for fail-closed risk only.
		mustAllow(t, store, limitObs("agent-a", "update_note", "write", 0, 2_002))
		// Other agents are untouched.
		mustAllow(t, store, limitObs("agent-b", "refund", "money_movement", 1_000, 2_003))
	})
}

func TestBreakerStaysClosedBelowTripThreshold(t *testing.T) {
	forEachLimitBackend(t, breakerCfg(), func(t *testing.T, store *LimitStore) {
		ctx := context.Background()
		for i := int64(0); i < 2; i++ {
			if err := store.RecordTrip(ctx, "proj", "agent-a", 1_000+i); err != nil {
				t.Fatalf("record trip: %v", err)
			}
		}
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 1_000, 2_000))
	})
}

func TestBreakerCooldownExpires(t *testing.T) {
	forEachLimitBackend(t, breakerCfg(), func(t *testing.T, store *LimitStore) {
		ctx := context.Background()
		for i := int64(0); i < 3; i++ {
			if err := store.RecordTrip(ctx, "proj", "agent-a", 1_000+i); err != nil {
				t.Fatalf("record trip: %v", err)
			}
		}
		mustBlock(t, store, limitObs("agent-a", "refund", "money_movement", 1_000, 2_000), SignalCircuitBreakerOpen)
		// Past the cooldown the quarantine lifts.
		after := int64(1_000 + 900_000 + 1_000)
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 1_000, after))
	})
}

// ---------- defaults ----------

func TestNoRulesNeverFires(t *testing.T) {
	forEachLimitBackend(t, LimitsConfig{}, func(t *testing.T, store *LimitStore) {
		mustAllow(t, store, limitObs("agent-a", "refund", "money_movement", 1_000_000, 1_000))
	})
}

// A nil store is the disabled state and must be safe to call.
func TestNilLimitStoreIsDisabled(t *testing.T) {
	var store *LimitStore
	decision, fired, err := store.Check(context.Background(), limitObs("agent-a", "refund", "money_movement", 1, 1))
	if err != nil || fired {
		t.Fatalf("nil store: fired=%t err=%v decision=%+v", fired, err, decision)
	}
	if err := store.RecordTrip(context.Background(), "proj", "agent-a", 1); err != nil {
		t.Fatalf("nil store record trip: %v", err)
	}
}
