package loop

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// The resource-rogue layer: limits that apply ACROSS actions, where the rest of
// the firewall judges each action in isolation. Three mechanisms, one store:
//
//   - cumulative amount caps: windowed spend per agent/session/resource/recipient
//   - velocity limits: windowed count of side-effecting actions
//   - circuit breaker: repeated firewall trips quarantine an agent's
//     fail-closed-risk actions for a cooldown
//
// All buckets are keyed by the SERVER-derived agent identity (the auth key ID),
// never by client-supplied fields: rotating a session sheds loop-detector state,
// but it cannot shed these counters. Rules are operator-declared only.
//
// Counting policy: limits count ATTEMPTS at decide time and are never refunded
// on failure — conservative in the safe direction. Windows are fixed (bucketed),
// so a burst straddling a boundary can reach ~2x a cap; that is an accepted v1
// trade-off, documented in docs/CONFIG_SAFETY.md.

const (
	SignalCumulativeAmountExceeded = "cumulative_amount_exceeded"
	SignalVelocityExceeded         = "velocity_exceeded"
	SignalCircuitBreakerOpen       = "circuit_breaker_open"
)

// AnonymousAgentKey buckets unauthenticated traffic per project. Coarse, but an
// unauthenticated caller must not get a fresh bucket by omitting credentials.
const AnonymousAgentKey = "anon"

type LimitsConfig struct {
	Cumulative []CumulativeRule
	Velocity   []VelocityRule
	Breaker    BreakerRule
}

// Enabled reports whether any rule is configured.
func (c LimitsConfig) Enabled() bool {
	return len(c.Cumulative) > 0 || len(c.Velocity) > 0 || c.Breaker.Trips > 0
}

// CumulativeRule caps total amount_cents across matching actions per window.
type CumulativeRule struct {
	Name           string
	Tool           string // optional exact tool filter; "" matches any tool
	Scope          string // agent (default) | session | resource | recipient
	WindowSeconds  int
	MaxAmountCents int64
}

// VelocityRule caps the number of side-effecting actions per window.
type VelocityRule struct {
	Name          string
	Tool          string // optional exact tool filter; "" matches any tool
	MinRisk       string // minimum floored tier counted: write (default) | dangerous
	Scope         string // agent (default) | session | resource | recipient
	WindowSeconds int
	MaxActions    int
}

// BreakerRule quarantines an agent's fail-closed-risk actions after it
// accumulates Trips enforced blocks within WindowSeconds.
type BreakerRule struct {
	Trips           int
	WindowSeconds   int
	CooldownSeconds int
}

// LimitObservation is what the limits layer needs to know about one action.
type LimitObservation struct {
	Project     string
	AgentKey    string // server-derived identity (auth key ID); "" treated as anon
	SessionID   string
	ToolName    string
	Risk        string // floored, normalized tier
	RawRisk     string // client label, for fail-closed detection
	ResourceID  string
	Recipient   string
	AmountCents int64
	UnixMillis  int64
}

type LimitStore struct {
	cfg     LimitsConfig
	backend limitBackend
}

func NewLimitStore(rdb *redis.Client, cfg LimitsConfig) *LimitStore {
	return &LimitStore{cfg: cfg, backend: redisLimitBackend{rdb: rdb}}
}

func NewMemoryLimitStore(cfg LimitsConfig) *LimitStore {
	return &LimitStore{cfg: cfg, backend: newMemoryLimitBackend()}
}

// Check evaluates every configured limit against one proposed action. It
// returns the blocking decision and fired=true when a limit rejects the action.
// Counters for allowed actions are consumed atomically; a blocked attempt never
// consumes budget.
func (ls *LimitStore) Check(ctx context.Context, obs LimitObservation) (ActionDecision, bool, error) {
	if ls == nil || ls.backend == nil || !ls.cfg.Enabled() {
		return ActionDecision{}, false, nil
	}
	now := obs.UnixMillis
	if now == 0 {
		now = time.Now().UnixMilli()
	}
	agent := obs.AgentKey
	if agent == "" {
		agent = AnonymousAgentKey
	}

	// Breaker first: a quarantined agent does not get to spend anything
	// fail-closed while the cooldown runs.
	if ls.cfg.Breaker.Trips > 0 && (FailClosedRisk(obs.RawRisk) || FailClosedRisk(obs.Risk)) {
		openUntil, ok, err := ls.backend.GetValue(ctx, limitKey("bo", "", obs.Project, agent, 0))
		if err != nil {
			return ActionDecision{}, false, fmt.Errorf("breaker state: %w", err)
		}
		if ok && openUntil > now {
			return blockActionDecision(
				SignalCircuitBreakerOpen,
				"agent is quarantined: repeated firewall blocks opened the circuit breaker",
				[]string{
					"breaker=open",
					fmt.Sprintf("open_until_ms=%d", openUntil),
					"agent_key=" + agent,
				},
				0.99,
				obs.SessionID,
			), true, nil
		}
	}

	for _, rule := range ls.cfg.Velocity {
		if !rule.matches(obs) {
			continue
		}
		scopeValue := limitScopeValue(rule.Scope, obs, agent)
		bucket := now / (int64(rule.WindowSeconds) * 1000)
		key := limitKey("v", rule.Name, obs.Project, scopeValue, bucket)
		over, err := ls.backend.Add(ctx, key, 1, int64(rule.MaxActions), 2*time.Duration(rule.WindowSeconds)*time.Second)
		if err != nil {
			return ActionDecision{}, false, fmt.Errorf("velocity %s: %w", rule.Name, err)
		}
		if over {
			return blockActionDecision(
				SignalVelocityExceeded,
				fmt.Sprintf("velocity limit %q exceeded: more than %d actions per %ds", rule.Name, rule.MaxActions, rule.WindowSeconds),
				[]string{
					"limit=" + rule.Name,
					fmt.Sprintf("max_actions=%d", rule.MaxActions),
					fmt.Sprintf("window_seconds=%d", rule.WindowSeconds),
					"scope=" + firstNonEmptyString(rule.Scope, "agent"),
				},
				0.99,
				obs.SessionID,
			), true, nil
		}
	}

	for _, rule := range ls.cfg.Cumulative {
		if obs.AmountCents <= 0 {
			continue
		}
		if rule.Tool != "" && rule.Tool != obs.ToolName {
			continue
		}
		scopeValue := limitScopeValue(rule.Scope, obs, agent)
		bucket := now / (int64(rule.WindowSeconds) * 1000)
		key := limitKey("c", rule.Name, obs.Project, scopeValue, bucket)
		over, err := ls.backend.Add(ctx, key, obs.AmountCents, rule.MaxAmountCents, 2*time.Duration(rule.WindowSeconds)*time.Second)
		if err != nil {
			return ActionDecision{}, false, fmt.Errorf("cumulative %s: %w", rule.Name, err)
		}
		if over {
			return blockActionDecision(
				SignalCumulativeAmountExceeded,
				fmt.Sprintf("cumulative amount cap %q exceeded: this action would push the %ds window past %d cents", rule.Name, rule.WindowSeconds, rule.MaxAmountCents),
				[]string{
					"limit=" + rule.Name,
					fmt.Sprintf("max_amount_cents=%d", rule.MaxAmountCents),
					fmt.Sprintf("amount_cents=%d", obs.AmountCents),
					fmt.Sprintf("window_seconds=%d", rule.WindowSeconds),
					"scope=" + firstNonEmptyString(rule.Scope, "agent"),
				},
				0.99,
				obs.SessionID,
			), true, nil
		}
	}

	return ActionDecision{}, false, nil
}

// RecordTrip counts one enforced block against the agent. Reaching the
// configured trip count opens the breaker for the cooldown; continued trips
// while open keep extending it.
func (ls *LimitStore) RecordTrip(ctx context.Context, project, agentKey string, unixMillis int64) error {
	if ls == nil || ls.backend == nil || ls.cfg.Breaker.Trips <= 0 {
		return nil
	}
	now := unixMillis
	if now == 0 {
		now = time.Now().UnixMilli()
	}
	if agentKey == "" {
		agentKey = AnonymousAgentKey
	}
	rule := ls.cfg.Breaker
	bucket := now / (int64(rule.WindowSeconds) * 1000)
	key := limitKey("bt", "", project, agentKey, bucket)
	// Max is Trips-1: the add that would exceed it IS the opening trip.
	over, err := ls.backend.Add(ctx, key, 1, int64(rule.Trips-1), 2*time.Duration(rule.WindowSeconds)*time.Second)
	if err != nil {
		return fmt.Errorf("breaker trip: %w", err)
	}
	if over {
		openUntil := now + int64(rule.CooldownSeconds)*1000
		ttl := time.Duration(rule.CooldownSeconds) * time.Second
		if err := ls.backend.SetValue(ctx, limitKey("bo", "", project, agentKey, 0), openUntil, ttl); err != nil {
			return fmt.Errorf("open breaker: %w", err)
		}
	}
	return nil
}

func (r VelocityRule) matches(obs LimitObservation) bool {
	if r.Tool != "" && r.Tool != obs.ToolName {
		return false
	}
	minRisk := r.MinRisk
	if minRisk == "" {
		minRisk = ActionRiskWrite
	}
	// Read-tier actions are never velocity-limited; the floor is write.
	if actionRiskRank(obs.Risk) < 1 {
		return false
	}
	return actionRiskRank(obs.Risk) >= actionRiskRank(minRisk)
}

// limitScopeValue picks the bucket identity for a rule. A missing scope value
// falls into a shared "unscoped" bucket rather than being skipped: an
// integration that omits resource ids must not thereby dodge a resource cap.
func limitScopeValue(scope string, obs LimitObservation, agent string) string {
	switch strings.ToLower(strings.TrimSpace(scope)) {
	case "", "agent":
		return "agent\x00" + agent
	case "session":
		return "session\x00" + firstNonEmptyString(obs.SessionID, "unscoped")
	case "resource":
		return "resource\x00" + firstNonEmptyString(actionValueFingerprint(obs.ResourceID), "unscoped")
	case "recipient":
		return "recipient\x00" + firstNonEmptyString(emailDomain(obs.Recipient), "unscoped")
	default:
		return "agent\x00" + agent
	}
}

// limitKey hashes every variable part so attacker-influenced values (sessions,
// projects) cannot alias another bucket by embedding separators.
func limitKey(kind, rule, project, scope string, bucket int64) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + rule + "\x00" + project + "\x00" + scope + "\x00" + strconv.FormatInt(bucket, 10)))
	return "limits:" + kind + ":" + fmt.Sprintf("%x", sum[:16])
}

// ---------- backends ----------

type limitBackend interface {
	// Add atomically adds delta to the counter at key, applying ttl on first
	// write. When the result would exceed max it rolls the addition back and
	// reports over=true, so blocked attempts never consume budget.
	Add(ctx context.Context, key string, delta, max int64, ttl time.Duration) (over bool, err error)
	SetValue(ctx context.Context, key string, value int64, ttl time.Duration) error
	GetValue(ctx context.Context, key string) (value int64, ok bool, err error)
}

type redisLimitBackend struct {
	rdb *redis.Client
}

var limitAddScript = redis.NewScript(`
local v = redis.call('INCRBY', KEYS[1], ARGV[1])
if v == tonumber(ARGV[1]) then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
if v > tonumber(ARGV[3]) then
  redis.call('DECRBY', KEYS[1], ARGV[1])
  return 1
end
return 0
`)

func (b redisLimitBackend) Add(ctx context.Context, key string, delta, max int64, ttl time.Duration) (bool, error) {
	if b.rdb == nil {
		return false, fmt.Errorf("redis client is nil")
	}
	res, err := limitAddScript.Run(ctx, b.rdb, []string{key}, delta, ttl.Milliseconds(), max).Int64()
	if err != nil {
		return false, err
	}
	return res == 1, nil
}

func (b redisLimitBackend) SetValue(ctx context.Context, key string, value int64, ttl time.Duration) error {
	if b.rdb == nil {
		return fmt.Errorf("redis client is nil")
	}
	return b.rdb.Set(ctx, key, value, ttl).Err()
}

func (b redisLimitBackend) GetValue(ctx context.Context, key string) (int64, bool, error) {
	if b.rdb == nil {
		return 0, false, fmt.Errorf("redis client is nil")
	}
	raw, err := b.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse limit value: %w", err)
	}
	return value, true, nil
}

// memoryLimitBackend is for tests and embedded use. Buckets are addressed by
// observation-time window indices, so stale buckets are simply never read
// again; it does not garbage-collect (fine for short-lived processes).
type memoryLimitBackend struct {
	mu     sync.Mutex
	values map[string]int64
}

func newMemoryLimitBackend() *memoryLimitBackend {
	return &memoryLimitBackend{values: map[string]int64{}}
}

func (b *memoryLimitBackend) Add(ctx context.Context, key string, delta, max int64, _ time.Duration) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	default:
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	next := b.values[key] + delta
	if next > max {
		return true, nil
	}
	b.values[key] = next
	return false, nil
}

func (b *memoryLimitBackend) SetValue(ctx context.Context, key string, value int64, _ time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.values[key] = value
	return nil
}

func (b *memoryLimitBackend) GetValue(ctx context.Context, key string) (int64, bool, error) {
	select {
	case <-ctx.Done():
		return 0, false, ctx.Err()
	default:
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	value, ok := b.values[key]
	return value, ok, nil
}
