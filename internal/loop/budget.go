package loop

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const budgetKeyTTL = 48 * time.Hour // keys expire after 2 days

// defaultReservePerRequest is the per-request budget reservation in USD.
// Concurrent requests each atomically claim this amount before running,
// preventing the TOCTOU gap where N requests all pass a read-only check
// and then all record their costs, blowing past the hard cap. After the
// request completes, Adjust() trues up the reservation to the actual cost.
const defaultReservePerRequest = 0.50

// BudgetEnforcer tracks per-project daily spending and enforces caps.
// Keys are partitioned by date (in the project's configured timezone) so
// budgets reset at midnight in the project's local time, not UTC.
type BudgetEnforcer struct {
	rdb               *redis.Client
	dailySoftUSD      float64
	dailyHardUSD      float64
	reservePerRequest float64
}

// NewBudgetEnforcer creates a BudgetEnforcer with the given daily caps.
// Pass 0 for a cap to disable it (no enforcement).
// reservePerRequest is the per-request reservation amount for atomic budget
// gating. Pass 0 to use the default ($0.50).
func NewBudgetEnforcer(rdb *redis.Client, dailySoftUSD, dailyHardUSD, reservePerRequest float64) *BudgetEnforcer {
	reserve := reservePerRequest
	if reserve <= 0 {
		reserve = defaultReservePerRequest
	}
	return &BudgetEnforcer{
		rdb:               rdb,
		dailySoftUSD:      dailySoftUSD,
		dailyHardUSD:      dailyHardUSD,
		reservePerRequest: reserve,
	}
}

// BudgetStatus indicates whether a project has exceeded its budget.
type BudgetStatus string

const (
	BudgetOK       BudgetStatus = "ok"
	BudgetSoftHit  BudgetStatus = "soft" // warn
	BudgetHardHit  BudgetStatus = "hard" // block
)

// BudgetCheck is the result of checking a project's budget before a request.
type BudgetCheck struct {
	Status       BudgetStatus
	SpentToday   float64 // total spent so far today (before this request)
	SoftLimitUSD float64 // configured soft limit (0 = disabled)
	HardLimitUSD float64 // configured hard limit (0 = disabled)
}

// Reserve atomically increments the daily spend by the per-request reserve
// amount and checks whether the result exceeds the hard or soft cap.
//
// This fixes the TOCTOU gap in the old Check/Record split: under concurrency,
// N requests could all pass a read-only Check while spend was under the limit,
// then all Record after running, blowing past the hard cap. With Reserve, each
// concurrent request atomically claims its slot via INCRBYFLOAT, so the second
// request sees the first's reservation in the total and gets rejected.
//
// If the hard cap is exceeded, the reservation is rolled back atomically and
// BudgetHardHit is returned. The caller MUST call Adjust() after the request
// completes to true-up the reservation to the actual cost.
func (be *BudgetEnforcer) Reserve(ctx context.Context, project string) (BudgetCheck, error) {
	if be.dailyHardUSD <= 0 && be.dailySoftUSD <= 0 {
		return BudgetCheck{Status: BudgetOK}, nil // both disabled
	}

	key := budgetKey(project, time.Now())
	newTotal, err := be.rdb.IncrByFloat(ctx, key, be.reservePerRequest).Result()
	if err != nil {
		return BudgetCheck{}, fmt.Errorf("redis incrbyfloat budget reserve: %w", err)
	}

	// Set TTL on first write (INCRBYFLOAT creates the key if absent)
	if newTotal <= be.reservePerRequest {
		be.rdb.Expire(ctx, key, budgetKeyTTL)
	}

	spentBefore := newTotal - be.reservePerRequest

	check := BudgetCheck{
		Status:       BudgetOK,
		SpentToday:   spentBefore,
		SoftLimitUSD: be.dailySoftUSD,
		HardLimitUSD: be.dailyHardUSD,
	}

	// Hard limit: reject if this reservation would push total over the cap
	if be.dailyHardUSD > 0 && newTotal > be.dailyHardUSD {
		// Roll back the reservation — we're not running this request
		be.rdb.IncrByFloat(ctx, key, -be.reservePerRequest)
		check.Status = BudgetHardHit
	} else if be.dailySoftUSD > 0 && newTotal > be.dailySoftUSD {
		check.Status = BudgetSoftHit
	}

	return check, nil
}

// Adjust corrects the reservation to the actual cost after the request
// completes. Does INCRBYFLOAT(actualCost - reservePerRequest) so the
// running total reflects real spend, not estimated spend. Must be called
// after every successful Reserve.
func (be *BudgetEnforcer) Adjust(ctx context.Context, project string, actualCost float64) error {
	diff := actualCost - be.reservePerRequest
	if diff == 0 {
		return nil
	}
	key := budgetKey(project, time.Now())
	return be.rdb.IncrByFloat(ctx, key, diff).Err()
}

// Record increments the project's daily spend by the given cost.
// Call this AFTER the request completes and you have the actual cost.
func (be *BudgetEnforcer) Record(ctx context.Context, project string, costUSD float64) error {
	if costUSD <= 0 {
		return nil // nothing to record
	}

	key := budgetKey(project, time.Now())
	newTotal, err := be.rdb.IncrByFloat(ctx, key, costUSD).Result()
	if err != nil {
		return fmt.Errorf("redis incrbyfloat budget: %w", err)
	}

	// Set TTL on first write (INCRBYFLOAT doesn't set TTL automatically)
	if newTotal == costUSD {
		be.rdb.Expire(ctx, key, budgetKeyTTL)
	}

	return nil
}

// budgetKey returns the Redis key for a project's daily budget on the given date.
// Format: budget:daily:{project}:{YYYY-MM-DD}
// TODO: Use project-configured timezone instead of UTC. For v1, UTC is acceptable
// because most projects care about "don't burn >$X in 24h", not calendar-day alignment.
func budgetKey(project string, t time.Time) string {
	date := t.UTC().Format("2006-01-02")
	return fmt.Sprintf("budget:daily:%s:%s", project, date)
}
