package loop

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const stateTTL = 10 * time.Minute

// StateStore persists per-(project, session) detector state in Redis.
// Key format: loop:{project}:{session}. TTL: 10 minutes.
// The State is small (bounded slices, capped at 12 entries) so a single
// GET/SET is fast and stays well under 1ms on a local Redis.
//
// Concurrency: Use Transact() for the hot path — it uses WATCH/MULTI for
// optimistic concurrency so two concurrent requests for the same session
// don't clobber each other's state. Load/Save are retained for tests.
type StateStore struct {
	rdb *redis.Client
}

// NewStateStore creates a StateStore backed by the given Redis client.
func NewStateStore(rdb *redis.Client) *StateStore {
	return &StateStore{rdb: rdb}
}

func stateKey(project, sessionID string) string {
	return fmt.Sprintf("loop:%s:%s", project, sessionID)
}

// Load retrieves the State for a (project, session) pair.
// Returns an empty State if the key does not exist.
func (ss *StateStore) Load(ctx context.Context, project, sessionID string) (State, error) {
	data, err := ss.rdb.Get(ctx, stateKey(project, sessionID)).Bytes()
	if err == redis.Nil {
		return NewState(), nil
	}
	if err != nil {
		return NewState(), fmt.Errorf("redis get loop state: %w", err)
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return NewState(), fmt.Errorf("unmarshal loop state: %w", err)
	}
	s.ensureInit()
	return s, nil
}

// Save persists the State with a 10-minute TTL.
func (ss *StateStore) Save(ctx context.Context, project, sessionID string, s State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal loop state: %w", err)
	}

	if err := ss.rdb.Set(ctx, stateKey(project, sessionID), data, stateTTL).Err(); err != nil {
		return fmt.Errorf("redis set loop state: %w", err)
	}
	return nil
}

// maxTransactRetries limits optimistic lock retries to bound latency.
const maxTransactRetries = 3

// Transact atomically loads state, applies fn, and saves the result.
// Uses Redis WATCH/MULTI for optimistic concurrency — if another request
// modifies the same key between our GET and SET, the transaction is retried
// up to 3 times before returning an error (caller should fail-open).
func (ss *StateStore) Transact(ctx context.Context, project, sessionID string, fn func(State) State) (State, error) {
	key := stateKey(project, sessionID)
	var result State

	for attempt := 0; attempt < maxTransactRetries; attempt++ {
		err := ss.rdb.Watch(ctx, func(tx *redis.Tx) error {
			// GET within WATCH — any external modification invalidates the tx
			data, err := tx.Get(ctx, key).Bytes()
			var state State
			if err == redis.Nil {
				state = NewState()
			} else if err != nil {
				return fmt.Errorf("redis get in transact: %w", err)
			} else {
				if err := json.Unmarshal(data, &state); err != nil {
					state = NewState() // corrupted state — reset
				}
				state.ensureInit()
			}

			// Apply the pure function (detector logic, no I/O)
			result = fn(state)

			// SET within MULTI/EXEC — atomic with the WATCH
			newData, err := json.Marshal(result)
			if err != nil {
				return fmt.Errorf("marshal state in transact: %w", err)
			}

			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				pipe.Set(ctx, key, newData, stateTTL)
				return nil
			})
			return err
		}, key)

		if err == nil {
			return result, nil
		}
		if err == redis.TxFailedErr {
			continue // optimistic lock conflict — retry
		}
		return result, fmt.Errorf("redis transact: %w", err)
	}

	return result, fmt.Errorf("redis transact: max retries (%d) exceeded", maxTransactRetries)
}
