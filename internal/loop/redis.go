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
// Concurrency note: Load/Save is a non-atomic read-modify-write. Two
// concurrent requests for the same (project, session) will race — last
// write wins, dropping one turn from detector history. This is acceptable
// in Phase 3 (shadow mode, no enforcement) because agent sessions are
// typically serialized. Phase 4 should replace this with a server-side
// Lua script (EVALSHA) that does GET-append-SET atomically.
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
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("redis get loop state: %w", err)
	}

	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("unmarshal loop state: %w", err)
	}
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
