package loop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	overrideTokenTTL = 5 * time.Minute
	overridePrefix   = "ovr_"
)

// OverrideStore manages one-shot override tokens in Redis.
// When the detector blocks a request, it mints a token the client can use
// to bypass the block exactly once. A false positive costs one retry, not
// a dead pipeline.
type OverrideStore struct {
	rdb *redis.Client
}

// NewOverrideStore creates an OverrideStore backed by the given Redis client.
func NewOverrideStore(rdb *redis.Client) *OverrideStore {
	return &OverrideStore{rdb: rdb}
}

// Mint generates a new override token, stores it in Redis with a 5-minute TTL,
// and returns the token string (prefixed with "ovr_").
func (os *OverrideStore) Mint(ctx context.Context, project, sessionID string) (string, error) {
	// Generate 16 random bytes → 32 hex chars
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate override token: %w", err)
	}
	token := overridePrefix + hex.EncodeToString(buf)

	// Store token → (project, session) mapping with TTL
	key := overrideKey(token)
	value := fmt.Sprintf("%s:%s", project, sessionID)
	if err := os.rdb.Set(ctx, key, value, overrideTokenTTL).Err(); err != nil {
		return "", fmt.Errorf("store override token: %w", err)
	}

	return token, nil
}

// Consume checks if the token exists and matches the (project, session) pair.
// If valid, it deletes the token (one-shot) and returns true.
// If invalid or already consumed, returns false.
func (os *OverrideStore) Consume(ctx context.Context, token, project, sessionID string) (bool, error) {
	key := overrideKey(token)

	// GETDEL: atomic get-and-delete in a single command (Redis 6.2+).
	val, err := os.rdb.GetDel(ctx, key).Result()
	if err == redis.Nil {
		return false, nil // token doesn't exist or already consumed
	}
	if err != nil {
		return false, fmt.Errorf("consume override token: %w", err)
	}

	expected := fmt.Sprintf("%s:%s", project, sessionID)
	return val == expected, nil
}

func overrideKey(token string) string {
	return fmt.Sprintf("override:%s", token)
}
