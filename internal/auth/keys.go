package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const (
	HeaderAPIKey  = "X-HubbleOps-API-Key"
	HeaderProject = "X-Project"

	hashPrefix = "sha256:"
)

// KeyRecord is the authenticated project binding for one API key.
type KeyRecord struct {
	Project   string
	Disabled  bool
	ExpiresAt *time.Time
}

func (k KeyRecord) Expired(now time.Time) bool {
	return k.ExpiresAt != nil && !k.ExpiresAt.After(now)
}

// HashAPIKey returns the deterministic value stored in api_keys.key_hash.
func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hashPrefix + hex.EncodeToString(sum[:])
}

// KeyID derives the short, stable identity of an API key: the first 16 hex chars of its
// hash. It identifies the key without being usable to authenticate as it, so it is safe
// to embed in session scopes, receipts, and logs.
func KeyID(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:8])
}

func legacyHashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}
