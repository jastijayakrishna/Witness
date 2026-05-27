package proxy

import (
	"crypto/sha256"
	"fmt"
	"net/http"
)

const (
	headerProject       = "X-Project"
	headerSession       = "X-Session-ID"
	headerAuthorization = "Authorization"
	defaultProject      = "unknown"
)

// ResolveProject determines the project identifier for a request.
// Priority: X-Project header → SHA256(Authorization header) → "unknown".
func ResolveProject(r *http.Request) string {
	if project := r.Header.Get(headerProject); project != "" {
		return project
	}
	if auth := r.Header.Get(headerAuthorization); auth != "" {
		hash := sha256.Sum256([]byte(auth))
		return fmt.Sprintf("key:%x", hash[:16])
	}
	return defaultProject
}

// ResolveSession returns the X-Session-ID header value, or empty string.
// Load-bearing for the loop detector's safety floor: the detector never
// hard-stops (blocks) a request that has no session ID.
func ResolveSession(r *http.Request) string {
	return r.Header.Get(headerSession)
}
