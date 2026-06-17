package proxy

import (
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/hubbleops/hubbleops/internal/auth"
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
	if project, ok := auth.ProjectFromContext(r.Context()); ok {
		return project
	}
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

// BindSession scopes a client-supplied session under the authenticated API-key identity.
// The session label alone is attacker-controlled: rotating it sheds loop-detector history
// and reusing another agent's label pollutes that agent's state. Namespacing under the
// key identity makes both impossible across keys, and an authenticated caller that omits
// the session still gets a stable per-key one — so enforcement floors that require a
// session (RequireSessionForBlock) cannot be dodged by omission. Unauthenticated
// requests (auth disabled / dev bypass) keep today's verbatim behavior.
func BindSession(r *http.Request, session string) string {
	keyID, ok := auth.KeyIDFromContext(r.Context())
	if !ok {
		return session
	}
	if session == "" {
		return "key:" + keyID
	}
	return "key:" + keyID + ":" + session
}
