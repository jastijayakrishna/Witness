package proxy

import (
	"crypto/sha256"
	"fmt"
	"net/http"
)

const (
	headerProject       = "X-Project"
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
