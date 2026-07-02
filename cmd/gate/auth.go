package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/hubbleops/hubbleops/internal/config"
)

// principal is the authenticated caller behind a request. Identity and Roles come from a
// verified credential, never from the request body, so an approval can be attributed to a
// caller who actually proved who they are.
type principal struct {
	Identity string
	Roles    []string
}

// gateAuth maps opaque API tokens to principals. Tokens are stored only as SHA-256 hashes
// and compared in constant time, so the in-memory map never holds a usable secret and
// lookups do not leak token length/contents via timing.
type gateAuth struct {
	disabled bool
	tokens   map[string]principal // hex(sha256(token)) -> principal
}

func newGateAuth(tokens map[string]principal) *gateAuth {
	hashed := make(map[string]principal, len(tokens))
	for tok, p := range tokens {
		hashed[hashToken(tok)] = p
	}
	return &gateAuth{tokens: hashed}
}

func disabledGateAuth() *gateAuth { return &gateAuth{disabled: true} }

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(tok)))
	return hex.EncodeToString(sum[:])
}

func (a *gateAuth) lookup(tok string) (principal, bool) {
	if a == nil {
		return principal{}, false
	}
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return principal{}, false
	}
	want := hashToken(tok)
	for stored, p := range a.tokens {
		if subtle.ConstantTimeCompare([]byte(stored), []byte(want)) == 1 {
			return p, true
		}
	}
	return principal{}, false
}

type principalCtxKey struct{}

func withPrincipal(ctx context.Context, p principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

func principalFrom(ctx context.Context) (principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(principal)
	return p, ok
}

func bearerToken(r *http.Request) string {
	if key := strings.TrimSpace(r.Header.Get("X-HubbleOps-API-Key")); key != "" {
		return key
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) > 7 && strings.EqualFold(authz[:7], "bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}

func (s *server) authEnabled() bool {
	return s.auth != nil && !s.auth.disabled
}

// requireAuth gates a handler on a valid credential. When auth is disabled (local dev),
// it injects a synthetic "dev" principal so handlers behave as before. When enabled, a
// missing/invalid credential is a hard 401 — fail closed.
func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authEnabled() {
			next(w, r.WithContext(withPrincipal(r.Context(), principal{Identity: "dev", Roles: []string{"dev"}})))
			return
		}
		p, ok := s.auth.lookup(bearerToken(r))
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing or invalid API credential")
			return
		}
		next(w, r.WithContext(withPrincipal(r.Context(), p)))
	}
}

// authorizedApprover reports whether the authenticated principal may approve an action
// whose policy requires one of `required`. An empty requirement means any authenticated
// principal may review; otherwise the principal's identity or one of its roles must match.
func authorizedApprover(p principal, required []string) bool {
	if len(required) == 0 {
		return true
	}
	candidates := append([]string{p.Identity}, p.Roles...)
	for _, req := range required {
		req = strings.TrimSpace(req)
		if req == "" {
			continue
		}
		for _, candidate := range candidates {
			if strings.EqualFold(strings.TrimSpace(candidate), req) {
				return true
			}
		}
	}
	return false
}

// loadGateAuth builds the gate's auth config from the validated runtime config plus token
// env, failing CLOSED when auth is enabled but no tokens are configured. Format:
//
//	HUBBLEOPS_GATE_TOKENS="tok1=alice:sre|billing-owner,tok2=bob"
func loadGateAuth(authCfg config.AuthConfig) (*gateAuth, error) {
	if !authCfg.Enabled {
		return disabledGateAuth(), nil
	}
	raw := strings.TrimSpace(os.Getenv("HUBBLEOPS_GATE_TOKENS"))
	if raw == "" {
		return nil, fmt.Errorf("gate auth is not configured: set HUBBLEOPS_GATE_TOKENS, or set HUBBLEOPS_AUTH_ENABLED=false outside production")
	}
	tokens := map[string]principal{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		tok, spec, ok := strings.Cut(entry, "=")
		tok = strings.TrimSpace(tok)
		if !ok || tok == "" {
			return nil, fmt.Errorf("invalid HUBBLEOPS_GATE_TOKENS entry %q: want token=identity[:role|role]", entry)
		}
		identity, rolesRaw, _ := strings.Cut(spec, ":")
		identity = strings.TrimSpace(identity)
		if identity == "" {
			return nil, fmt.Errorf("invalid HUBBLEOPS_GATE_TOKENS entry %q: identity is required", entry)
		}
		var roles []string
		for _, role := range strings.Split(rolesRaw, "|") {
			if r := strings.TrimSpace(role); r != "" {
				roles = append(roles, r)
			}
		}
		tokens[tok] = principal{Identity: identity, Roles: roles}
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("HUBBLEOPS_GATE_TOKENS parsed to zero tokens")
	}
	return newGateAuth(tokens), nil
}
