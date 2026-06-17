package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type contextKey string

const (
	projectContextKey contextKey = "hubbleops.auth.project"
	keyIDContextKey   contextKey = "hubbleops.auth.key_id"
)

type Options struct {
	Store         KeyStore
	Enabled       bool
	DevBypass     bool
	Environment   string
	MetricsPublic bool
	Now           func() time.Time
}

func Middleware(opts Options) func(http.Handler) http.Handler {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	env := strings.ToLower(strings.TrimSpace(opts.Environment))
	if env == "" {
		env = "prod"
	}
	devBypass := opts.DevBypass && env == "dev"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if IsAlwaysPublicPath(r.URL.Path) || (opts.MetricsPublic && r.URL.Path == "/metrics") {
				next.ServeHTTP(w, r)
				return
			}
			if !opts.Enabled {
				next.ServeHTTP(w, r)
				return
			}
			if devBypass {
				project := strings.TrimSpace(r.Header.Get(HeaderProject))
				if project == "" {
					project = "dev"
					r.Header.Set(HeaderProject, project)
				}
				next.ServeHTTP(w, withProject(r, project))
				return
			}
			if opts.Store == nil {
				writeAuthError(w, http.StatusServiceUnavailable, "auth_unavailable")
				return
			}

			rawKey := strings.TrimSpace(r.Header.Get(HeaderAPIKey))
			if rawKey == "" {
				writeAuthError(w, http.StatusUnauthorized, "missing_api_key")
				return
			}
			key, err := opts.Store.LookupAPIKey(r.Context(), rawKey)
			if errors.Is(err, ErrInvalidKey) {
				writeAuthError(w, http.StatusUnauthorized, "invalid_api_key")
				return
			}
			if err != nil {
				writeAuthError(w, http.StatusServiceUnavailable, "auth_unavailable")
				return
			}
			if key.Disabled || key.Expired(opts.Now()) {
				writeAuthError(w, http.StatusUnauthorized, "invalid_api_key")
				return
			}
			project := strings.TrimSpace(key.Project)
			if project == "" {
				writeAuthError(w, http.StatusServiceUnavailable, "auth_unavailable")
				return
			}
			if requested := strings.TrimSpace(r.Header.Get(HeaderProject)); requested != "" && requested != project {
				writeAuthError(w, http.StatusForbidden, "project_mismatch")
				return
			}

			r.Header.Set(HeaderProject, project)
			next.ServeHTTP(w, withIdentity(r, project, KeyID(rawKey)))
		})
	}
}

func IsAlwaysPublicPath(path string) bool {
	switch path {
	case "/healthz", "/livez", "/readyz":
		return true
	default:
		return false
	}
}

func ProjectFromContext(ctx context.Context) (string, bool) {
	project, ok := ctx.Value(projectContextKey).(string)
	return project, ok && project != ""
}

// KeyIDFromContext returns the stable identity of the API key that authenticated this
// request. It is the trustworthy "who" for session scoping and attribution — unlike any
// client-supplied header, the caller cannot choose or rotate it.
func KeyIDFromContext(ctx context.Context) (string, bool) {
	keyID, ok := ctx.Value(keyIDContextKey).(string)
	return keyID, ok && keyID != ""
}

// WithIdentity is for tests and trusted internal callers that need an authenticated
// project + key identity without standing up the HTTP middleware.
func WithIdentity(ctx context.Context, project, keyID string) context.Context {
	return context.WithValue(WithProject(ctx, project), keyIDContextKey, keyID)
}

func withIdentity(r *http.Request, project, keyID string) *http.Request {
	return r.WithContext(WithIdentity(r.Context(), project, keyID))
}

func withProject(r *http.Request, project string) *http.Request {
	ctx := context.WithValue(r.Context(), projectContextKey, project)
	return r.WithContext(ctx)
}

// WithProject is for tests and trusted internal callers that need to exercise
// authenticated request paths without standing up the HTTP middleware.
func WithProject(ctx context.Context, project string) context.Context {
	return context.WithValue(ctx, projectContextKey, project)
}

func writeAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"type": code,
		},
	})
}
