package proxy

import (
	"net/http"
	"strings"

	"github.com/hubbleops/hubbleops/internal/loop"
)

func classifyProviderResponse(statusCode int, body []byte) string {
	if statusCode >= 200 && statusCode < 300 {
		return ""
	}

	lower := strings.ToLower(string(body))
	switch {
	case statusCode == http.StatusTooManyRequests ||
		containsProviderError(lower, "resource_exhausted", "rate limit", "rate_limit", "too many requests", "quota", "throttl"):
		return loop.ResultRateLimited
	case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden ||
		containsProviderError(lower, "api key", "apikey", "unauthorized", "unauthenticated", "forbidden", "permission", "permission_denied", "access denied"):
		return loop.ResultPermissionError
	case statusCode == http.StatusRequestTimeout || statusCode == http.StatusGatewayTimeout ||
		containsProviderError(lower, "timeout", "timed out", "deadline", "deadline_exceeded"):
		return loop.ResultTimeout
	case statusCode == http.StatusBadRequest || statusCode == http.StatusUnprocessableEntity ||
		containsProviderError(lower, "invalid_argument", "bad request", "schema", "validation", "invalid json", "parse error", "malformed"):
		return loop.ResultSchemaError
	case statusCode == http.StatusNotFound:
		return loop.ResultNotFound
	default:
		return loop.ResultUnknownError
	}
}

func containsProviderError(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
