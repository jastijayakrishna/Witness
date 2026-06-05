package loop

import (
	"encoding/json"
	"regexp"
	"strings"
)

const (
	ResultSuccess         = "success"
	ResultEmpty           = "empty"
	ResultNotFound        = "not_found"
	ResultTimeout         = "timeout"
	ResultPermissionError = "permission_error"
	ResultSchemaError     = "schema_error"
	ResultSameOutput      = "same_output"
	ResultPending         = "pending"
	ResultRateLimited     = "rate_limited"
	ResultUnknownError    = "unknown_error"
	ResultDuplicateAction = "duplicate_side_effect"
)

var resultClassRE = regexp.MustCompile(`[^a-z0-9_]+`)

func normalizeResultClass(class string) string {
	class = strings.ToLower(strings.TrimSpace(class))
	class = resultClassRE.ReplaceAllString(class, "_")
	class = strings.Trim(class, "_")
	switch class {
	case "", ResultSuccess, ResultEmpty, ResultNotFound, ResultTimeout,
		ResultPermissionError, ResultSchemaError, ResultSameOutput, ResultPending,
		ResultRateLimited, ResultUnknownError, ResultDuplicateAction:
		return class
	case "notfound", "missing", "no_result", "not_found_error":
		return ResultNotFound
	case "timed_out", "deadline", "deadline_exceeded":
		return ResultTimeout
	case "permission", "forbidden", "unauthorized", "auth_error":
		return ResultPermissionError
	case "schema", "parse_error", "validation_error", "invalid_json":
		return ResultSchemaError
	case "queued", "running", "waiting", "processing", "in_progress":
		return ResultPending
	case "rate_limit", "ratelimit", "too_many_requests", "throttled", "throttle":
		return ResultRateLimited
	case "duplicate_action", "duplicate", "already_done", "already_executed":
		return ResultDuplicateAction
	case "error", "failed", "failure", "exception":
		return ResultUnknownError
	default:
		return class
	}
}

func NormalizeResultClassForAPI(class string) string {
	return normalizeResultClass(class)
}

// ClassifyResult converts arbitrary tool output into a low-cardinality progress
// class. The detector treats repeated failure classes as no-progress evidence
// even when arguments mutate.
func ClassifyResult(result any) string {
	if result == nil {
		return ResultEmpty
	}

	text := strings.TrimSpace(resultText(result))
	if text == "" || text == "null" || text == "{}" || text == "[]" {
		return ResultEmpty
	}

	lower := strings.ToLower(text)
	switch {
	case containsAny(lower, "duplicate side-effect", "duplicate_side_effect", "already executed", "already_done", "already happened"):
		return ResultDuplicateAction
	case containsAny(lower, "rate limit", "rate_limit", "too many requests", "429", "throttled"):
		return ResultRateLimited
	case containsAny(lower, "file_not_found", "not_found", "not found", "no such file", "does not exist", "404", "missing"):
		return ResultNotFound
	case containsAny(lower, "timeout", "timed out", "deadline exceeded", "deadline_exceeded"):
		return ResultTimeout
	case containsAny(lower, "permission", "unauthorized", "forbidden", "access denied", "401", "403"):
		return ResultPermissionError
	case containsAny(lower, "schema", "invalid json", "parse error", "validation", "type mismatch", "invalid_argument"):
		return ResultSchemaError
	case containsAny(lower, `"status":"pending"`, `"status":"queued"`, `"status":"running"`, `"status":"processing"`, `"state":"pending"`):
		return ResultPending
	case containsAny(lower, `"ok":true`, `"success":true`, `"status":"ok"`, `"status":"success"`, "completed", "succeeded"):
		return ResultSuccess
	case containsAny(lower, "error", "failed", "failure", "exception", `"status":"failed"`, `"code":500`, "server_error"):
		return ResultUnknownError
	default:
		return ResultSuccess
	}
}

func isFailureClass(class string) bool {
	switch normalizeResultClass(class) {
	case ResultNotFound, ResultTimeout, ResultPermissionError, ResultSchemaError, ResultRateLimited, ResultUnknownError, ResultDuplicateAction:
		return true
	default:
		return false
	}
}

func isNoProgressClass(class string) bool {
	switch normalizeResultClass(class) {
	case ResultEmpty, ResultSameOutput:
		return true
	default:
		return isFailureClass(class)
	}
}

func resultText(result any) string {
	if s, ok := result.(string); ok {
		return s
	}
	b, err := json.Marshal(result)
	if err != nil {
		return stringify(result)
	}
	return string(b)
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
