package outcomes

import (
	"regexp"
	"strings"
)

type OutcomeCategory string

const (
	OutcomeDuplicateSideEffect OutcomeCategory = "duplicate_side_effect"
	OutcomeSemanticNoProgress  OutcomeCategory = "semantic_no_progress"
	OutcomeBenignRetry         OutcomeCategory = "benign_retry"
	OutcomeTerminalToolFailure OutcomeCategory = "terminal_tool_failure"
	OutcomeUnsafeMutation      OutcomeCategory = "unsafe_mutation"
	OutcomeUnboundedCostGrowth OutcomeCategory = "unbounded_cost_growth"
	OutcomeContextBloat        OutcomeCategory = "context_bloat"
	OutcomeFalseSuccess        OutcomeCategory = "false_success"
	OutcomeApprovalRequired    OutcomeCategory = "approval_required"
	OutcomePolicyViolation     OutcomeCategory = "policy_violation"
	OutcomeUnknown             OutcomeCategory = "unknown"
)

type ResultClass string

const (
	ResultClassSuccess         ResultClass = "success"
	ResultClassNotFound        ResultClass = "not_found"
	ResultClassTimeout         ResultClass = "timeout"
	ResultClassPermissionError ResultClass = "permission_error"
	ResultClassSchemaError     ResultClass = "schema_error"
	ResultClassRateLimited     ResultClass = "rate_limited"
	ResultClassEmptyResult     ResultClass = "empty_result"
	ResultClassNoStateDelta    ResultClass = "no_state_delta"
	ResultClassDuplicate       ResultClass = "duplicate"
	ResultClassUnknown         ResultClass = "unknown"
)

type RiskClass string

const (
	RiskClassReadOnly        RiskClass = "read_only"
	RiskClassCustomerVisible RiskClass = "customer_visible"
	RiskClassMoneyMovement   RiskClass = "money_movement"
	RiskClassDataMutation    RiskClass = "data_mutation"
	RiskClassDestructive     RiskClass = "destructive"
	RiskClassInfrastructure  RiskClass = "infrastructure"
	RiskClassUnknown         RiskClass = "unknown"
)

// Environment captures where a consequential action ran. Production failures are
// worth far more as training signal than sandbox noise, so it must be captured at
// decision time — it cannot be reconstructed later from fingerprints.
type Environment string

const (
	EnvironmentProduction  Environment = "production"
	EnvironmentStaging     Environment = "staging"
	EnvironmentDevelopment Environment = "development"
	EnvironmentTest        Environment = "test"
	EnvironmentUnknown     Environment = "unknown"
)

// RecipientType captures who/what a side effect touched. "external_customer" plus
// a destructive operation is the high-value combination policy learning cares about.
type RecipientType string

const (
	RecipientInternal         RecipientType = "internal"
	RecipientExternalCustomer RecipientType = "external_customer"
	RecipientExternalVendor   RecipientType = "external_vendor"
	RecipientSelf             RecipientType = "self"
	RecipientNone             RecipientType = "none"
	RecipientUnknown          RecipientType = "unknown"
)

// OperationType is the verb of the action, normalized across frameworks so that a
// "delete" is comparable whether it came from SQL, an HTTP DELETE, or a tool name.
type OperationType string

const (
	OperationCreate  OperationType = "create"
	OperationRead    OperationType = "read"
	OperationUpdate  OperationType = "update"
	OperationDelete  OperationType = "delete"
	OperationSend    OperationType = "send"
	OperationExecute OperationType = "execute"
	OperationUnknown OperationType = "unknown"
)

var tokenRE = regexp.MustCompile(`[^a-z0-9_]+`)

func NormalizeResultClass(raw string) ResultClass {
	switch normalizeToken(raw) {
	case "success", "ok", "succeeded", "complete", "completed":
		return ResultClassSuccess
	case "not_found", "notfound", "missing", "no_result", "not_found_error", "file_not_found", "does_not_exist", "404":
		return ResultClassNotFound
	case "timeout", "timed_out", "timedout", "time_out", "deadline", "deadline_exceeded":
		return ResultClassTimeout
	case "permission_error", "permission", "permission_denied", "forbidden", "unauthorized", "auth_error", "access_denied", "401", "403":
		return ResultClassPermissionError
	case "schema_error", "schema", "parse_error", "validation_error", "invalid_json", "invalid_schema", "bad_request", "invalid_argument", "type_mismatch", "400":
		return ResultClassSchemaError
	case "rate_limited", "rate_limit", "ratelimit", "too_many_requests", "throttled", "throttle", "429":
		return ResultClassRateLimited
	case "empty_result", "empty", "null", "none", "no_data", "no_rows", "zero_results":
		return ResultClassEmptyResult
	case "no_state_delta", "same_output", "unchanged", "no_change", "same_state", "no_progress":
		return ResultClassNoStateDelta
	case "duplicate", "duplicate_action", "duplicate_side_effect", "already_done", "already_executed", "dedupe_hit":
		return ResultClassDuplicate
	default:
		return ResultClassUnknown
	}
}

func NormalizeRiskClass(raw string) RiskClass {
	switch normalizeToken(raw) {
	case "read_only", "read", "readonly", "read_only_action", "low", "lookup", "search", "query":
		return RiskClassReadOnly
	case "customer_visible", "side_effect", "side_effecting", "write", "medium", "high", "email", "ticket", "crm", "notification", "message", "send_email":
		return RiskClassCustomerVisible
	case "money_movement", "money", "payment", "payments", "refund", "charge", "billing", "payout", "invoice", "purchase":
		return RiskClassMoneyMovement
	case "data_mutation", "db_write", "database_write", "write_delete", "update", "upsert", "insert", "delete_record", "mutate", "mutation":
		return RiskClassDataMutation
	case "destructive", "dangerous", "danger", "critical", "delete", "drop", "wipe", "destroy", "truncate", "purge":
		return RiskClassDestructive
	case "infrastructure", "infra", "shell", "filesystem", "deploy", "deployment", "kubernetes", "cloud", "server", "database_admin", "backup", "restore":
		return RiskClassInfrastructure
	default:
		return RiskClassUnknown
	}
}

func MapResultToOutcome(result ResultClass, risk RiskClass) OutcomeCategory {
	result = NormalizeResultClass(string(result))
	risk = NormalizeRiskClass(string(risk))

	switch result {
	case ResultClassDuplicate:
		return OutcomeDuplicateSideEffect
	case ResultClassEmptyResult, ResultClassNoStateDelta:
		return OutcomeSemanticNoProgress
	case ResultClassTimeout, ResultClassRateLimited:
		return OutcomeBenignRetry
	case ResultClassPermissionError:
		return OutcomeApprovalRequired
	case ResultClassNotFound, ResultClassSchemaError:
		return OutcomeTerminalToolFailure
	case ResultClassUnknown:
		switch risk {
		case RiskClassMoneyMovement, RiskClassDataMutation, RiskClassDestructive:
			return OutcomeUnsafeMutation
		}
	}
	return OutcomeUnknown
}

func NormalizeEnvironment(raw string) Environment {
	switch normalizeToken(raw) {
	case "production", "prod", "live", "prd":
		return EnvironmentProduction
	case "staging", "stage", "stg", "preprod", "pre_production", "preproduction", "uat", "qa":
		return EnvironmentStaging
	case "development", "dev", "local", "localhost", "sandbox", "sbx":
		return EnvironmentDevelopment
	case "test", "testing", "ci", "cicd":
		return EnvironmentTest
	default:
		return EnvironmentUnknown
	}
}

func NormalizeRecipientType(raw string) RecipientType {
	switch normalizeToken(raw) {
	case "internal", "employee", "staff", "team", "first_party", "firstparty", "colleague":
		return RecipientInternal
	case "external_customer", "customer", "client", "end_user", "enduser", "user", "subscriber":
		return RecipientExternalCustomer
	case "external_vendor", "vendor", "partner", "supplier", "third_party", "thirdparty", "contractor":
		return RecipientExternalVendor
	case "self", "system", "agent", "service", "internal_system":
		return RecipientSelf
	case "none", "na", "not_applicable", "no_recipient", "noone":
		return RecipientNone
	default:
		return RecipientUnknown
	}
}

func NormalizeOperationType(raw string) OperationType {
	switch normalizeToken(raw) {
	case "create", "insert", "add", "new", "post", "provision", "register", "write":
		return OperationCreate
	case "read", "get", "list", "query", "search", "fetch", "lookup", "select", "describe":
		return OperationRead
	case "update", "modify", "edit", "patch", "upsert", "change", "put", "set":
		return OperationUpdate
	case "delete", "remove", "drop", "destroy", "purge", "truncate", "wipe":
		return OperationDelete
	case "send", "email", "notify", "message", "dispatch", "publish", "post_message", "notification":
		return OperationSend
	case "execute", "run", "exec", "invoke", "call", "deploy", "trigger", "perform":
		return OperationExecute
	default:
		return OperationUnknown
	}
}

func normalizeToken(raw string) string {
	token := strings.ToLower(strings.TrimSpace(raw))
	token = strings.NewReplacer("-", "_", " ", "_", "/", "_", ".", "_", ":", "_").Replace(token)
	token = tokenRE.ReplaceAllString(token, "_")
	return strings.Trim(token, "_")
}
