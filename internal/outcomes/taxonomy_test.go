package outcomes

import "testing"

func TestNormalizeResultClass(t *testing.T) {
	tests := map[string]ResultClass{
		"SUCCESS":                ResultClassSuccess,
		"file-not-found":         ResultClassNotFound,
		"deadline_exceeded":      ResultClassTimeout,
		"403":                    ResultClassPermissionError,
		"validation error":       ResultClassSchemaError,
		"too many requests":      ResultClassRateLimited,
		"empty":                  ResultClassEmptyResult,
		"same_output":            ResultClassNoStateDelta,
		"duplicate_side_effect":  ResultClassDuplicate,
		"already executed":       ResultClassDuplicate,
		"custom provider status": ResultClassUnknown,
		"":                       ResultClassUnknown,
	}

	for raw, want := range tests {
		if got := NormalizeResultClass(raw); got != want {
			t.Fatalf("NormalizeResultClass(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestNormalizeRiskClass(t *testing.T) {
	tests := map[string]RiskClass{
		"read":             RiskClassReadOnly,
		"customer-visible": RiskClassCustomerVisible,
		"High":             RiskClassCustomerVisible,
		"refund":           RiskClassMoneyMovement,
		"db/write":         RiskClassDataMutation,
		"dangerous":        RiskClassDestructive,
		"deploy":           RiskClassInfrastructure,
		"custom":           RiskClassUnknown,
		"":                 RiskClassUnknown,
	}

	for raw, want := range tests {
		if got := NormalizeRiskClass(raw); got != want {
			t.Fatalf("NormalizeRiskClass(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestMapResultToOutcome(t *testing.T) {
	tests := []struct {
		name   string
		result ResultClass
		risk   RiskClass
		want   OutcomeCategory
	}{
		{"duplicate", ResultClassDuplicate, RiskClassMoneyMovement, OutcomeDuplicateSideEffect},
		{"empty", ResultClassEmptyResult, RiskClassReadOnly, OutcomeSemanticNoProgress},
		{"no state delta", ResultClassNoStateDelta, RiskClassCustomerVisible, OutcomeSemanticNoProgress},
		{"timeout", ResultClassTimeout, RiskClassReadOnly, OutcomeBenignRetry},
		{"rate limit", ResultClassRateLimited, RiskClassReadOnly, OutcomeBenignRetry},
		{"permission", ResultClassPermissionError, RiskClassInfrastructure, OutcomeApprovalRequired},
		{"not found", ResultClassNotFound, RiskClassReadOnly, OutcomeTerminalToolFailure},
		{"schema", ResultClassSchemaError, RiskClassCustomerVisible, OutcomeTerminalToolFailure},
		{"unknown destructive", ResultClassUnknown, RiskClassDestructive, OutcomeUnsafeMutation},
		{"success", ResultClassSuccess, RiskClassReadOnly, OutcomeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MapResultToOutcome(tt.result, tt.risk); got != tt.want {
				t.Fatalf("MapResultToOutcome(%q, %q)=%q want %q", tt.result, tt.risk, got, tt.want)
			}
		})
	}
}

func TestMapResultToOutcomeNormalizesInputs(t *testing.T) {
	got := MapResultToOutcome(ResultClass("duplicate side-effect"), RiskClass("payment"))
	if got != OutcomeDuplicateSideEffect {
		t.Fatalf("MapResultToOutcome normalized raw aliases to %q want %q", got, OutcomeDuplicateSideEffect)
	}
}

func TestNormalizeEnvironment(t *testing.T) {
	tests := map[string]Environment{
		"production":     EnvironmentProduction,
		"PROD":           EnvironmentProduction,
		"live":           EnvironmentProduction,
		"staging":        EnvironmentStaging,
		"pre-production": EnvironmentStaging,
		"uat":            EnvironmentStaging,
		"development":    EnvironmentDevelopment,
		"local":          EnvironmentDevelopment,
		"sandbox":        EnvironmentDevelopment,
		"test":           EnvironmentTest,
		"ci":             EnvironmentTest,
		"something-else": EnvironmentUnknown,
		"":               EnvironmentUnknown,
	}
	for raw, want := range tests {
		if got := NormalizeEnvironment(raw); got != want {
			t.Fatalf("NormalizeEnvironment(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestNormalizeRecipientType(t *testing.T) {
	tests := map[string]RecipientType{
		"internal":        RecipientInternal,
		"employee":        RecipientInternal,
		"customer":        RecipientExternalCustomer,
		"end-user":        RecipientExternalCustomer,
		"external_vendor": RecipientExternalVendor,
		"partner":         RecipientExternalVendor,
		"third party":     RecipientExternalVendor,
		"self":            RecipientSelf,
		"system":          RecipientSelf,
		"none":            RecipientNone,
		"not_applicable":  RecipientNone,
		"mystery":         RecipientUnknown,
		"":                RecipientUnknown,
	}
	for raw, want := range tests {
		if got := NormalizeRecipientType(raw); got != want {
			t.Fatalf("NormalizeRecipientType(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestNormalizeOperationType(t *testing.T) {
	tests := map[string]OperationType{
		"create":   OperationCreate,
		"insert":   OperationCreate,
		"read":     OperationRead,
		"list":     OperationRead,
		"search":   OperationRead,
		"update":   OperationUpdate,
		"patch":    OperationUpdate,
		"delete":   OperationDelete,
		"drop":     OperationDelete,
		"send":     OperationSend,
		"notify":   OperationSend,
		"execute":  OperationExecute,
		"deploy":   OperationExecute,
		"weird-op": OperationUnknown,
		"":         OperationUnknown,
	}
	for raw, want := range tests {
		if got := NormalizeOperationType(raw); got != want {
			t.Fatalf("NormalizeOperationType(%q)=%q want %q", raw, got, want)
		}
	}
}
