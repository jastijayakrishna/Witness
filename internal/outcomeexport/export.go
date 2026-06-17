package outcomeexport

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hubbleops/hubbleops/internal/moatmetrics"
	"github.com/hubbleops/hubbleops/internal/outcomes"
	"github.com/hubbleops/hubbleops/internal/privacy"
	"github.com/hubbleops/hubbleops/internal/storage"
)

var codePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,96}$`)

type Options struct {
	Anonymize        bool
	Salt             string
	IncludeCostExact bool
	ReviewedOnly     bool
}

type Record struct {
	ActionType          string   `json:"action_type"`
	ActionRisk          string   `json:"action_risk"`
	ActionNameHash      string   `json:"action_name_hash"`
	ToolSignatureHash   string   `json:"tool_signature_hash,omitempty"`
	ResultClass         string   `json:"result_class"`
	Environment         string   `json:"environment"`
	RecipientType       string   `json:"recipient_type"`
	OperationType       string   `json:"operation_type"`
	HubbleOpsAction       string   `json:"hubbleops_action"`
	DecisionReason      string   `json:"decision_reason"`
	EvidenceCodes       []string `json:"evidence_codes,omitempty"`
	PolicyVersion       string   `json:"policy_version"`
	DetectorVersion     string   `json:"detector_version"`
	CustomerReviewLabel string   `json:"customer_review_label,omitempty"`
	EstimatedCostBucket string   `json:"estimated_cost_bucket"`
	EstimatedCostUSD    *float64 `json:"estimated_cost_usd_exact,omitempty"`
	CreatedAtBucketDay  string   `json:"created_at_bucket_day"`
}

func WriteJSONL(w io.Writer, rows []storage.ActionDecisionOutcomeExport, opts Options) (int, error) {
	if !opts.Anonymize {
		return 0, fmt.Errorf("anonymized export requires anonymize=true")
	}
	if strings.TrimSpace(opts.Salt) == "" {
		return 0, fmt.Errorf("anonymized export requires a non-empty salt")
	}
	enc := json.NewEncoder(w)
	count := 0
	for _, row := range rows {
		if opts.ReviewedOnly && strings.TrimSpace(row.ReviewLabel) == "" {
			continue
		}
		rec := BuildRecord(row, opts)
		if err := enc.Encode(rec); err != nil {
			moatmetrics.RecordExportRecords(count)
			return count, err
		}
		count++
	}
	moatmetrics.RecordExportRecords(count)
	return count, nil
}

func BuildRecord(row storage.ActionDecisionOutcomeExport, opts Options) Record {
	outcome := row.Outcome
	rec := Record{
		ActionType:          normalizeCode(outcome.ActionType, "unknown"),
		ActionRisk:          string(outcomes.NormalizeRiskClass(outcome.ActionRisk)),
		ActionNameHash:      scopedHash("action_name", outcome.ActionName, opts.Salt),
		ToolSignatureHash:   scopedHash("tool_signature", firstNonEmpty(outcome.ToolSignatureHash, outcome.ActionName), opts.Salt),
		ResultClass:         string(outcomes.NormalizeResultClass(outcome.ResultClass)),
		Environment:         string(outcomes.NormalizeEnvironment(outcome.Environment)),
		RecipientType:       string(outcomes.NormalizeRecipientType(outcome.RecipientType)),
		OperationType:       string(outcomes.NormalizeOperationType(outcome.OperationType)),
		HubbleOpsAction:       normalizeCode(outcome.HubbleOpsAction, "unknown"),
		DecisionReason:      safeReason(outcome.DecisionReason),
		EvidenceCodes:       evidenceCodes(outcome.EvidenceJSON),
		PolicyVersion:       safeVersion(outcome.PolicyVersion),
		DetectorVersion:     safeVersion(outcome.DetectorVersion),
		CustomerReviewLabel: normalizeCode(row.ReviewLabel, ""),
		EstimatedCostBucket: costBucket(outcome.EstimatedCostUSD),
		CreatedAtBucketDay:  dayBucket(outcome.CreatedAt),
	}
	if opts.IncludeCostExact && outcome.EstimatedCostUSD != nil {
		exact := *outcome.EstimatedCostUSD
		rec.EstimatedCostUSD = &exact
	}
	return rec
}

func scopedHash(scope, value, salt string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = "unknown"
	}
	sum := sha256.Sum256([]byte(salt + "\x00" + scope + "\x00" + value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func normalizeCode(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.NewReplacer(" ", "_", "-", "_", "/", "_").Replace(value)
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == ':' {
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "_.:")
	if out == "" {
		return fallback
	}
	if len(out) > 96 {
		return out[:96]
	}
	return out
}

func safeReason(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if value == "" {
		return "unspecified"
	}
	if strings.ContainsAny(value, "{}[]\"'\n\r\t@") || privacy.ContainsSensitiveText(value) {
		return "raw_sensitive_redacted"
	}
	if len(value) > 160 {
		return value[:157] + "..."
	}
	return value
}

func safeVersion(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if value == "" {
		return "unknown"
	}
	if strings.ContainsAny(value, "{}[]\"'\n\r\t@") || privacy.ContainsSensitiveText(value) {
		return "redacted"
	}
	if len(value) > 96 {
		return value[:96]
	}
	return value
}

func evidenceCodes(raw []byte) []string {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil
	}
	codes := map[string]struct{}{}
	collectEvidenceCodes(parsed, codes, false)
	out := make([]string, 0, len(codes))
	for code := range codes {
		out = append(out, code)
	}
	sort.Strings(out)
	if len(out) > 10 {
		return out[:10]
	}
	return out
}

func collectEvidenceCodes(value any, codes map[string]struct{}, allowBareString bool) {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			collectEvidenceCodes(item, codes, true)
		}
	case map[string]any:
		for key, child := range typed {
			normalizedKey := normalizeCode(key, "")
			if isEvidenceCodeKey(normalizedKey) {
				addEvidenceValue(child, codes)
			}
			if isUnsafeEvidenceKey(normalizedKey) {
				continue
			}
			collectEvidenceCodes(child, codes, false)
		}
	case string:
		if allowBareString {
			addEvidenceCode(typed, codes)
		}
	}
}

func addEvidenceValue(value any, codes map[string]struct{}) {
	switch typed := value.(type) {
	case string:
		addEvidenceCode(typed, codes)
	case []any:
		for _, item := range typed {
			addEvidenceValue(item, codes)
		}
	}
}

func addEvidenceCode(value string, codes map[string]struct{}) {
	code := normalizeCode(value, "")
	if code == "" || privacy.ContainsSensitiveText(value) || !codePattern.MatchString(code) {
		return
	}
	codes[code] = struct{}{}
}

func isEvidenceCodeKey(key string) bool {
	switch key {
	case "code", "evidence_code", "reason_code", "signal", "type":
		return true
	default:
		return false
	}
}

func isUnsafeEvidenceKey(key string) bool {
	return privacy.IsRawSensitiveKey(key)
}

func costBucket(value *float64) string {
	if value == nil {
		return "unknown"
	}
	v := *value
	switch {
	case v <= 0:
		return "0"
	case v <= 0.01:
		return "0_0.01"
	case v <= 0.10:
		return "0.01_0.10"
	case v <= 1:
		return "0.10_1"
	case v <= 10:
		return "1_10"
	default:
		return "10_plus"
	}
}

func dayBucket(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format("2006-01-02")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
