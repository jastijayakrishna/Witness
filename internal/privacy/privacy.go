package privacy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/hubbleops/hubbleops/internal/moatmetrics"
)

const (
	CaptureModeFingerprint = "fingerprint"
	CaptureModeRaw         = "raw"
)

var (
	ErrRawCaptureDisabled = errors.New("raw capture is disabled")

	emailPattern            = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	phonePattern            = regexp.MustCompile(`\b(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b`)
	ssnPattern              = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	creditCardPattern       = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	secretAssignmentPattern = regexp.MustCompile(`(?i)\b(password|token|api[_-]?key|secret|authorization)\b\s*[:=]\s*[^,\s;&]+`)
	safeLabelPattern        = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,96}$`)
	fingerprintPattern      = regexp.MustCompile(`^(sha256:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{16,128}|(?:fp|hash):[A-Za-z0-9_+=:./-]{16,128})$`)

	sensitiveKeys = map[string]struct{}{
		"password":      {},
		"token":         {},
		"api_key":       {},
		"apikey":        {},
		"secret":        {},
		"authorization": {},
		"email":         {},
		"phone":         {},
		"ssn":           {},
		"credit_card":   {},
		"creditcard":    {},
		"card_number":   {},
		"cardnumber":    {},
		"address":       {},
	}

	rawSensitiveKeys = map[string]struct{}{
		"args":            {},
		"arguments":       {},
		"body":            {},
		"content":         {},
		"crm":             {},
		"db_row":          {},
		"dbrow":           {},
		"file":            {},
		"idempotency_key": {},
		"idempotencykey":  {},
		"messages":        {},
		"payment":         {},
		"pii":             {},
		"prompt":          {},
		"raw":             {},
		"raw_args":        {},
		"rawargs":         {},
		"raw_body":        {},
		"rawbody":         {},
		"raw_output":      {},
		"rawoutput":       {},
		"resource_id":     {},
		"resourceid":      {},
	}
)

// FingerprintString returns a stable sha256 fingerprint for non-empty text.
func FingerprintString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return FingerprintBytes([]byte(value))
}

// FingerprintBytes returns a stable sha256 fingerprint for non-empty bytes.
func FingerprintBytes(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// FingerprintJSON returns a stable fingerprint of JSON-like data after privacy
// normalization. Sensitive values affect the hash, but raw values do not appear
// in any intermediate representation returned by this package.
func FingerprintJSON(value any) string {
	normalized := RedactKnownSecrets(jsonLikeValue(value))
	return FingerprintString(canonicalValue(normalized))
}

// RedactKnownSecrets recursively replaces obvious sensitive values with
// fingerprints and safe structural metadata.
func RedactKnownSecrets(value any) any {
	return redactKnownSecrets(jsonLikeValue(value))
}

// RejectRawCaptureIfDisabled returns an error when a caller asks for raw capture
// without an explicit raw-capture enablement.
func RejectRawCaptureIfDisabled(captureMode string, rawEnabled bool) error {
	captureMode = strings.ToLower(strings.TrimSpace(captureMode))
	if captureMode == "" {
		captureMode = CaptureModeFingerprint
	}
	if captureMode == CaptureModeRaw && !rawEnabled {
		moatmetrics.RecordRawCaptureRejection()
		return ErrRawCaptureDisabled
	}
	return nil
}

// SafeEvidence converts signals and evidence snippets into JSON that can be
// stored in the reviewed-decision corpus without raw args, PII, or secrets.
func SafeEvidence(signals, evidence []string) []byte {
	items := make([]map[string]string, 0, len(signals)+len(evidence))
	for _, signal := range signals {
		signal = strings.TrimSpace(signal)
		if signal == "" {
			continue
		}
		if IsSafeLabel(signal) && !ContainsSensitiveText(signal) {
			items = append(items, map[string]string{"signal": signal})
			continue
		}
		items = append(items, map[string]string{"signal_fingerprint": FingerprintString(signal)})
	}
	for _, item := range evidence {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if IsSafeLabel(item) && !ContainsSensitiveText(item) {
			items = append(items, map[string]string{"evidence_code": item})
			continue
		}
		if parsed, ok := parseJSONValue(item); ok {
			moatmetrics.RecordPrivacyRedaction()
			items = append(items, map[string]string{
				"evidence_fingerprint": FingerprintJSON(parsed),
				"evidence_shape":       shapeName(parsed),
			})
			continue
		}
		moatmetrics.RecordPrivacyRedaction()
		items = append(items, map[string]string{"evidence_fingerprint": FingerprintString(item)})
	}
	if len(items) == 0 {
		items = append(items, map[string]string{"signal": "none"})
	}
	data, err := json.Marshal(items)
	if err != nil {
		return []byte("[]")
	}
	return data
}

func IsSafeLabel(value string) bool {
	return safeLabelPattern.MatchString(strings.TrimSpace(value))
}

func IsFingerprint(value string) bool {
	return fingerprintPattern.MatchString(strings.TrimSpace(value))
}

func IsSensitiveKey(key string) bool {
	normalized := normalizeKey(key)
	if _, ok := sensitiveKeys[normalized]; ok {
		return true
	}
	for marker := range sensitiveKeys {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func IsRawSensitiveKey(key string) bool {
	normalized := normalizeKey(key)
	if _, ok := rawSensitiveKeys[normalized]; ok {
		return true
	}
	return IsSensitiveKey(key)
}

func ContainsSensitiveText(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	if emailPattern.MatchString(value) ||
		phonePattern.MatchString(value) ||
		ssnPattern.MatchString(value) ||
		secretAssignmentPattern.MatchString(value) ||
		containsCreditCard(value) {
		return true
	}
	for _, marker := range []string{
		"password", "token", "api_key", "api-key", "apikey", "secret",
		"authorization", "bearer ", "email", "phone", "ssn",
		"credit_card", "credit-card", "card_number", "card-number",
		"address", "raw_args", "raw_body", "raw_output", "prompt",
		"payment", "crm", "db_row", "private_key", "idempotency_key",
		"resource_id",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func RedactString(value string) string {
	out := emailPattern.ReplaceAllStringFunc(value, redactionMarker)
	out = phonePattern.ReplaceAllStringFunc(out, redactionMarker)
	out = ssnPattern.ReplaceAllStringFunc(out, redactionMarker)
	out = creditCardPattern.ReplaceAllStringFunc(out, func(match string) string {
		if containsCreditCard(match) {
			return redactionMarker(match)
		}
		return match
	})
	out = secretAssignmentPattern.ReplaceAllStringFunc(out, redactionMarker)
	return out
}

func redactKnownSecrets(value any) any {
	switch typed := value.(type) {
	case nil, bool, float64, int, int64, uint64:
		return typed
	case string:
		if ContainsSensitiveText(typed) {
			redacted := RedactString(typed)
			if redacted == typed {
				moatmetrics.RecordPrivacyRedaction()
			}
			return redacted
		}
		return typed
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, redactKnownSecrets(item))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			if IsSensitiveKey(key) {
				moatmetrics.RecordPrivacyRedaction()
				out[sensitiveFieldKey(key)] = fingerprintedValue(child)
				continue
			}
			out[safeFieldKey(key)] = redactKnownSecrets(child)
		}
		return out
	default:
		return redactKnownSecrets(jsonLikeValue(typed))
	}
}

func fingerprintedValue(value any) map[string]any {
	parsed := jsonLikeValue(value)
	return map[string]any{
		"hubbleops_capture": "fingerprint",
		"sha256":          strings.TrimPrefix(fingerprintRaw(parsed), "sha256:"),
		"type":            shapeName(parsed),
		"shape":           structuralShape(parsed),
	}
}

func structuralShape(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		fields := make([]string, 0, len(typed))
		for key := range typed {
			if IsSensitiveKey(key) {
				fields = append(fields, sensitiveFieldKey(key))
				continue
			}
			fields = append(fields, safeFieldKey(key))
		}
		sort.Strings(fields)
		return map[string]any{"type": "object", "fields": fields}
	case []any:
		return map[string]any{"type": "array", "length": len(typed)}
	case string:
		return map[string]any{"type": "string", "length_bucket": lengthBucket(len(typed))}
	case nil:
		return map[string]any{"type": "null"}
	case bool:
		return map[string]any{"type": "bool"}
	default:
		return map[string]any{"type": "number"}
	}
}

func fingerprintRaw(value any) string {
	return FingerprintString(canonicalValue(jsonLikeValue(value)))
}

func canonicalValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case float64, int, int64, uint64:
		data, _ := json.Marshal(typed)
		return string(data)
	case string:
		data, _ := json.Marshal(typed)
		return string(data)
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, canonicalValue(item))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			keyJSON, _ := json.Marshal(key)
			parts = append(parts, string(keyJSON)+":"+canonicalValue(typed[key]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		return canonicalValue(jsonLikeValue(typed))
	}
}

func jsonLikeValue(value any) any {
	switch typed := value.(type) {
	case nil, bool, float64, string, []any, map[string]any:
		if s, ok := typed.(string); ok {
			if parsed, ok := parseJSONValue(s); ok {
				return parsed
			}
		}
		return typed
	case []byte:
		if parsed, ok := parseJSONValue(string(typed)); ok {
			return parsed
		}
		return string(typed)
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return fmt.Sprintf("%v", typed)
		}
		var parsed any
		if err := json.Unmarshal(data, &parsed); err != nil {
			return string(data)
		}
		return parsed
	}
}

func parseJSONValue(value string) (any, bool) {
	value = strings.TrimSpace(value)
	if value == "" || !json.Valid([]byte(value)) {
		return nil, false
	}
	var parsed any
	if err := json.Unmarshal([]byte(value), &parsed); err != nil {
		return nil, false
	}
	return parsed, true
}

func normalizeKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	replacer := strings.NewReplacer("-", "_", " ", "_", ".", "_")
	return strings.Trim(replacer.Replace(key), "_")
}

func safeFieldKey(key string) string {
	key = normalizeKey(key)
	if IsSafeLabel(key) && !ContainsSensitiveText(key) {
		return key
	}
	return "field_hash_" + shortHash(key)
}

func sensitiveFieldKey(key string) string {
	return "sensitive_field_" + shortHash(normalizeKey(key))
}

func shortHash(value string) string {
	fp := FingerprintString(value)
	if len(fp) < len("sha256:")+16 {
		return "unknown"
	}
	return fp[len("sha256:") : len("sha256:")+16]
}

func redactionMarker(value string) string {
	moatmetrics.RecordPrivacyRedaction()
	return "<redacted:" + FingerprintString(value) + ">"
}

func shapeName(value any) string {
	switch value.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case nil:
		return "null"
	case bool:
		return "bool"
	default:
		return "number"
	}
}

func lengthBucket(length int) string {
	switch {
	case length <= 0:
		return "0"
	case length <= 16:
		return "1_16"
	case length <= 64:
		return "17_64"
	case length <= 256:
		return "65_256"
	default:
		return "256_plus"
	}
}

func containsCreditCard(value string) bool {
	return creditCardPattern.MatchString(value) && len(onlyDigits(value)) >= 13
}

func onlyDigits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
