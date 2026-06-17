package privacy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestRedactKnownSecretsRedactsSecrets(t *testing.T) {
	input := map[string]any{
		"token":    "hubbleops_live_secret_token",
		"password": "correct-horse-battery-staple",
		"safe":     "duplicate_side_effect",
	}

	redacted := RedactKnownSecrets(input)
	encoded := mustJSON(t, redacted)

	for _, forbidden := range []string{"hubbleops_live_secret_token", "correct-horse-battery-staple", `"token"`, `"password"`} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("redaction leaked %q: %s", forbidden, encoded)
		}
	}
	if !strings.Contains(encoded, `"hubbleops_capture":"fingerprint"`) || !strings.Contains(encoded, `"sha256"`) {
		t.Fatalf("redaction did not keep fingerprint metadata: %s", encoded)
	}
	if !strings.Contains(encoded, "duplicate_side_effect") {
		t.Fatalf("safe metadata should remain readable: %s", encoded)
	}
}

func TestEmailNotStoredRaw(t *testing.T) {
	redacted := RedactKnownSecrets("notify customer@example.com before retry")
	encoded := mustJSON(t, redacted)

	if strings.Contains(encoded, "customer@example.com") {
		t.Fatalf("email leaked raw: %s", encoded)
	}
	if !strings.Contains(encoded, "sha256:") {
		t.Fatalf("redacted email should be fingerprinted: %s", encoded)
	}
}

func TestNestedJSONHandled(t *testing.T) {
	input := map[string]any{
		"action": "send_email",
		"payload": map[string]any{
			"profile": map[string]any{
				"email":   "nested@example.com",
				"api_key": "sk_live_nested",
			},
		},
	}

	encoded := mustJSON(t, RedactKnownSecrets(input))
	for _, forbidden := range []string{"nested@example.com", "sk_live_nested", `"email"`, `"api_key"`} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("nested JSON leaked %q: %s", forbidden, encoded)
		}
	}
	if !strings.Contains(encoded, "send_email") {
		t.Fatalf("safe action label should remain: %s", encoded)
	}
}

func TestArraysHandled(t *testing.T) {
	input := map[string]any{
		"recipients": []any{
			map[string]any{"phone": "415-555-1212"},
			map[string]any{"credit_card": "4242 4242 4242 4242"},
			"safe_signal",
		},
	}

	encoded := mustJSON(t, RedactKnownSecrets(input))
	for _, forbidden := range []string{"415-555-1212", "4242 4242 4242 4242", `"phone"`, `"credit_card"`} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("array redaction leaked %q: %s", forbidden, encoded)
		}
	}
	if !strings.Contains(encoded, "safe_signal") {
		t.Fatalf("safe array item should remain: %s", encoded)
	}
}

func TestStableFingerprints(t *testing.T) {
	left := FingerprintJSON(map[string]any{
		"b": []any{2.0, 1.0},
		"a": map[string]any{"email": "stable@example.com"},
	})
	right := FingerprintJSON(map[string]any{
		"a": map[string]any{"email": "stable@example.com"},
		"b": []any{2.0, 1.0},
	})
	changed := FingerprintJSON(map[string]any{
		"a": map[string]any{"email": "other@example.com"},
		"b": []any{2.0, 1.0},
	})

	if left == "" || !strings.HasPrefix(left, "sha256:") {
		t.Fatalf("fingerprint=%q", left)
	}
	if left != right {
		t.Fatalf("fingerprint not stable: %s != %s", left, right)
	}
	if left == changed {
		t.Fatalf("different sensitive value produced same fingerprint: %s", left)
	}
}

func TestRejectRawCaptureIfDisabled(t *testing.T) {
	if err := RejectRawCaptureIfDisabled("fingerprint", false); err != nil {
		t.Fatalf("fingerprint mode rejected: %v", err)
	}
	if err := RejectRawCaptureIfDisabled("raw", true); err != nil {
		t.Fatalf("enabled raw mode rejected: %v", err)
	}
	if err := RejectRawCaptureIfDisabled("raw", false); !errors.Is(err, ErrRawCaptureDisabled) {
		t.Fatalf("err=%v want ErrRawCaptureDisabled", err)
	}
}

func TestSafeEvidenceDoesNotStoreRawSensitiveData(t *testing.T) {
	raw := `{"email":"customer@example.com","nested":{"token":"secret-token"},"items":[{"card_number":"4242424242424242"}]}`
	evidence := SafeEvidence([]string{"duplicate_side_effect"}, []string{raw})
	encoded := string(evidence)

	for _, forbidden := range []string{"customer@example.com", "secret-token", "4242424242424242", `"email"`, `"token"`, `"card_number"`} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("safe evidence leaked %q: %s", forbidden, encoded)
		}
	}
	if !strings.Contains(encoded, "duplicate_side_effect") || !strings.Contains(encoded, "evidence_fingerprint") {
		t.Fatalf("safe evidence missing useful metadata: %s", encoded)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(data)
}
