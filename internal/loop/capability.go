package loop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const capabilityTokenPrefix = "witcap_v1"

type Capability struct {
	Version        string `json:"version"`
	Project        string `json:"project,omitempty"`
	AgentID        string `json:"agent_id,omitempty"`
	UserID         string `json:"user_id,omitempty"`
	ActionName     string `json:"action_name,omitempty"`
	ResourceID     string `json:"resource_id,omitempty"`
	MaxAmountCents int64  `json:"max_amount_cents,omitempty"`
	ExpiresUnix    int64  `json:"expires_unix,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
}

func IssueCapability(secret []byte, cap Capability) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("capability secret is required")
	}
	if cap.Version == "" {
		cap.Version = capabilityTokenPrefix
	}
	payload, err := json.Marshal(cap)
	if err != nil {
		return "", fmt.Errorf("marshal capability: %w", err)
	}
	sig := signCapabilityPayload(secret, payload)
	return capabilityTokenPrefix + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func VerifyCapability(secret []byte, token string, obs ActionObservation, now time.Time) (Capability, error) {
	if len(secret) == 0 {
		return Capability{}, fmt.Errorf("capability secret is not configured")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != capabilityTokenPrefix {
		return Capability{}, fmt.Errorf("invalid capability token format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Capability{}, fmt.Errorf("invalid capability payload")
	}
	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Capability{}, fmt.Errorf("invalid capability signature encoding")
	}
	wantSig := signCapabilityPayload(secret, payload)
	if !hmac.Equal(gotSig, wantSig) {
		return Capability{}, fmt.Errorf("invalid capability signature")
	}

	var cap Capability
	if err := json.Unmarshal(payload, &cap); err != nil {
		return Capability{}, fmt.Errorf("invalid capability JSON")
	}
	if cap.Version != "" && cap.Version != capabilityTokenPrefix {
		return Capability{}, fmt.Errorf("unsupported capability version")
	}
	if cap.ExpiresUnix > 0 && now.Unix() > cap.ExpiresUnix {
		return Capability{}, fmt.Errorf("capability expired")
	}
	if err := requireCapabilityMatch("project", cap.Project, obs.Project); err != nil {
		return Capability{}, err
	}
	if err := requireCapabilityMatch("agent_id", cap.AgentID, obs.AgentID); err != nil {
		return Capability{}, err
	}
	if err := requireCapabilityMatch("user_id", cap.UserID, obs.UserID); err != nil {
		return Capability{}, err
	}
	if err := requireCapabilityMatch("action_name", cap.ActionName, obs.ToolName); err != nil {
		return Capability{}, err
	}
	if cap.ResourceID != "" {
		if obs.ResourceID == "" {
			return Capability{}, fmt.Errorf("resource_id required by capability")
		}
		if err := requireCapabilityMatch("resource_id", cap.ResourceID, obs.ResourceID); err != nil {
			return Capability{}, err
		}
	}
	if cap.MaxAmountCents > 0 && obs.AmountCents > cap.MaxAmountCents {
		return Capability{}, fmt.Errorf("amount exceeds capability")
	}
	return cap, nil
}

func signCapabilityPayload(secret, payload []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return mac.Sum(nil)
}

func requireCapabilityMatch(field, want, got string) error {
	if want == "" {
		return nil
	}
	if got == "" {
		return fmt.Errorf("%s required by capability", field)
	}
	if !strings.EqualFold(want, got) {
		return fmt.Errorf("%s outside capability", field)
	}
	return nil
}
