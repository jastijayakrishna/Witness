package receipts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hubbleops/hubbleops/internal/wal"
)

// signatureVersion is bumped to v2 for the move from symmetric HMAC-SHA256 to asymmetric
// Ed25519. Receipts are now signed with a private key and verified with the corresponding
// public key, so an external auditor can verify authenticity without holding any secret
// that would let them forge receipts. The signing secret never leaves the server; the
// public key (PublicKeyFromSecret) is what gets published.
const signatureVersion = "hubbleopsreceipt_v2"

type Signer struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

// NewSigner derives a deterministic Ed25519 keypair from the configured signing secret.
// Keeping the secret-based config means no key-rotation/storage changes for operators,
// while the signature itself becomes asymmetric: the secret stays server-side and the
// derived public key (PublicKeyBase64) is handed to verifiers.
func NewSigner(keyID string, secret []byte) *Signer {
	keyID = normalizeKeyID(keyID)
	if len(secret) == 0 {
		return &Signer{keyID: keyID}
	}
	priv := privateKeyFromSecret(secret)
	return &Signer{keyID: keyID, priv: priv, pub: priv.Public().(ed25519.PublicKey)}
}

func normalizeKeyID(keyID string) string {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		keyID = "local"
	}
	return keyID
}

// privateKeyFromSecret deterministically maps an arbitrary secret to an Ed25519 private
// key by using its SHA-256 as the 32-byte seed. The same secret always yields the same
// keypair, so receipts remain verifiable across restarts and instances.
func privateKeyFromSecret(secret []byte) ed25519.PrivateKey {
	seed := sha256.Sum256(secret)
	return ed25519.NewKeyFromSeed(seed[:])
}

// PublicKeyFromSecret returns the public half of the keypair derived from a signing
// secret. Operators publish this so auditors can verify receipts without the secret.
func PublicKeyFromSecret(secret []byte) ed25519.PublicKey {
	if len(secret) == 0 {
		return nil
	}
	return privateKeyFromSecret(secret).Public().(ed25519.PublicKey)
}

// PublicKeyBase64 returns the signer's published verification key.
func (s *Signer) PublicKeyBase64() string {
	if s == nil || len(s.pub) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(s.pub)
}

// KeyID returns the signer's key identifier.
func (s *Signer) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

func (s *Signer) SignRecord(rec wal.Record) (string, string, error) {
	if s == nil || len(s.priv) == 0 {
		return "", "", nil
	}
	sig, err := signWithKey(s.priv, rec)
	if err != nil {
		return "", "", err
	}
	return sig, s.keyID, nil
}

// SignRecord signs a record with the keypair derived from secret. Retained for callers
// and tests that work from the raw secret.
func SignRecord(secret []byte, rec wal.Record) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("receipt signing secret is required")
	}
	return signWithKey(privateKeyFromSecret(secret), rec)
}

func signWithKey(priv ed25519.PrivateKey, rec wal.Record) (string, error) {
	payload, err := canonicalPayload(rec)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, payload)
	return signatureVersion + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyRecord verifies a receipt using the keypair derived from secret. Internally it
// verifies against the public key, so it proves the same thing an external verifier would.
func VerifyRecord(secret []byte, rec wal.Record) error {
	pub := PublicKeyFromSecret(secret)
	if pub == nil {
		return fmt.Errorf("receipt signing secret is required")
	}
	return VerifyRecordWithPublicKey(pub, rec)
}

// VerifyRecordWithPublicKey verifies a receipt signature with only the public key — the
// path an external auditor uses. It cannot be used to produce a signature.
func VerifyRecordWithPublicKey(pub ed25519.PublicKey, rec wal.Record) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid receipt public key")
	}
	if rec.ReceiptSignature == "" {
		return fmt.Errorf("receipt signature missing")
	}
	version, encoded, ok := strings.Cut(rec.ReceiptSignature, ".")
	if !ok || version != signatureVersion {
		return fmt.Errorf("unsupported receipt signature version")
	}
	sig, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("invalid receipt signature encoding")
	}
	payload, err := canonicalPayload(rec)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("receipt signature mismatch")
	}
	return nil
}

// ParsePublicKey decodes a base64 (raw or standard) Ed25519 public key, as published by
// the signer, for use by VerifyRecordWithPublicKey.
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("empty public key")
	}
	for _, dec := range []*base64.Encoding{base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding} {
		if raw, err := dec.DecodeString(encoded); err == nil && len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw), nil
		}
	}
	return nil, fmt.Errorf("invalid Ed25519 public key (want %d base64 bytes)", ed25519.PublicKeySize)
}

func HashToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type recordPayload struct {
	Version             string  `json:"version"`
	DecisionID          string  `json:"decision_id,omitempty"`
	Project             string  `json:"project,omitempty"`
	SessionID           string  `json:"session_id,omitempty"`
	TrajectoryID        string  `json:"trajectory_id,omitempty"`
	DecisionStage       string  `json:"decision_stage,omitempty"`
	StepID              string  `json:"step_id,omitempty"`
	ToolSignature       string  `json:"tool_signature,omitempty"`
	ArgsFingerprint     string  `json:"args_fingerprint,omitempty"`
	StatusCode          int     `json:"status_code,omitempty"`
	LoopAction          string  `json:"loop_action,omitempty"`
	LoopSignalsFired    string  `json:"loop_signals_fired,omitempty"`
	LoopConfidence      float64 `json:"loop_confidence,omitempty"`
	DetectorVersion     string  `json:"detector_version,omitempty"`
	PolicyVersion       string  `json:"policy_version,omitempty"`
	DecisionReason      string  `json:"decision_reason,omitempty"`
	DecisionEvidence    string  `json:"decision_evidence,omitempty"`
	AgentID             string  `json:"agent_id,omitempty"`
	UserID              string  `json:"user_id,omitempty"`
	ActionRisk          string  `json:"action_risk,omitempty"`
	IdempotencyKey      string  `json:"idempotency_key,omitempty"`
	IdempotencyKeyHash  string  `json:"idempotency_key_hash,omitempty"`
	ResourceID          string  `json:"resource_id,omitempty"`
	ResourceFingerprint string  `json:"resource_fingerprint,omitempty"`
	AmountCents         int64   `json:"amount_cents,omitempty"`
	MaxAmountCents      int64   `json:"max_amount_cents,omitempty"`
	BackupID            string  `json:"backup_id,omitempty"`
	RecipientDomain     string  `json:"recipient_domain,omitempty"`
	AllowedDomain       string  `json:"allowed_domain,omitempty"`
	CapabilityHash      string  `json:"capability_hash,omitempty"`
}

func canonicalPayload(rec wal.Record) ([]byte, error) {
	payload := recordPayload{
		Version:             signatureVersion,
		DecisionID:          rec.DecisionID,
		Project:             rec.Project,
		SessionID:           rec.SessionID,
		TrajectoryID:        rec.TrajectoryID,
		DecisionStage:       rec.DecisionStage,
		StepID:              rec.StepID,
		ToolSignature:       rec.ToolSignature,
		ArgsFingerprint:     rec.ArgsFingerprint,
		StatusCode:          rec.StatusCode,
		LoopAction:          rec.LoopAction,
		LoopSignalsFired:    rec.LoopSignalsFired,
		LoopConfidence:      rec.LoopConfidence,
		DetectorVersion:     rec.DetectorVersion,
		PolicyVersion:       rec.PolicyVersion,
		DecisionReason:      rec.DecisionReason,
		DecisionEvidence:    rec.DecisionEvidence,
		AgentID:             rec.AgentID,
		UserID:              rec.UserID,
		ActionRisk:          rec.ActionRisk,
		IdempotencyKey:      rec.IdempotencyKey,
		IdempotencyKeyHash:  rec.IdempotencyKeyHash,
		ResourceID:          rec.ResourceID,
		ResourceFingerprint: rec.ResourceFingerprint,
		AmountCents:         rec.AmountCents,
		MaxAmountCents:      rec.MaxAmountCents,
		BackupID:            rec.BackupID,
		RecipientDomain:     rec.RecipientDomain,
		AllowedDomain:       rec.AllowedDomain,
		CapabilityHash:      rec.CapabilityHash,
	}
	return json.Marshal(payload)
}
