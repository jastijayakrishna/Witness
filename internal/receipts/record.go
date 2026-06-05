package receipts

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/witness-proxy/witness-proxy/internal/wal"
)

const signatureVersion = "witreceipt_v1"

type Signer struct {
	keyID  string
	secret []byte
}

func NewSigner(keyID string, secret []byte) *Signer {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		keyID = "local"
	}
	return &Signer{keyID: keyID, secret: append([]byte(nil), secret...)}
}

func (s *Signer) SignRecord(rec wal.Record) (string, string, error) {
	if s == nil || len(s.secret) == 0 {
		return "", "", nil
	}
	sig, err := SignRecord(s.secret, rec)
	if err != nil {
		return "", "", err
	}
	return sig, s.keyID, nil
}

func SignRecord(secret []byte, rec wal.Record) (string, error) {
	if len(secret) == 0 {
		return "", fmt.Errorf("receipt signing secret is required")
	}
	payload, err := canonicalPayload(rec)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	return signatureVersion + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func VerifyRecord(secret []byte, rec wal.Record) error {
	if rec.ReceiptSignature == "" {
		return fmt.Errorf("receipt signature missing")
	}
	want, err := SignRecord(secret, rec)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(rec.ReceiptSignature), []byte(want)) {
		return fmt.Errorf("receipt signature mismatch")
	}
	return nil
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
	Version          string  `json:"version"`
	DecisionID       string  `json:"decision_id,omitempty"`
	Project          string  `json:"project,omitempty"`
	SessionID        string  `json:"session_id,omitempty"`
	TrajectoryID     string  `json:"trajectory_id,omitempty"`
	DecisionStage    string  `json:"decision_stage,omitempty"`
	StepID           string  `json:"step_id,omitempty"`
	ToolSignature    string  `json:"tool_signature,omitempty"`
	ArgsFingerprint  string  `json:"args_fingerprint,omitempty"`
	StatusCode       int     `json:"status_code,omitempty"`
	LoopAction       string  `json:"loop_action,omitempty"`
	LoopSignalsFired string  `json:"loop_signals_fired,omitempty"`
	LoopConfidence   float64 `json:"loop_confidence,omitempty"`
	DetectorVersion  string  `json:"detector_version,omitempty"`
	PolicyVersion    string  `json:"policy_version,omitempty"`
	DecisionReason   string  `json:"decision_reason,omitempty"`
	DecisionEvidence string  `json:"decision_evidence,omitempty"`
	AgentID          string  `json:"agent_id,omitempty"`
	UserID           string  `json:"user_id,omitempty"`
	ActionRisk       string  `json:"action_risk,omitempty"`
	IdempotencyKey   string  `json:"idempotency_key,omitempty"`
	ResourceID       string  `json:"resource_id,omitempty"`
	AmountCents      int64   `json:"amount_cents,omitempty"`
	MaxAmountCents   int64   `json:"max_amount_cents,omitempty"`
	BackupID         string  `json:"backup_id,omitempty"`
	RecipientDomain  string  `json:"recipient_domain,omitempty"`
	AllowedDomain    string  `json:"allowed_domain,omitempty"`
	CapabilityHash   string  `json:"capability_hash,omitempty"`
}

func canonicalPayload(rec wal.Record) ([]byte, error) {
	payload := recordPayload{
		Version:          signatureVersion,
		DecisionID:       rec.DecisionID,
		Project:          rec.Project,
		SessionID:        rec.SessionID,
		TrajectoryID:     rec.TrajectoryID,
		DecisionStage:    rec.DecisionStage,
		StepID:           rec.StepID,
		ToolSignature:    rec.ToolSignature,
		ArgsFingerprint:  rec.ArgsFingerprint,
		StatusCode:       rec.StatusCode,
		LoopAction:       rec.LoopAction,
		LoopSignalsFired: rec.LoopSignalsFired,
		LoopConfidence:   rec.LoopConfidence,
		DetectorVersion:  rec.DetectorVersion,
		PolicyVersion:    rec.PolicyVersion,
		DecisionReason:   rec.DecisionReason,
		DecisionEvidence: rec.DecisionEvidence,
		AgentID:          rec.AgentID,
		UserID:           rec.UserID,
		ActionRisk:       rec.ActionRisk,
		IdempotencyKey:   rec.IdempotencyKey,
		ResourceID:       rec.ResourceID,
		AmountCents:      rec.AmountCents,
		MaxAmountCents:   rec.MaxAmountCents,
		BackupID:         rec.BackupID,
		RecipientDomain:  rec.RecipientDomain,
		AllowedDomain:    rec.AllowedDomain,
		CapabilityHash:   rec.CapabilityHash,
	}
	return json.Marshal(payload)
}
