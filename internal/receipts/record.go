package receipts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hubbleops/hubbleops/internal/wal"
)

// signatureVersion: v2 moved from symmetric HMAC to asymmetric Ed25519; v3 additionally
// bound the signing key id into the signed payload; v4 binds seq and prev_hash so the
// signature covers exact chain position. The signing secret never leaves the server; the
// public key (PublicKeyFromSecret) is what gets published.
const signatureVersion = "hubbleopsreceipt_v4"
const legacySignatureVersion = "hubbleopsreceipt_v3"
const checkpointSignatureVersion = "hubbleopscheckpoint_v1"

type ReceiptSigner interface {
	SignRecord(rec wal.Record) (sig string, keyID string, err error)
	SignCheckpoint(cp wal.Checkpoint) (wal.Checkpoint, error)
	PublicKeyBase64() string
	KeyID() string
}

type LocalSecretSigner struct {
	keyID string
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
}

// Signer is retained as a compatibility alias for callers that used the historical
// secret-derived signer. Production must use an external signer such as AWS KMS.
type Signer = LocalSecretSigner

// NewSigner returns a dev-only local signer backed by a key deterministically derived
// from the configured secret. Use NewLocalSecretSigner in new code for clarity.
func NewSigner(keyID string, secret []byte) *LocalSecretSigner {
	return NewLocalSecretSigner(keyID, secret)
}

// NewLocalSecretSigner derives a deterministic Ed25519 keypair from a local signing
// secret. This is intended for development and tests; production forbids it because
// any host holding the secret can forge receipts.
func NewLocalSecretSigner(keyID string, secret []byte) *LocalSecretSigner {
	keyID = normalizeKeyID(keyID)
	if len(secret) == 0 {
		return &LocalSecretSigner{keyID: keyID}
	}
	priv := privateKeyFromSecret(secret)
	return &LocalSecretSigner{keyID: keyID, priv: priv, pub: priv.Public().(ed25519.PublicKey)}
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
func (s *LocalSecretSigner) PublicKeyBase64() string {
	if s == nil || len(s.pub) == 0 {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(s.pub)
}

// KeyID returns the signer's key identifier.
func (s *LocalSecretSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

func (s *LocalSecretSigner) SignRecord(rec wal.Record) (string, string, error) {
	if s == nil || len(s.priv) == 0 {
		return "", "", nil
	}
	// Bind the key id into the signed payload (rec is a value copy). The caller persists the
	// same key id on the record, so verification recomputes an identical payload.
	rec.ReceiptKeyID = s.keyID
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
	return encodeRecordSignature(sig), nil
}

func encodeRecordSignature(sig []byte) string {
	return signatureVersion + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func encodeCheckpointSignature(sig []byte) string {
	return checkpointSignatureVersion + "." + base64.RawURLEncoding.EncodeToString(sig)
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
	return verifyRecordWithPayload(pub, rec, signatureVersion, canonicalPayload)
}

// VerifyLegacyRecordWithPublicKey verifies pre-sequence receipts whose signatures did not
// bind seq/prev_hash. Callers must gate this behind an explicit legacy mode.
func VerifyLegacyRecordWithPublicKey(pub ed25519.PublicKey, rec wal.Record) error {
	return verifyRecordWithPayload(pub, rec, legacySignatureVersion, legacyCanonicalPayload)
}

func verifyRecordWithPayload(pub ed25519.PublicKey, rec wal.Record, expectedVersion string, payloadFn func(wal.Record) ([]byte, error)) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid receipt public key")
	}
	if rec.ReceiptSignature == "" {
		return fmt.Errorf("receipt signature missing")
	}
	version, encoded, ok := strings.Cut(rec.ReceiptSignature, ".")
	if !ok || version != expectedVersion {
		return fmt.Errorf("unsupported receipt signature version")
	}
	sig, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("invalid receipt signature encoding")
	}
	payload, err := payloadFn(rec)
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

// KeySet maps key ids to verification keys so receipts signed before and after a key
// rotation all verify: the active key signs new receipts while retired public keys stay in
// the set to verify historical ones. The first key added is the fallback for receipts whose
// key id is absent (single-key/legacy receipts).
type KeySet struct {
	keys     map[string]ed25519.PublicKey
	fallback ed25519.PublicKey
}

func NewKeySet() *KeySet {
	return &KeySet{keys: map[string]ed25519.PublicKey{}}
}

func (ks *KeySet) Add(keyID string, pub ed25519.PublicKey) {
	if ks.keys == nil {
		ks.keys = map[string]ed25519.PublicKey{}
	}
	ks.keys[normalizeKeyID(keyID)] = pub
	if ks.fallback == nil {
		ks.fallback = pub
	}
}

func (ks *KeySet) Len() int {
	if ks == nil {
		return 0
	}
	return len(ks.keys)
}

// VerifyRecord selects the verification key by the receipt's key id, so a rotated keyset
// verifies every receipt regardless of which key signed it. A receipt whose key id is not
// in the set is checked against the fallback, which fails closed if it was signed by an
// unknown key.
func (ks *KeySet) VerifyRecord(rec wal.Record) error {
	if ks == nil || len(ks.keys) == 0 {
		return fmt.Errorf("no verification keys configured")
	}
	if pub, ok := ks.keys[normalizeKeyID(rec.ReceiptKeyID)]; ok {
		return VerifyRecordWithPublicKey(pub, rec)
	}
	if ks.fallback != nil {
		return VerifyRecordWithPublicKey(ks.fallback, rec)
	}
	return fmt.Errorf("no verification key for key_id %q", rec.ReceiptKeyID)
}

func (ks *KeySet) VerifyLegacyRecord(rec wal.Record) error {
	if ks == nil || len(ks.keys) == 0 {
		return fmt.Errorf("no verification keys configured")
	}
	if pub, ok := ks.keys[normalizeKeyID(rec.ReceiptKeyID)]; ok {
		return VerifyLegacyRecordWithPublicKey(pub, rec)
	}
	if ks.fallback != nil {
		return VerifyLegacyRecordWithPublicKey(ks.fallback, rec)
	}
	return fmt.Errorf("no verification key for key_id %q", rec.ReceiptKeyID)
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
	Version             string   `json:"version"`
	KeyID               string   `json:"key_id,omitempty"`
	Seq                 uint64   `json:"seq,omitempty"`
	PrevHash            string   `json:"prev_hash,omitempty"`
	DecisionID          string   `json:"decision_id,omitempty"`
	Project             string   `json:"project,omitempty"`
	SessionID           string   `json:"session_id,omitempty"`
	TrajectoryID        string   `json:"trajectory_id,omitempty"`
	DecisionStage       string   `json:"decision_stage,omitempty"`
	StepID              string   `json:"step_id,omitempty"`
	ToolSignature       string   `json:"tool_signature,omitempty"`
	ArgsFingerprint     string   `json:"args_fingerprint,omitempty"`
	StatusCode          int      `json:"status_code,omitempty"`
	LoopAction          string   `json:"loop_action,omitempty"`
	LoopSignalsFired    string   `json:"loop_signals_fired,omitempty"`
	LoopConfidence      float64  `json:"loop_confidence,omitempty"`
	DetectorVersion     string   `json:"detector_version,omitempty"`
	PolicyVersion       string   `json:"policy_version,omitempty"`
	DecisionReason      string   `json:"decision_reason,omitempty"`
	DecisionEvidence    string   `json:"decision_evidence,omitempty"`
	AgentID             string   `json:"agent_id,omitempty"`
	UserID              string   `json:"user_id,omitempty"`
	ActionRisk          string   `json:"action_risk,omitempty"`
	IdempotencyKey      string   `json:"idempotency_key,omitempty"`
	IdempotencyKeyHash  string   `json:"idempotency_key_hash,omitempty"`
	ResourceID          string   `json:"resource_id,omitempty"`
	ResourceFingerprint string   `json:"resource_fingerprint,omitempty"`
	AmountCents         int64    `json:"amount_cents,omitempty"`
	MaxAmountCents      int64    `json:"max_amount_cents,omitempty"`
	BackupID            string   `json:"backup_id,omitempty"`
	RecipientDomain     string   `json:"recipient_domain,omitempty"`
	AllowedDomain       string   `json:"allowed_domain,omitempty"`
	CapabilityHash      string   `json:"capability_hash,omitempty"`
	Actor               string   `json:"actor,omitempty"`
	HumanDelegator      string   `json:"human_delegator,omitempty"`
	Action              string   `json:"action,omitempty"`
	Target              string   `json:"target,omitempty"`
	Environment         string   `json:"environment,omitempty"`
	IntentHash          string   `json:"intent_hash,omitempty"`
	EvidenceHashes      []string `json:"evidence_hashes,omitempty"`
	BlastRadius         string   `json:"blast_radius,omitempty"`
	RiskScore           int      `json:"risk_score,omitempty"`
	Decision            string   `json:"decision,omitempty"`
	RequiredApprovers   []string `json:"required_approvers,omitempty"`
	Approvals           []string `json:"approvals,omitempty"`
}

func canonicalPayload(rec wal.Record) ([]byte, error) {
	return canonicalPayloadForRecord(rec, true, signatureVersion)
}

func legacyCanonicalPayload(rec wal.Record) ([]byte, error) {
	return canonicalPayloadForRecord(rec, false, legacySignatureVersion)
}

func canonicalPayloadForRecord(rec wal.Record, includePosition bool, version string) ([]byte, error) {
	payload := recordPayload{
		Version:             version,
		KeyID:               rec.ReceiptKeyID,
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
		Actor:               rec.Actor,
		HumanDelegator:      rec.HumanDelegator,
		Action:              rec.Action,
		Target:              rec.Target,
		Environment:         rec.Environment,
		IntentHash:          rec.IntentHash,
		EvidenceHashes:      rec.EvidenceHashes,
		BlastRadius:         rec.BlastRadius,
		RiskScore:           rec.RiskScore,
		Decision:            rec.Decision,
		RequiredApprovers:   rec.RequiredApprovers,
		Approvals:           rec.Approvals,
	}
	if includePosition {
		payload.Seq = rec.Seq
		payload.PrevHash = rec.PrevHash
	}
	return json.Marshal(payload)
}

type checkpointPayload struct {
	Version  string `json:"version"`
	KeyID    string `json:"key_id,omitempty"`
	Seq      uint64 `json:"seq"`
	HeadHash string `json:"head_hash"`
	Count    uint64 `json:"count"`
	SignedAt string `json:"signed_at"`
}

func (s *LocalSecretSigner) SignCheckpoint(cp wal.Checkpoint) (wal.Checkpoint, error) {
	if s == nil || len(s.priv) == 0 {
		return cp, nil
	}
	cp.KeyID = s.keyID
	if cp.SignedAt.IsZero() {
		cp.SignedAt = nowUTC()
	}
	payload, err := canonicalCheckpointPayload(cp)
	if err != nil {
		return cp, err
	}
	sig := ed25519.Sign(s.priv, payload)
	cp.Signature = encodeCheckpointSignature(sig)
	return cp, nil
}

func VerifyCheckpointWithPublicKey(pub ed25519.PublicKey, cp wal.Checkpoint) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid receipt public key")
	}
	if cp.Signature == "" {
		return fmt.Errorf("checkpoint signature missing")
	}
	version, encoded, ok := strings.Cut(cp.Signature, ".")
	if !ok || version != checkpointSignatureVersion {
		return fmt.Errorf("unsupported checkpoint signature version")
	}
	sig, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("invalid checkpoint signature encoding")
	}
	payload, err := canonicalCheckpointPayload(cp)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("checkpoint signature mismatch")
	}
	return nil
}

func (ks *KeySet) VerifyCheckpoint(cp wal.Checkpoint) error {
	if ks == nil || len(ks.keys) == 0 {
		return fmt.Errorf("no verification keys configured")
	}
	if pub, ok := ks.keys[normalizeKeyID(cp.KeyID)]; ok {
		return VerifyCheckpointWithPublicKey(pub, cp)
	}
	if ks.fallback != nil {
		return VerifyCheckpointWithPublicKey(ks.fallback, cp)
	}
	return fmt.Errorf("no verification key for checkpoint key_id %q", cp.KeyID)
}

func canonicalCheckpointPayload(cp wal.Checkpoint) ([]byte, error) {
	payload := checkpointPayload{
		Version:  checkpointSignatureVersion,
		KeyID:    cp.KeyID,
		Seq:      cp.Seq,
		HeadHash: cp.HeadHash,
		Count:    cp.Count,
		SignedAt: cp.SignedAt.UTC().Format(timeFormatRFC3339Nano),
	}
	return json.Marshal(payload)
}

const timeFormatRFC3339Nano = "2006-01-02T15:04:05.999999999Z07:00"

func nowUTC() time.Time {
	return time.Now().UTC()
}
