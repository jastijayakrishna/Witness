package receipts

import (
	"testing"

	"github.com/hubbleops/hubbleops/internal/wal"
)

// fullSignedRecord populates every security-relevant decision field so the coverage
// test can prove each one is bound by the Ed25519 signature. record_hash is keyless
// SHA-256 (anyone can recompute it), so the signature is the ONLY thing that makes a
// portable receipt unforgeable — every field an auditor relies on must be inside it.
func fullSignedRecord() wal.Record {
	return wal.Record{
		DecisionID:          "dec_1",
		Project:             "acme",
		SessionID:           "sess",
		PolicyVersion:       "engineering-gate/v1",
		DecisionReason:      "destructive engineering action detected",
		Actor:               "agent:claude-code",
		HumanDelegator:      "krish",
		Action:              "terraform.destroy",
		Target:              "aws_s3_bucket.audit_logs_prod",
		Environment:         "production",
		IdempotencyKeyHash:  "sha256:abc",
		ResourceFingerprint: "sha256:def",
		IntentHash:          "sha256:ghi",
		EvidenceHashes:      []string{"sha256:e1"},
		BlastRadius:         "high",
		RiskScore:           99,
		Decision:            "block",
		RequiredApprovers:   []string{"sre"},
		ReceiptKeyID:        "prod-2026",
	}
}

// TestReceiptSignatureCoversEverySecurityRelevantDecisionField fails if any decision
// field can be tampered without invalidating the signature. If a future wal.Record
// field is added to a receipt but not to canonicalPayload, add it here and it will be
// caught — silent unsigned fields are the regression this guards against.
func TestReceiptSignatureCoversEverySecurityRelevantDecisionField(t *testing.T) {
	secret := []byte("receipt-secret")
	sig, err := SignRecord(secret, fullSignedRecord())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	baseline := fullSignedRecord()
	baseline.ReceiptSignature = sig
	if err := VerifyRecord(secret, baseline); err != nil {
		t.Fatalf("baseline verify failed: %v", err)
	}

	mutations := map[string]func(*wal.Record){
		"decision":             func(r *wal.Record) { r.Decision = "allow" },
		"risk_score":           func(r *wal.Record) { r.RiskScore = 0 },
		"target":               func(r *wal.Record) { r.Target = "aws_s3_bucket.dev" },
		"actor":                func(r *wal.Record) { r.Actor = "agent:evil" },
		"human_delegator":      func(r *wal.Record) { r.HumanDelegator = "mallory" },
		"action":               func(r *wal.Record) { r.Action = "terraform.plan" },
		"environment":          func(r *wal.Record) { r.Environment = "development" },
		"policy_version":       func(r *wal.Record) { r.PolicyVersion = "tampered" },
		"decision_reason":      func(r *wal.Record) { r.DecisionReason = "all good" },
		"required_approvers":   func(r *wal.Record) { r.RequiredApprovers = nil },
		"idempotency_key_hash": func(r *wal.Record) { r.IdempotencyKeyHash = "sha256:zzz" },
		"resource_fingerprint": func(r *wal.Record) { r.ResourceFingerprint = "sha256:zzz" },
		"intent_hash":          func(r *wal.Record) { r.IntentHash = "sha256:zzz" },
		"evidence_hashes":      func(r *wal.Record) { r.EvidenceHashes = []string{"sha256:tampered"} },
		"blast_radius":         func(r *wal.Record) { r.BlastRadius = "low" },
		"key_id":               func(r *wal.Record) { r.ReceiptKeyID = "attacker-key" },
	}
	for name, mutate := range mutations {
		tampered := fullSignedRecord()
		tampered.ReceiptSignature = sig
		mutate(&tampered)
		if err := VerifyRecord(secret, tampered); err == nil {
			t.Fatalf("tampering %q was NOT detected: this field is outside the signed payload", name)
		}
	}
}
