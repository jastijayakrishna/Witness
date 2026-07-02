package receipts

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/hubbleops/hubbleops/internal/wal"
)

type goldenVector struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func TestGoldenReceiptV4CanonicalPayloadAndSignature(t *testing.T) {
	rec := goldenReceiptRecord()
	signer := NewSigner("golden-2026", []byte("golden-secret-v1"))
	rec.ReceiptKeyID = signer.KeyID()

	payload, err := canonicalPayload(rec)
	if err != nil {
		t.Fatalf("canonical payload: %v", err)
	}
	sig, keyID, err := signer.SignRecord(rec)
	if err != nil {
		t.Fatalf("sign record: %v", err)
	}
	got := goldenVector{
		KeyID:     keyID,
		PublicKey: signer.PublicKeyBase64(),
		Payload:   string(payload),
		Signature: sig,
	}

	raw, err := os.ReadFile("testdata/golden/receipt_v4.json")
	if err != nil {
		t.Fatalf("read golden vector: %v\npayload=%s\nsignature=%s\npublic_key=%s", err, got.Payload, got.Signature, got.PublicKey)
	}
	var want goldenVector
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("parse golden vector: %v", err)
	}
	if got != want {
		t.Fatalf("golden vector drift\nwant=%+v\ngot =%+v", want, got)
	}
}

func TestEveryRecordPayloadFieldIsSignatureBound(t *testing.T) {
	base := goldenReceiptRecord()
	signer := NewSigner("coverage-2026", []byte("coverage-secret-v1"))
	base.ReceiptKeyID = signer.KeyID()
	sig, keyID, err := signer.SignRecord(base)
	if err != nil {
		t.Fatalf("sign base: %v", err)
	}
	base.ReceiptSignature = sig
	base.ReceiptKeyID = keyID
	pub := PublicKeyFromSecret([]byte("coverage-secret-v1"))

	payloadType := reflect.TypeOf(recordPayload{})
	for i := 0; i < payloadType.NumField(); i++ {
		field := payloadType.Field(i)
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
		if jsonName == "" || jsonName == "-" {
			t.Fatalf("recordPayload field %s has no JSON name", field.Name)
		}
		if field.Name == "Version" {
			continue // The exact signature version is pinned by TestGoldenReceiptV4CanonicalPayloadAndSignature.
		}
		t.Run(jsonName, func(t *testing.T) {
			mutated := base
			mutatePayloadBackedRecordField(t, &mutated, field.Name)
			if err := VerifyRecordWithPublicKey(pub, mutated); err == nil {
				t.Fatalf("mutating signed payload field %s/%s still verified", field.Name, jsonName)
			}
		})
	}
}

func mutatePayloadBackedRecordField(t *testing.T, rec *wal.Record, payloadFieldName string) {
	t.Helper()
	recordFieldName := payloadFieldName
	if payloadFieldName == "KeyID" {
		recordFieldName = "ReceiptKeyID"
	}
	value := reflect.ValueOf(rec).Elem().FieldByName(recordFieldName)
	if !value.IsValid() {
		t.Fatalf("recordPayload field %s has no mutation mapping to wal.Record", payloadFieldName)
	}
	if !value.CanSet() {
		t.Fatalf("wal.Record field %s cannot be mutated", recordFieldName)
	}
	switch value.Kind() {
	case reflect.String:
		value.SetString(value.String() + "_tampered")
	case reflect.Uint64:
		value.SetUint(value.Uint() + 1)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		value.SetInt(value.Int() + 1)
	case reflect.Float32, reflect.Float64:
		value.SetFloat(value.Float() + 0.25)
	case reflect.Slice:
		if value.Type().Elem().Kind() != reflect.String {
			t.Fatalf("unsupported slice field %s", recordFieldName)
		}
		value.Set(reflect.ValueOf([]string{"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}))
	default:
		t.Fatalf("unsupported signed field kind %s for %s", value.Kind(), recordFieldName)
	}
}

func goldenReceiptRecord() wal.Record {
	return wal.Record{
		Seq:                 7,
		Project:             "proj-golden",
		Provider:            "_preflight",
		Model:               "preflight",
		PromptHash:          "sha256:prompt",
		StatusCode:          200,
		SessionID:           "sess-golden",
		TrajectoryID:        "traj-golden",
		DecisionStage:       "preflight",
		StepID:              "step-7",
		ToolSignature:       "terraform.apply",
		ArgsFingerprint:     "sha256:args",
		PrevHash:            "genesis",
		DecisionID:          "dec_golden",
		AgentID:             "agent-golden",
		UserID:              "user-golden",
		ActionRisk:          "dangerous",
		IdempotencyKey:      "deploy:golden",
		IdempotencyKeyHash:  "sha256:idempotency",
		ResourceID:          "resource-golden",
		ResourceFingerprint: "sha256:resource",
		AmountCents:         1234,
		MaxAmountCents:      5000,
		BackupID:            "backup-golden",
		RecipientDomain:     "example.com",
		AllowedDomain:       "example.com",
		CapabilityHash:      "sha256:capability",
		PolicyVersion:       "engineering-gate/v1",
		DecisionReason:      "golden destructive action blocked",
		DecisionEvidence:    "terraform_action=delete",
		Actor:               "agent:codex",
		HumanDelegator:      "krish",
		Action:              "terraform.destroy",
		Target:              "aws_db_instance.prod",
		Environment:         "production",
		IntentHash:          "sha256:intent",
		EvidenceHashes:      []string{"sha256:evidence1", "sha256:evidence2"},
		BlastRadius:         "high",
		RiskScore:           99,
		Decision:            "block",
		RequiredApprovers:   []string{"sre", "db-owner"},
		Approvals:           []string{"approval-1"},
		LoopAction:          "block",
		LoopSignalsFired:    "policy_amount_exceeded",
		LoopConfidence:      0.99,
		DetectorVersion:     "detector-golden",
	}
}
