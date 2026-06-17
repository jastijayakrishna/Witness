package outcomeexport

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/hubbleops/hubbleops/internal/storage"
)

func TestWriteJSONLExportsAnonymizedOutcome(t *testing.T) {
	var out bytes.Buffer
	before := metricValue(t, "hubbleops_export_records_total", nil)
	count, err := WriteJSONL(&out, []storage.ActionDecisionOutcomeExport{sampleExportRow("true_positive")}, Options{
		Anonymize: true,
		Salt:      "salt-a",
	})
	if err != nil {
		t.Fatalf("write export: %v", err)
	}
	if count != 1 {
		t.Fatalf("count=%d want 1", count)
	}
	if got := metricValue(t, "hubbleops_export_records_total", nil) - before; got != 1 {
		t.Fatalf("export metric delta=%f want 1", got)
	}
	var rec Record
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &rec); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if rec.ActionType != "payment_action" || rec.ActionRisk != "customer_visible" {
		t.Fatalf("normalized fields: %+v", rec)
	}
	if !strings.HasPrefix(rec.ActionNameHash, "sha256:") || strings.Contains(out.String(), "refund_customer") {
		t.Fatalf("action name was not anonymized: %s", out.String())
	}
	if rec.ResultClass != "duplicate" || rec.HubbleOpsAction != "block" {
		t.Fatalf("decision fields: %+v", rec)
	}
	if rec.CustomerReviewLabel != "true_positive" {
		t.Fatalf("review label=%q", rec.CustomerReviewLabel)
	}
	if rec.EstimatedCostBucket != "0.10_1" || rec.EstimatedCostUSD != nil {
		t.Fatalf("cost export: %+v", rec)
	}
	if rec.CreatedAtBucketDay != "2026-06-05" {
		t.Fatalf("created_at bucket=%q", rec.CreatedAtBucketDay)
	}
	if len(rec.EvidenceCodes) != 1 || rec.EvidenceCodes[0] != "duplicate_side_effect" {
		t.Fatalf("evidence codes=%v", rec.EvidenceCodes)
	}
}

func TestSemanticFieldsExportedAsNormalizedCodes(t *testing.T) {
	row := sampleExportRow("true_positive")
	row.Outcome.Environment = "PROD"
	row.Outcome.RecipientType = "customer"
	row.Outcome.OperationType = "delete"

	rec := BuildRecord(row, Options{Anonymize: true, Salt: "salt"})
	if rec.Environment != "production" {
		t.Fatalf("environment=%q want production", rec.Environment)
	}
	if rec.RecipientType != "external_customer" {
		t.Fatalf("recipient_type=%q want external_customer", rec.RecipientType)
	}
	if rec.OperationType != "delete" {
		t.Fatalf("operation_type=%q want delete", rec.OperationType)
	}
}

func TestSemanticFieldsDefaultToUnknownWhenAbsent(t *testing.T) {
	rec := BuildRecord(sampleExportRow("true_positive"), Options{Anonymize: true, Salt: "salt"})
	if rec.Environment != "unknown" || rec.RecipientType != "unknown" || rec.OperationType != "unknown" {
		t.Fatalf("absent semantic fields should export as unknown: %+v", rec)
	}
}

func TestAnonymizationStableWithSameSalt(t *testing.T) {
	row := sampleExportRow("false_positive")
	left := BuildRecord(row, Options{Anonymize: true, Salt: "same-salt"})
	right := BuildRecord(row, Options{Anonymize: true, Salt: "same-salt"})

	if left.ActionNameHash != right.ActionNameHash || left.ToolSignatureHash != right.ToolSignatureHash {
		t.Fatalf("hashes should be stable: left=%+v right=%+v", left, right)
	}
}

func TestAnonymizationChangesWithDifferentSalt(t *testing.T) {
	row := sampleExportRow("false_positive")
	left := BuildRecord(row, Options{Anonymize: true, Salt: "salt-a"})
	right := BuildRecord(row, Options{Anonymize: true, Salt: "salt-b"})

	if left.ActionNameHash == right.ActionNameHash {
		t.Fatalf("action_name_hash should change with salt: %s", left.ActionNameHash)
	}
	if left.ToolSignatureHash == right.ToolSignatureHash {
		t.Fatalf("tool_signature_hash should change with salt: %s", left.ToolSignatureHash)
	}
}

func TestRawFieldsAbsent(t *testing.T) {
	row := sampleExportRow("true_positive")
	row.Outcome.Project = "real-customer"
	row.Outcome.SessionID = "session-user@example.com"
	row.Outcome.TrajectoryID = "traj-secret"
	row.Outcome.ArgsFingerprint = `{"email":"customer@example.com"}`
	row.Outcome.ResultFingerprint = `{"card":"4242"}`
	row.Outcome.ResourceFingerprint = "invoice-raw-123"
	row.Outcome.DecisionReason = "raw_args included customer@example.com"
	row.Outcome.EvidenceJSON = []byte(`[{"signal":"duplicate_side_effect"},{"email":"customer@example.com"}]`)

	var out bytes.Buffer
	if _, err := WriteJSONL(&out, []storage.ActionDecisionOutcomeExport{row}, Options{Anonymize: true, Salt: "salt"}); err != nil {
		t.Fatalf("write export: %v", err)
	}
	encoded := out.String()
	for _, forbidden := range []string{
		"real-customer",
		"session-user@example.com",
		"traj-secret",
		"customer@example.com",
		"invoice-raw-123",
		"4242",
		"args_fingerprint",
		"result_fingerprint",
		"resource_fingerprint",
		"session_id",
		"trajectory_id",
		"project",
		"notes",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("export leaked %q: %s", forbidden, encoded)
		}
	}
	if !strings.Contains(encoded, "raw_sensitive_redacted") {
		t.Fatalf("unsafe decision reason should be redacted: %s", encoded)
	}
}

func TestEvidenceFingerprintsAreNotExportedAsCodes(t *testing.T) {
	row := sampleExportRow("true_positive")
	row.Outcome.EvidenceJSON = []byte(`[{"signal":"duplicate_side_effect"},{"evidence_fingerprint":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","evidence_shape":"object"}]`)

	rec := BuildRecord(row, Options{Anonymize: true, Salt: "salt"})
	if len(rec.EvidenceCodes) != 1 || rec.EvidenceCodes[0] != "duplicate_side_effect" {
		t.Fatalf("evidence codes should exclude fingerprints: %v", rec.EvidenceCodes)
	}
}

func TestReviewedOnlyExcludesUnreviewedRows(t *testing.T) {
	rows := []storage.ActionDecisionOutcomeExport{
		sampleExportRow("true_positive"),
		sampleExportRow(""),
	}
	var out bytes.Buffer
	count, err := WriteJSONL(&out, rows, Options{
		Anonymize:    true,
		Salt:         "salt",
		ReviewedOnly: true,
	})
	if err != nil {
		t.Fatalf("write export: %v", err)
	}
	if count != 1 {
		t.Fatalf("count=%d want 1", count)
	}
	if strings.Count(strings.TrimSpace(out.String()), "\n") != 0 {
		t.Fatalf("expected one JSONL line, got: %s", out.String())
	}
}

func TestIncludeExactCostIsOptIn(t *testing.T) {
	row := sampleExportRow("true_positive")
	rec := BuildRecord(row, Options{Anonymize: true, Salt: "salt", IncludeCostExact: true})
	if rec.EstimatedCostUSD == nil || *rec.EstimatedCostUSD != 0.42 {
		t.Fatalf("exact cost=%v want 0.42", rec.EstimatedCostUSD)
	}
}

func TestWriteJSONLRequiresAnonymization(t *testing.T) {
	_, err := WriteJSONL(&bytes.Buffer{}, []storage.ActionDecisionOutcomeExport{sampleExportRow("true_positive")}, Options{Salt: "salt"})
	if err == nil {
		t.Fatalf("non-anonymized export succeeded")
	}
	_, err = WriteJSONL(&bytes.Buffer{}, []storage.ActionDecisionOutcomeExport{sampleExportRow("true_positive")}, Options{Anonymize: true})
	if err == nil {
		t.Fatalf("export without salt succeeded")
	}
}

func sampleExportRow(label string) storage.ActionDecisionOutcomeExport {
	cost := 0.42
	riskPrevented := 0.8
	return storage.ActionDecisionOutcomeExport{
		Outcome: storage.ActionDecisionOutcome{
			Project:                "proj-a",
			SessionID:              "session-a",
			TrajectoryID:           "trajectory-a",
			DecisionID:             "decision-a",
			ActionName:             "refund_customer",
			ActionType:             "Payment Action",
			ActionRisk:             "High",
			ToolSignatureHash:      "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ResultClass:            "Duplicate Side-Effect",
			HubbleOpsAction:          "Block",
			DecisionReason:         "duplicate_side_effect",
			EvidenceJSON:           []byte(`[{"signal":"duplicate_side_effect"},{"raw_args":{"email":"customer@example.com"}}]`),
			PolicyVersion:          "policy-v1",
			DetectorVersion:        "detector-v1",
			EstimatedCostUSD:       &cost,
			EstimatedRiskPrevented: &riskPrevented,
			CreatedAt:              time.Date(2026, 6, 5, 13, 45, 0, 0, time.FixedZone("local", 5*60*60)),
		},
		ReviewLabel: label,
	}
}

func metricValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			seen := map[string]string{}
			for _, label := range metric.GetLabel() {
				seen[label.GetName()] = label.GetValue()
			}
			matches := true
			for key, value := range labels {
				if seen[key] != value {
					matches = false
					break
				}
			}
			if !matches {
				continue
			}
			if metric.GetCounter() != nil {
				return metric.GetCounter().GetValue()
			}
			if metric.GetGauge() != nil {
				return metric.GetGauge().GetValue()
			}
		}
	}
	return 0
}
