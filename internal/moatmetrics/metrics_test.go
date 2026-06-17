package moatmetrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestDataQualityMetricsIncrement(t *testing.T) {
	outcomeBefore := metricValue(t, "hubbleops_outcome_records_total", nil)
	failureBefore := metricValue(t, "hubbleops_outcome_write_failures_total", nil)
	reviewBefore := metricValue(t, "hubbleops_decision_reviews_total", map[string]string{"label": "true_positive"})
	exportBefore := metricValue(t, "hubbleops_export_records_total", nil)
	suggestionBefore := metricValue(t, "hubbleops_policy_suggestions_total", nil)
	redactionBefore := metricValue(t, "hubbleops_privacy_redactions_total", nil)
	rejectionBefore := metricValue(t, "hubbleops_raw_capture_rejections_total", nil)

	RecordOutcomeRecord()
	RecordOutcomeWriteFailure()
	RecordDecisionReview("true_positive")
	RecordExportRecords(2)
	RecordPolicySuggestions(3)
	RecordPrivacyRedaction()
	RecordRawCaptureRejection()
	SetUnreviewedDecisions(7)

	if got := metricValue(t, "hubbleops_outcome_records_total", nil) - outcomeBefore; got != 1 {
		t.Fatalf("outcome records delta=%f want 1", got)
	}
	if got := metricValue(t, "hubbleops_outcome_write_failures_total", nil) - failureBefore; got != 1 {
		t.Fatalf("outcome failures delta=%f want 1", got)
	}
	if got := metricValue(t, "hubbleops_decision_reviews_total", map[string]string{"label": "true_positive"}) - reviewBefore; got != 1 {
		t.Fatalf("reviews delta=%f want 1", got)
	}
	if got := metricValue(t, "hubbleops_export_records_total", nil) - exportBefore; got != 2 {
		t.Fatalf("exports delta=%f want 2", got)
	}
	if got := metricValue(t, "hubbleops_policy_suggestions_total", nil) - suggestionBefore; got != 3 {
		t.Fatalf("suggestions delta=%f want 3", got)
	}
	if got := metricValue(t, "hubbleops_privacy_redactions_total", nil) - redactionBefore; got != 1 {
		t.Fatalf("redactions delta=%f want 1", got)
	}
	if got := metricValue(t, "hubbleops_raw_capture_rejections_total", nil) - rejectionBefore; got != 1 {
		t.Fatalf("raw rejections delta=%f want 1", got)
	}
	if got := metricValue(t, "hubbleops_unreviewed_decisions_total", nil); got != 7 {
		t.Fatalf("unreviewed gauge=%f want 7", got)
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
