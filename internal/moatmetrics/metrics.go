package moatmetrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	OutcomeRecordsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hubbleops_outcome_records_total",
			Help: "Total privacy-safe action decision outcome records written to the data moat.",
		},
	)
	OutcomeWriteFailuresTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hubbleops_outcome_write_failures_total",
			Help: "Total failed action decision outcome writes.",
		},
	)
	DecisionReviewsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "hubbleops_decision_reviews_total",
			Help: "Total customer decision reviews accepted, labeled by review label.",
		},
		[]string{"label"},
	)
	UnreviewedDecisionsTotal = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "hubbleops_unreviewed_decisions_total",
			Help: "Current number of action decision outcomes without a customer review label.",
		},
	)
	ExportRecordsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hubbleops_export_records_total",
			Help: "Total anonymized outcome export records written.",
		},
	)
	PolicySuggestionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hubbleops_policy_suggestions_total",
			Help: "Total policy template suggestions produced from reviewed decision outcomes.",
		},
	)
	PrivacyRedactionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hubbleops_privacy_redactions_total",
			Help: "Total privacy redactions or privacy-safe fingerprint substitutions applied before capture/export.",
		},
	)
	RawCaptureRejectionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "hubbleops_raw_capture_rejections_total",
			Help: "Total raw capture attempts rejected because raw capture was not explicitly enabled.",
		},
	)
)

func init() {
	prometheus.MustRegister(
		OutcomeRecordsTotal,
		OutcomeWriteFailuresTotal,
		DecisionReviewsTotal,
		UnreviewedDecisionsTotal,
		ExportRecordsTotal,
		PolicySuggestionsTotal,
		PrivacyRedactionsTotal,
		RawCaptureRejectionsTotal,
	)
	for _, label := range []string{"true_positive", "false_positive", "benign_retry", "needs_review", "unsafe_but_allowed", "missed_runaway"} {
		DecisionReviewsTotal.WithLabelValues(label)
	}
}

func RecordOutcomeRecord() {
	OutcomeRecordsTotal.Inc()
}

func RecordOutcomeWriteFailure() {
	OutcomeWriteFailuresTotal.Inc()
}

func RecordDecisionReview(label string) {
	DecisionReviewsTotal.WithLabelValues(normalizeLabel(label)).Inc()
}

func SetUnreviewedDecisions(count int) {
	if count < 0 {
		count = 0
	}
	UnreviewedDecisionsTotal.Set(float64(count))
}

func RecordExportRecords(count int) {
	if count > 0 {
		ExportRecordsTotal.Add(float64(count))
	}
}

func RecordPolicySuggestions(count int) {
	if count > 0 {
		PolicySuggestionsTotal.Add(float64(count))
	}
}

func RecordPrivacyRedaction() {
	PrivacyRedactionsTotal.Inc()
}

func RecordRawCaptureRejection() {
	RawCaptureRejectionsTotal.Inc()
}

func normalizeLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" {
		return "unknown"
	}
	label = strings.NewReplacer(" ", "_", "-", "_", "/", "_").Replace(label)
	var b strings.Builder
	for _, r := range label {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == ':' {
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "_.:")
	if out == "" {
		return "unknown"
	}
	if len(out) > 96 {
		return out[:96]
	}
	return out
}
