package proxy

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

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
