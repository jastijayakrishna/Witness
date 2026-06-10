package demopack

import "testing"

func TestIncidentsLoadAllEight(t *testing.T) {
	incidents, err := Incidents()
	if err != nil {
		t.Fatalf("load incidents: %v", err)
	}
	if len(incidents) != 8 {
		t.Fatalf("incidents=%d want 8", len(incidents))
	}
	for _, inc := range incidents {
		if inc.Label == "" || inc.SourceIncident == "" || inc.ExpectedSignal == "" {
			t.Fatalf("incident missing ground truth: %+v", inc.Label)
		}
		if len(inc.Events) == 0 {
			t.Fatalf("incident %s has no events", inc.Label)
		}
	}
}
