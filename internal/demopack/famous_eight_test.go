package demopack

import (
	"context"
	"testing"

	"github.com/hubbleops/hubbleops/internal/loop"
	"github.com/hubbleops/hubbleops/internal/synthcorpus"
)

// TestFamousEightDetected is bar #1: every demo incident must block, with the
// expected signal among those fired. 8/8 or the build fails.
func TestFamousEightDetected(t *testing.T) {
	incidents, err := Incidents()
	if err != nil {
		t.Fatalf("load incidents: %v", err)
	}
	if len(incidents) != 8 {
		t.Fatalf("incidents=%d want 8", len(incidents))
	}
	for _, inc := range incidents {
		res, err := synthcorpus.ReplaySession(context.Background(), inc.Events, loop.DefaultConfig(), loop.NewMemoryActionStore())
		if err != nil {
			t.Fatalf("%s: replay: %v", inc.Label, err)
		}
		if res.Verdict != "block" {
			t.Errorf("FAMOUS EIGHT MISS: %s verdict=%s signals=%v (%s)",
				inc.Label, res.Verdict, res.Signals, inc.SourceIncident)
			continue
		}
		found := false
		for _, s := range res.Signals {
			if s == inc.ExpectedSignal {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("FAMOUS EIGHT WRONG SIGNAL: %s fired %v, want %s",
				inc.Label, res.Signals, inc.ExpectedSignal)
		}
	}
}
