package synthcorpus

import (
	"strings"
	"testing"
)

func sampleResults() []SessionResult {
	return []SessionResult{
		{Label: "pos_fam", ExpectedAction: "block", Verdict: "block"},
		{Label: "pos_fam", ExpectedAction: "block", Verdict: "block"},
		{Label: "pos_fam", ExpectedAction: "block", Verdict: "allow", SessionID: "missed-1"},
		{Label: "neg_fam", ExpectedAction: "allow", Verdict: "allow"},
		{Label: "neg_fam", ExpectedAction: "allow", Verdict: "warn", SessionID: "warned-1"},
		{Label: "neg_fam", ExpectedAction: "allow", Verdict: "block", SessionID: "blocked-1"},
	}
}

func TestScoreAggregatesPerFamily(t *testing.T) {
	sb := Score(sampleResults())
	if len(sb.Rows) != 2 {
		t.Fatalf("rows=%d want 2", len(sb.Rows))
	}
	pos := sb.Rows[1] // sorted by family name: neg_fam, pos_fam
	if pos.Family != "pos_fam" || pos.Sessions != 3 || pos.Detected != 2 {
		t.Fatalf("positive row wrong: %+v", pos)
	}
	neg := sb.Rows[0]
	if neg.Family != "neg_fam" || neg.FalseBlocks != 1 || neg.Warns != 1 {
		t.Fatalf("negative row wrong: %+v", neg)
	}
	if len(sb.Misses) != 3 {
		t.Fatalf("misses=%d want 3 (1 missed positive + 1 false block + 1 warn)", len(sb.Misses))
	}
}

func TestGateFailures(t *testing.T) {
	sb := Score(sampleResults())
	failures := sb.GateFailures(0.95, 0.01)
	// pos_fam 2/3 = 66% < 95%; neg_fam has a block AND warn rate 33% > 1%.
	if len(failures) != 3 {
		t.Fatalf("failures=%v want 3 entries", failures)
	}
}

func TestGatePassesCleanBoard(t *testing.T) {
	results := []SessionResult{
		{Label: "pos", ExpectedAction: "block", Verdict: "block"},
		{Label: "neg", ExpectedAction: "allow", Verdict: "allow"},
	}
	sb := Score(results)
	if failures := sb.GateFailures(0.95, 0.01); len(failures) != 0 {
		t.Fatalf("unexpected failures: %v", failures)
	}
}

func TestFormatLabelsSynthetic(t *testing.T) {
	out := Score(sampleResults()).Format()
	if !strings.Contains(out, "synthetic") {
		t.Fatalf("scoreboard must be labeled synthetic:\n%s", out)
	}
	if !strings.Contains(out, "pos_fam") || !strings.Contains(out, "2/3") {
		t.Fatalf("per-family detected/total missing:\n%s", out)
	}
}
