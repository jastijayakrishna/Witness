package synthcorpus

import (
	"strings"
	"testing"
)

func TestReadJSONLSkipsBlanksAndComments(t *testing.T) {
	input := `# comment line

{"project":"p","session_id":"s1","tool_name":"read_file","args":{"f":1},"cost_usd":0.01,"unix_millis":1000,"label":"fam_a","expected_action":"block","expected_signal":"identical_repeat","source_incident":"A10","unknown_field":"ignored"}
{"project":"p","session_id":"s2","tool_name":"refund_payment","idempotency_key":"k1","action_risk":"dangerous","amount_cents":500,"max_amount_cents":100,"unix_millis":2000,"label":"fam_b","expected_action":"block"}
`
	events, err := ReadJSONL(strings.NewReader(input), "test.jsonl")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events=%d want 2", len(events))
	}
	if events[0].Label != "fam_a" || events[0].ExpectedSignal != "identical_repeat" || events[0].SourceIncident != "A10" {
		t.Fatalf("ground truth fields not decoded: %+v", events[0])
	}
	if events[1].AmountCents != 500 || events[1].MaxAmountCents != 100 || events[1].IdempotencyKey != "k1" {
		t.Fatalf("firewall fields not decoded: %+v", events[1])
	}
}

func TestReadJSONLFailsWithFileAndLine(t *testing.T) {
	_, err := ReadJSONL(strings.NewReader("{broken\n"), "bad.jsonl")
	if err == nil || !strings.Contains(err.Error(), "bad.jsonl") || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("want file+line in error, got: %v", err)
	}
}

func TestGroupSessionsPreservesOrder(t *testing.T) {
	events := []Event{
		{Project: "p", SessionID: "b", ToolName: "t", UnixMillis: 1},
		{Project: "p", SessionID: "a", ToolName: "t", UnixMillis: 2},
		{Project: "p", SessionID: "b", ToolName: "t", UnixMillis: 3},
	}
	sessions := GroupSessions(events)
	if len(sessions) != 2 {
		t.Fatalf("sessions=%d want 2", len(sessions))
	}
	if sessions[0].SessionID != "b" || len(sessions[0].Events) != 2 {
		t.Fatalf("first-seen order broken: %+v", sessions[0])
	}
	if sessions[0].Events[0].UnixMillis != 1 || sessions[0].Events[1].UnixMillis != 3 {
		t.Fatalf("event order broken within session")
	}
}
