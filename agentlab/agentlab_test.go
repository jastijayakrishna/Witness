package main

import (
	"context"
	"strings"
	"testing"
)

// runSceneOffline runs one scene against a fresh embedded HubbleOps with the
// scripted planner. This is the whole suite, no network, no API key.
func runSceneOffline(t *testing.T, sceneName string) (*Transcript, Scene) {
	t.Helper()
	var scene Scene
	found := false
	for _, s := range allScenes() {
		if s.Name == sceneName {
			scene, found = s, true
			break
		}
	}
	if !found {
		t.Fatalf("unknown scene %q", sceneName)
	}
	script := scriptFor(sceneName)
	if script == nil {
		t.Fatalf("no script for scene %q", sceneName)
	}
	lab, err := startHubbleOps()
	if err != nil {
		t.Fatalf("start hubbleops: %v", err)
	}
	t.Cleanup(lab.Close)

	tr, err := runScene(context.Background(), lab, newFakePlanner(script), scene)
	if err != nil {
		t.Fatalf("run scene: %v", err)
	}
	return tr, scene
}

func assertVerdict(t *testing.T, sceneName string) (*Transcript, []string) {
	t.Helper()
	tr, scene := runSceneOffline(t, sceneName)
	got, detail := scene.Verdict(tr)
	if got != scene.Expect {
		t.Fatalf("scene %q verdict=%s want %s\ndetail: %v\nevents: %+v", sceneName, got, scene.Expect, detail, tr.Events)
	}
	return tr, detail
}

// ---------- best case: nothing legitimate may be blocked ----------

func TestB1LegitimateRefundsAreClean(t *testing.T) {
	assertVerdict(t, "B1 legitimate refunds")
}

// B2 is also the end-to-end proof of the claim-nonce roundtrip: if the nonce
// were not echoed, the rate-limited claim would never release and the retry
// would be stuck behind a 409 instead of executing.
func TestB2HonestRetryIsClean(t *testing.T) {
	tr, _ := assertVerdict(t, "B2 honest retry after provable failure")
	for _, ev := range tr.Events {
		if ev.CheckStatus == 409 {
			t.Fatalf("retry hit in-flight: claim nonce was not echoed/released: %+v", tr.Events)
		}
	}
}

func TestB3BatchWorkIsClean(t *testing.T) {
	assertVerdict(t, "B3 batch work is not a loop")
}

// ---------- worst case ----------

func TestW1DuplicateRefundAfterTimeoutIsCaught(t *testing.T) {
	tr, _ := assertVerdict(t, "W1 duplicate refund after timeout")
	// The blind retry during the hold must have been refused as in-flight.
	saw409 := false
	for _, ev := range tr.Events {
		if ev.CheckStatus == 409 {
			saw409 = true
		}
	}
	if !saw409 {
		t.Fatalf("expected the blind retry to hit an in-flight hold: %+v", tr.Events)
	}
}

func TestW2RunawayLoopIsCaught(t *testing.T) {
	assertVerdict(t, "W2 runaway retry loop")
}

func TestW3DangerousDeleteIsCaught(t *testing.T) {
	tr, _ := assertVerdict(t, "W3 dangerous delete without precondition")
	if tr.Executions["delete_account"] != 0 {
		t.Fatalf("delete executed despite block")
	}
}

func TestW4KeyTamperingIsCaught(t *testing.T) {
	assertVerdict(t, "W4 idempotency key tampering")
}

func TestW5WindowCollapseIsCaught(t *testing.T) {
	assertVerdict(t, "W5 duplicate-window collapse attempt")
}

func TestW6UnkeyedDuplicateIsPartial(t *testing.T) {
	assertVerdict(t, "W6 unkeyed duplicate write")
}

// Step 4 flipped this scene: rotation still sheds loop state, but the
// key-scoped velocity limit holds.
func TestW7SessionRotationIsCaughtByVelocityLimit(t *testing.T) {
	assertVerdict(t, "W7 session rotation to shed loop state")
}

// Step 4 flipped this scene: the cumulative cap stops the drain mid-spray.
func TestW8CumulativeDrainIsCaughtByCumulativeCap(t *testing.T) {
	assertVerdict(t, "W8 cumulative drain under the per-action cap")
}

func TestW9CircuitBreakerQuarantinesAgent(t *testing.T) {
	assertVerdict(t, "W9 circuit breaker quarantines a tripping agent")
}

// ---------- mechanics ----------

// Block reasons must reach the model: a real agent can only adapt if the
// firewall's explanation is fed back as the tool response.
func TestBlockReasonIsFedBackToPlanner(t *testing.T) {
	var scene Scene
	for _, s := range allScenes() {
		if strings.HasPrefix(s.Name, "W3") {
			scene = s
		}
	}
	lab, err := startHubbleOps()
	if err != nil {
		t.Fatalf("start hubbleops: %v", err)
	}
	t.Cleanup(lab.Close)
	p := newFakePlanner(scriptFor(scene.Name))
	if _, err := runScene(context.Background(), lab, p, scene); err != nil {
		t.Fatalf("run scene: %v", err)
	}
	if len(p.Fed) == 0 {
		t.Fatalf("planner was never fed a tool response")
	}
	last := p.Fed[len(p.Fed)-1]
	if last["error"] != "blocked_by_hubbleops" || last["reason"] == "" {
		t.Fatalf("block reason did not reach the planner: %+v", last)
	}
}

// The lab's own evidence must verify: every scene leaves a tamper-evident
// WAL trail behind.
func TestLabWALVerifies(t *testing.T) {
	lab, err := startHubbleOps()
	if err != nil {
		t.Fatalf("start hubbleops: %v", err)
	}
	t.Cleanup(lab.Close)
	scene := allScenes()[0]
	if _, err := runScene(context.Background(), lab, newFakePlanner(scriptFor(scene.Name)), scene); err != nil {
		t.Fatalf("run scene: %v", err)
	}
	report, err := verifyLabWAL(lab)
	if err != nil {
		t.Fatalf("verify wal: %v", err)
	}
	if !report.Verified || report.TotalRecords == 0 {
		t.Fatalf("lab WAL did not verify: %+v", report)
	}
}
