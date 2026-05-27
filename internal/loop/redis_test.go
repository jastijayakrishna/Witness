package loop

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T) (*StateStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return NewStateStore(rdb), mr
}

func TestStateKey(t *testing.T) {
	got := stateKey("proj-1", "sess-abc")
	want := "loop:proj-1:sess-abc"
	if got != want {
		t.Errorf("stateKey = %q, want %q", got, want)
	}
}

func TestStateStore_LoadMiss(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	state, err := store.Load(ctx, "proj", "nonexistent")
	if err != nil {
		t.Fatalf("Load miss returned error: %v", err)
	}
	// Empty state expected
	if len(state.CallHistory) != 0 || len(state.CostEvents) != 0 {
		t.Error("Load miss should return empty state")
	}
}

func TestStateStore_SaveAndLoad(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	original := State{
		CallHistory:   []callKey{{Tool: "bash", ArgsHash: "abc123"}, {Tool: "read", ArgsHash: "def456"}},
		ResultHistory: []resultKey{{Tool: "bash", ResultHash: "res1"}},
		ContextSizes:  []int{100, 200, 300},
		OutputSizes:   []int{50, 60},
		CostEvents:    []costEvent{{T: 1700000000000, Cost: 0.01}, {T: 1700000060000, Cost: 0.02}},
	}

	if err := store.Save(ctx, "proj", "sess-1", original); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load(ctx, "proj", "sess-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Verify all fields roundtrip
	if len(loaded.CallHistory) != 2 {
		t.Fatalf("CallHistory len = %d, want 2", len(loaded.CallHistory))
	}
	if loaded.CallHistory[0].Tool != "bash" || loaded.CallHistory[0].ArgsHash != "abc123" {
		t.Errorf("CallHistory[0] = %v", loaded.CallHistory[0])
	}
	if loaded.CallHistory[1].Tool != "read" || loaded.CallHistory[1].ArgsHash != "def456" {
		t.Errorf("CallHistory[1] = %v", loaded.CallHistory[1])
	}
	if len(loaded.ResultHistory) != 1 || loaded.ResultHistory[0].Tool != "bash" {
		t.Errorf("ResultHistory = %v", loaded.ResultHistory)
	}
	if len(loaded.ContextSizes) != 3 || loaded.ContextSizes[2] != 300 {
		t.Errorf("ContextSizes = %v", loaded.ContextSizes)
	}
	if len(loaded.OutputSizes) != 2 || loaded.OutputSizes[1] != 60 {
		t.Errorf("OutputSizes = %v", loaded.OutputSizes)
	}
	if len(loaded.CostEvents) != 2 || loaded.CostEvents[1].Cost != 0.02 {
		t.Errorf("CostEvents = %v", loaded.CostEvents)
	}
}

func TestStateStore_IsolatedBySession(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	s1 := State{CallHistory: []callKey{{Tool: "bash", ArgsHash: "aaa"}}}
	s2 := State{CallHistory: []callKey{{Tool: "read", ArgsHash: "bbb"}}}

	store.Save(ctx, "proj", "sess-1", s1)
	store.Save(ctx, "proj", "sess-2", s2)

	loaded1, _ := store.Load(ctx, "proj", "sess-1")
	loaded2, _ := store.Load(ctx, "proj", "sess-2")

	if loaded1.CallHistory[0].Tool != "bash" {
		t.Errorf("sess-1 contaminated: got tool %q", loaded1.CallHistory[0].Tool)
	}
	if loaded2.CallHistory[0].Tool != "read" {
		t.Errorf("sess-2 contaminated: got tool %q", loaded2.CallHistory[0].Tool)
	}
}

func TestStateStore_TTL(t *testing.T) {
	store, mr := newTestStore(t)
	ctx := context.Background()

	state := State{CallHistory: []callKey{{Tool: "bash", ArgsHash: "x"}}}
	store.Save(ctx, "proj", "sess", state)

	// Verify TTL was set
	ttl := mr.TTL(stateKey("proj", "sess"))
	if ttl <= 0 {
		t.Fatal("TTL not set on saved state")
	}
	if ttl > 10*time.Minute+time.Second {
		t.Errorf("TTL = %v, expected ~10m", ttl)
	}

	// Fast-forward past TTL
	mr.FastForward(11 * time.Minute)

	loaded, err := store.Load(ctx, "proj", "sess")
	if err != nil {
		t.Fatalf("Load after TTL: %v", err)
	}
	if len(loaded.CallHistory) != 0 {
		t.Error("state should have expired after TTL")
	}
}

func TestStateStore_OverwriteUpdatesState(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	// Save initial state
	s1 := State{CallHistory: []callKey{{Tool: "bash", ArgsHash: "v1"}}}
	store.Save(ctx, "proj", "sess", s1)

	// Overwrite with new state
	s2 := State{
		CallHistory: []callKey{{Tool: "bash", ArgsHash: "v1"}, {Tool: "bash", ArgsHash: "v2"}},
		CostEvents:  []costEvent{{T: 1700000000000, Cost: 0.05}},
	}
	store.Save(ctx, "proj", "sess", s2)

	loaded, _ := store.Load(ctx, "proj", "sess")
	if len(loaded.CallHistory) != 2 {
		t.Errorf("CallHistory len = %d after overwrite, want 2", len(loaded.CallHistory))
	}
	if len(loaded.CostEvents) != 1 {
		t.Errorf("CostEvents len = %d after overwrite, want 1", len(loaded.CostEvents))
	}
}

func TestStateStore_FullRoundtripWithDetector(t *testing.T) {
	// End-to-end: save detector output, load it back, feed another observation
	store, _ := newTestStore(t)
	ctx := context.Background()
	cfg := DefaultConfig()

	obs1 := Observation{
		Project: "proj", SessionID: "sess",
		ToolName: "bash", Args: map[string]string{"cmd": "ls"},
		PromptTokens: 100, OutputTokens: 20, CostUSD: 0.01,
		UnixMillis: 1700000000000,
	}

	state := State{}
	state, _ = Observe(state, obs1, cfg)

	// Persist
	if err := store.Save(ctx, "proj", "sess", state); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Load back
	loaded, err := store.Load(ctx, "proj", "sess")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Feed another observation into the loaded state
	obs2 := Observation{
		Project: "proj", SessionID: "sess",
		ToolName: "bash", Args: map[string]string{"cmd": "cat"},
		PromptTokens: 120, OutputTokens: 25, CostUSD: 0.01,
		UnixMillis: 1700000060000,
	}
	loaded, dec := Observe(loaded, obs2, cfg)

	// Should have 2 entries in call history
	if len(loaded.CallHistory) != 2 {
		t.Errorf("CallHistory len = %d after roundtrip, want 2", len(loaded.CallHistory))
	}
	// Second observation alone shouldn't trigger any signals
	if len(dec.SignalsFired) != 0 {
		t.Errorf("unexpected signals after 2 normal turns: %v", dec.SignalsFired)
	}
}
