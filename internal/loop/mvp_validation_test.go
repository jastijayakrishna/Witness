package loop

import (
	"fmt"
	"testing"
)

// mvp_validation_test.go
//
// This test is the PROOF of the MVP promise: the detector blocks runaway
// loops and passes legitimate work — across BOTH tool-calling agents and
// plain-chat (non-tool) requests.
//
// It exercises the detector exactly as the patched handler calls it:
//   - Tool requests: ToolName + Args from the call, Result from the prior
//     tool result fed back in the request body.
//   - Non-tool requests: ToolName="_prompt", Args=promptHash, Result=promptHash
//     (the prompt-hash unification fix).
//
// If this test passes, the core product does what it claims.

const pseudoPromptTool = "_prompt"

// run feeds a sequence of observations and returns the final decision.
func runMVP(t *testing.T, cfg Config, session string, n int, mk func(i int) Observation) Decision {
	t.Helper()
	state := NewState()
	var dec Decision
	base := int64(1_700_000_000_000)
	for i := 0; i < n; i++ {
		obs := mk(i)
		obs.SessionID = session
		obs.UnixMillis = base + int64(i)*1000 // 1s apart
		state, dec = Observe(state, obs, cfg)
	}
	return dec
}

// ──────────────────────────────────────────────────────────────────────
// STOP BAD: a tool-calling agent stuck calling the same tool, same args.
// ──────────────────────────────────────────────────────────────────────
func TestMVP_ToolLoop_Blocks(t *testing.T) {
	cfg := DefaultConfig()
	dec := runMVP(t, cfg, "loop-session", 8, func(i int) Observation {
		return Observation{
			ToolName:     "search_docs",
			Args:         map[string]any{"query": "reset password"}, // identical
			Result:       "no results found",                        // identical
			PromptTokens: 1200 + i*300,                              // context creeping up
			OutputTokens: 40,
			CostUSD:      0.012,
		}
	})
	if dec.ActionCeiling != ActionBlock {
		t.Fatalf("runaway tool loop should BLOCK, got ceiling=%s confidence=%.2f signals=%v",
			dec.ActionCeiling, dec.Confidence, dec.SignalsFired)
	}
	t.Logf("✓ tool loop blocked: confidence=%.2f signals=%v", dec.Confidence, dec.SignalsFired)
}

// ──────────────────────────────────────────────────────────────────────
// PASS LEGIT: a batch agent calling the same tool with DIFFERENT args,
// getting DIFFERENT results — real progress. Must NOT block.
// ──────────────────────────────────────────────────────────────────────
func TestMVP_LegitBatch_Passes(t *testing.T) {
	cfg := DefaultConfig()
	dec := runMVP(t, cfg, "batch-session", 12, func(i int) Observation {
		return Observation{
			ToolName:     "fetch_invoice",
			Args:         map[string]any{"invoice_id": fmt.Sprintf("INV-%04d", i)}, // varies
			Result:       fmt.Sprintf("invoice total $%d.00", 100+i*7),             // varies
			PromptTokens: 1000,
			OutputTokens: 120,
			CostUSD:      0.008,
		}
	})
	if dec.ActionCeiling == ActionBlock {
		t.Fatalf("legitimate batch work must PASS, but was BLOCKED: confidence=%.2f signals=%v",
			dec.Confidence, dec.SignalsFired)
	}
	t.Logf("✓ legit batch passed: ceiling=%s confidence=%.2f", dec.ActionCeiling, dec.Confidence)
}

// ──────────────────────────────────────────────────────────────────────
// STOP BAD (non-tool): a plain-chat retry storm — same prompt, no tools.
// This is the case the detector was BLIND to before the prompt-hash fix.
// Simulated exactly as the patched handler will feed it.
// ──────────────────────────────────────────────────────────────────────
func TestMVP_PlainChatLoop_Blocks(t *testing.T) {
	cfg := DefaultConfig()
	dec := runMVP(t, cfg, "chat-loop-session", 8, func(i int) Observation {
		return Observation{
			ToolName:     pseudoPromptTool,
			Args:         "prompthash_ABC123", // identical prompt every turn
			Result:       "prompthash_ABC123", // result tracks prompt for non-tool
			PromptTokens: 600,
			OutputTokens: 55,
			CostUSD:      0.006,
		}
	})
	if dec.ActionCeiling != ActionBlock {
		t.Fatalf("plain-chat retry storm should BLOCK, got ceiling=%s confidence=%.2f signals=%v",
			dec.ActionCeiling, dec.Confidence, dec.SignalsFired)
	}
	t.Logf("✓ plain-chat loop blocked: confidence=%.2f signals=%v", dec.Confidence, dec.SignalsFired)
}

// ──────────────────────────────────────────────────────────────────────
// PASS LEGIT (non-tool): a normal chat session — different prompt each turn.
// Must NOT block (proves the prompt-hash fix has no false-positive on real chat).
// ──────────────────────────────────────────────────────────────────────
func TestMVP_VariedChat_Passes(t *testing.T) {
	cfg := DefaultConfig()
	dec := runMVP(t, cfg, "chat-session", 12, func(i int) Observation {
		return Observation{
			ToolName:     pseudoPromptTool,
			Args:         fmt.Sprintf("prompthash_turn_%d", i), // unique each turn
			Result:       fmt.Sprintf("prompthash_turn_%d", i),
			PromptTokens: 500 + i*20,
			OutputTokens: 90,
			CostUSD:      0.005,
		}
	})
	if dec.ActionCeiling == ActionBlock {
		t.Fatalf("normal varied chat must PASS, but was BLOCKED: confidence=%.2f signals=%v",
			dec.Confidence, dec.SignalsFired)
	}
	t.Logf("✓ varied chat passed: ceiling=%s confidence=%.2f", dec.ActionCeiling, dec.Confidence)
}

// ──────────────────────────────────────────────────────────────────────
// PASS LEGIT: a couple of legitimate retries (transient error) must not trip.
// ──────────────────────────────────────────────────────────────────────
func TestMVP_FewRetries_Pass(t *testing.T) {
	cfg := DefaultConfig()
	dec := runMVP(t, cfg, "retry-session", 2, func(i int) Observation {
		return Observation{
			ToolName:     "call_api",
			Args:         map[string]any{"endpoint": "/charge"},
			Result:       "503 retry",
			PromptTokens: 800,
			OutputTokens: 30,
			CostUSD:      0.004,
		}
	})
	if dec.ActionCeiling == ActionBlock {
		t.Fatalf("2 retries must PASS, but was BLOCKED: confidence=%.2f", dec.Confidence)
	}
	t.Logf("✓ few retries passed: ceiling=%s confidence=%.2f", dec.ActionCeiling, dec.Confidence)
}
