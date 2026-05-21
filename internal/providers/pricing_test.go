package providers

import (
	"math"
	"testing"
)

func almostEqual(a, b, tolerance float64) bool {
	return math.Abs(a-b) < tolerance
}

func TestComputeCost_GPT4oMini(t *testing.T) {
	// gpt-4o-mini: $0.15/1M input, $0.60/1M output
	// 1000 input + 500 output = $0.00015 + $0.0003 = $0.00045
	cost := ComputeCost("gpt-4o-mini", 1000, 500)
	expected := 1000*0.15/1_000_000 + 500*0.60/1_000_000
	if !almostEqual(cost, expected, 1e-12) {
		t.Errorf("cost = %.12f, want %.12f", cost, expected)
	}
}

func TestComputeCost_GPT4o(t *testing.T) {
	// gpt-4o: $2.50/1M input, $10.00/1M output
	cost := ComputeCost("gpt-4o", 10000, 2000)
	expected := 10000*2.50/1_000_000 + 2000*10.00/1_000_000
	if !almostEqual(cost, expected, 1e-12) {
		t.Errorf("cost = %.12f, want %.12f", cost, expected)
	}
}

func TestComputeCost_Claude35Sonnet(t *testing.T) {
	// claude-3-5-sonnet: $3.00/1M input, $15.00/1M output
	cost := ComputeCost("claude-3-5-sonnet-20241022", 5000, 1000)
	expected := 5000*3.00/1_000_000 + 1000*15.00/1_000_000
	if !almostEqual(cost, expected, 1e-12) {
		t.Errorf("cost = %.12f, want %.12f", cost, expected)
	}
}

func TestComputeCost_ClaudeOpus(t *testing.T) {
	// claude-3-opus: $15.00/1M input, $75.00/1M output — the expensive one
	cost := ComputeCost("claude-3-opus-20240229", 100000, 50000)
	expected := 100000*15.00/1_000_000 + 50000*75.00/1_000_000
	if !almostEqual(cost, expected, 1e-10) {
		t.Errorf("cost = %.10f, want %.10f", cost, expected)
	}
}

func TestComputeCost_UnknownModel(t *testing.T) {
	cost := ComputeCost("unknown-model-v99", 1000, 500)
	if cost != 0 {
		t.Errorf("expected 0 for unknown model, got %f", cost)
	}
}

func TestComputeCost_ZeroTokens(t *testing.T) {
	cost := ComputeCost("gpt-4o", 0, 0)
	if cost != 0 {
		t.Errorf("expected 0 for zero tokens, got %f", cost)
	}
}

func TestComputeCost_OnlyInput(t *testing.T) {
	cost := ComputeCost("gpt-4o-mini", 1_000_000, 0)
	expected := 0.15 // $0.15 per million input tokens
	if !almostEqual(cost, expected, 1e-10) {
		t.Errorf("cost = %f, want %f", cost, expected)
	}
}

func TestComputeCost_OnlyOutput(t *testing.T) {
	cost := ComputeCost("gpt-4o-mini", 0, 1_000_000)
	expected := 0.60 // $0.60 per million output tokens
	if !almostEqual(cost, expected, 1e-10) {
		t.Errorf("cost = %f, want %f", cost, expected)
	}
}

// Verify every model in the pricing table produces non-zero cost
func TestComputeCost_AllModelsNonZero(t *testing.T) {
	for model := range PricingTable {
		cost := ComputeCost(model, 100, 100)
		if cost <= 0 {
			t.Errorf("model %q produced zero or negative cost: %f", model, cost)
		}
	}
}

// Verify relative pricing makes sense (sanity checks)
func TestPricingRelativeOrder(t *testing.T) {
	// GPT-4 should be more expensive than GPT-4o
	gpt4 := ComputeCost("gpt-4", 1000, 1000)
	gpt4o := ComputeCost("gpt-4o", 1000, 1000)
	if gpt4 <= gpt4o {
		t.Errorf("gpt-4 ($%.6f) should be more expensive than gpt-4o ($%.6f)", gpt4, gpt4o)
	}

	// GPT-4o-mini should be cheaper than GPT-4o
	gpt4oMini := ComputeCost("gpt-4o-mini", 1000, 1000)
	if gpt4oMini >= gpt4o {
		t.Errorf("gpt-4o-mini ($%.6f) should be cheaper than gpt-4o ($%.6f)", gpt4oMini, gpt4o)
	}

	// Claude Opus should be more expensive than Claude Sonnet
	opus := ComputeCost("claude-3-opus-20240229", 1000, 1000)
	sonnet := ComputeCost("claude-3-5-sonnet-20241022", 1000, 1000)
	if opus <= sonnet {
		t.Errorf("claude-3-opus ($%.6f) should be more expensive than claude-3-5-sonnet ($%.6f)", opus, sonnet)
	}

	// Claude Haiku should be cheapest Anthropic model
	haiku := ComputeCost("claude-3-haiku-20240307", 1000, 1000)
	if haiku >= sonnet {
		t.Errorf("claude-3-haiku ($%.6f) should be cheaper than claude-3-5-sonnet ($%.6f)", haiku, sonnet)
	}
}
