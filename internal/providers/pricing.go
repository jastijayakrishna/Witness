package providers

// ModelPricing holds per-token costs in USD.
type ModelPricing struct {
	InputPerToken  float64
	OutputPerToken float64
}

// PricingTable maps model names to their per-token costs.
// Prices in USD. Updated as of early 2025.
var PricingTable = map[string]ModelPricing{
	// OpenAI
	"gpt-4o":                 {InputPerToken: 2.50 / 1_000_000, OutputPerToken: 10.00 / 1_000_000},
	"gpt-4o-2024-11-20":      {InputPerToken: 2.50 / 1_000_000, OutputPerToken: 10.00 / 1_000_000},
	"gpt-4o-2024-08-06":      {InputPerToken: 2.50 / 1_000_000, OutputPerToken: 10.00 / 1_000_000},
	"gpt-4o-2024-05-13":      {InputPerToken: 5.00 / 1_000_000, OutputPerToken: 15.00 / 1_000_000},
	"gpt-4o-mini":            {InputPerToken: 0.15 / 1_000_000, OutputPerToken: 0.60 / 1_000_000},
	"gpt-4o-mini-2024-07-18": {InputPerToken: 0.15 / 1_000_000, OutputPerToken: 0.60 / 1_000_000},
	"gpt-4-turbo":            {InputPerToken: 10.00 / 1_000_000, OutputPerToken: 30.00 / 1_000_000},
	"gpt-4-turbo-preview":    {InputPerToken: 10.00 / 1_000_000, OutputPerToken: 30.00 / 1_000_000},
	"gpt-4":                  {InputPerToken: 30.00 / 1_000_000, OutputPerToken: 60.00 / 1_000_000},
	"gpt-3.5-turbo":          {InputPerToken: 0.50 / 1_000_000, OutputPerToken: 1.50 / 1_000_000},
	"o1":                     {InputPerToken: 15.00 / 1_000_000, OutputPerToken: 60.00 / 1_000_000},
	"o1-mini":                {InputPerToken: 3.00 / 1_000_000, OutputPerToken: 12.00 / 1_000_000},
	"o1-preview":             {InputPerToken: 15.00 / 1_000_000, OutputPerToken: 60.00 / 1_000_000},
	"o3-mini":                {InputPerToken: 1.10 / 1_000_000, OutputPerToken: 4.40 / 1_000_000},

	// Anthropic
	"claude-3-5-sonnet-20241022": {InputPerToken: 3.00 / 1_000_000, OutputPerToken: 15.00 / 1_000_000},
	"claude-3-5-sonnet-20240620": {InputPerToken: 3.00 / 1_000_000, OutputPerToken: 15.00 / 1_000_000},
	"claude-3-5-haiku-20241022":  {InputPerToken: 0.80 / 1_000_000, OutputPerToken: 4.00 / 1_000_000},
	"claude-3-opus-20240229":     {InputPerToken: 15.00 / 1_000_000, OutputPerToken: 75.00 / 1_000_000},
	"claude-3-sonnet-20240229":   {InputPerToken: 3.00 / 1_000_000, OutputPerToken: 15.00 / 1_000_000},
	"claude-3-haiku-20240307":    {InputPerToken: 0.25 / 1_000_000, OutputPerToken: 1.25 / 1_000_000},
	"claude-sonnet-4-20250514":   {InputPerToken: 3.00 / 1_000_000, OutputPerToken: 15.00 / 1_000_000},
	"claude-haiku-4-20250514":    {InputPerToken: 0.80 / 1_000_000, OutputPerToken: 4.00 / 1_000_000},
}

// ComputeCost calculates the USD cost for a given model and token counts.
// Returns 0 if the model is not found in the pricing table.
func ComputeCost(model string, inputTokens, outputTokens int) float64 {
	p, ok := PricingTable[model]
	if !ok {
		return 0
	}
	return float64(inputTokens)*p.InputPerToken + float64(outputTokens)*p.OutputPerToken
}
