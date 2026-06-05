package providers

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog/log"
)

var unknownModelTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "llmproxy_unknown_model_total",
		Help: "Requests with models not in the pricing table. Cost recorded as zero.",
	},
	[]string{"model"},
)

func init() {
	prometheus.MustRegister(unknownModelTotal)
}

// ModelPricing holds per-token costs in USD.
type ModelPricing struct {
	InputPerToken  float64
	OutputPerToken float64
}

var DeprecatedModels = map[string]string{
	"gemini-2.0-flash":          "deprecated and shut down June 1, 2026; migrate to Gemini 2.5 or 3",
	"gemini-2.0-flash-001":      "deprecated and shut down June 1, 2026; migrate to Gemini 2.5 or 3",
	"gemini-2.0-flash-lite":     "deprecated and shut down June 1, 2026; migrate to Gemini 2.5 or 3",
	"gemini-2.0-flash-lite-001": "deprecated and shut down June 1, 2026; migrate to Gemini 2.5 or 3",
}

// PricingTable maps model names to their per-token costs.
// Prices in USD per token. Keep current with provider pricing docs.
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

	// Google Gemini
	"gemini-1.5-pro":                        {InputPerToken: 1.25 / 1_000_000, OutputPerToken: 5.00 / 1_000_000},
	"gemini-1.5-pro-001":                    {InputPerToken: 1.25 / 1_000_000, OutputPerToken: 5.00 / 1_000_000},
	"gemini-1.5-pro-002":                    {InputPerToken: 1.25 / 1_000_000, OutputPerToken: 5.00 / 1_000_000},
	"gemini-1.5-flash":                      {InputPerToken: 0.075 / 1_000_000, OutputPerToken: 0.30 / 1_000_000},
	"gemini-1.5-flash-001":                  {InputPerToken: 0.075 / 1_000_000, OutputPerToken: 0.30 / 1_000_000},
	"gemini-1.5-flash-002":                  {InputPerToken: 0.075 / 1_000_000, OutputPerToken: 0.30 / 1_000_000},
	"gemini-2.5-pro":                        {InputPerToken: 1.25 / 1_000_000, OutputPerToken: 10.00 / 1_000_000},
	"gemini-2.5-flash":                      {InputPerToken: 0.30 / 1_000_000, OutputPerToken: 2.50 / 1_000_000},
	"gemini-2.5-flash-preview-09-2025":      {InputPerToken: 0.30 / 1_000_000, OutputPerToken: 2.50 / 1_000_000},
	"gemini-2.5-flash-lite":                 {InputPerToken: 0.10 / 1_000_000, OutputPerToken: 0.40 / 1_000_000},
	"gemini-2.5-flash-lite-preview-09-2025": {InputPerToken: 0.10 / 1_000_000, OutputPerToken: 0.40 / 1_000_000},
	"gemini-3-pro-preview":                  {InputPerToken: 2.00 / 1_000_000, OutputPerToken: 12.00 / 1_000_000},
	"gemini-3-flash-preview":                {InputPerToken: 0.50 / 1_000_000, OutputPerToken: 3.00 / 1_000_000},
	"gemini-2.0-flash":                      {InputPerToken: 0.10 / 1_000_000, OutputPerToken: 0.40 / 1_000_000},
	"gemini-2.0-flash-001":                  {InputPerToken: 0.10 / 1_000_000, OutputPerToken: 0.40 / 1_000_000},
	"gemini-2.0-flash-exp":                  {InputPerToken: 0.10 / 1_000_000, OutputPerToken: 0.40 / 1_000_000},
	"gemini-2.0-flash-lite":                 {InputPerToken: 0.075 / 1_000_000, OutputPerToken: 0.30 / 1_000_000},
	"gemini-2.0-flash-lite-001":             {InputPerToken: 0.075 / 1_000_000, OutputPerToken: 0.30 / 1_000_000},
	"gemini-flash-latest":                   {InputPerToken: 0.30 / 1_000_000, OutputPerToken: 2.50 / 1_000_000},
	"gemini-flash-lite-latest":              {InputPerToken: 0.10 / 1_000_000, OutputPerToken: 0.40 / 1_000_000},
	"gemini-pro":                            {InputPerToken: 0.50 / 1_000_000, OutputPerToken: 1.50 / 1_000_000},
	"gemini-pro-vision":                     {InputPerToken: 0.50 / 1_000_000, OutputPerToken: 1.50 / 1_000_000},
}

// ComputeCost calculates the USD cost for a given model and token counts.
// Logs a warning and returns 0 if the model is not found in the pricing table.
func ComputeCost(model string, inputTokens, outputTokens int) float64 {
	p, ok := PricingFor(model)
	if !ok {
		if model != "" {
			unknownModelTotal.WithLabelValues(model).Inc()
			log.Warn().Str("model", model).Msg("unknown model: cost recorded as $0 — update PricingTable")
		}
		return 0
	}
	return float64(inputTokens)*p.InputPerToken + float64(outputTokens)*p.OutputPerToken
}

func PricingFor(model string) (ModelPricing, bool) {
	p, ok := PricingTable[model]
	return p, ok
}

func HasPricing(model string) bool {
	_, ok := PricingFor(model)
	return ok
}

func DeprecationNotice(model string) string {
	return DeprecatedModels[model]
}
