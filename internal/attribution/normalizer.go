package attribution

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"sync"
)

var (
	// Compiled regexes for normalization (compiled once at package init)
	isoTimestampRegex *regexp.Regexp
	uuidRegex         *regexp.Regexp
	emailRegex        *regexp.Regexp
	phoneRegex        *regexp.Regexp
	dollarRegex       *regexp.Regexp
	initOnce          sync.Once
)

// initRegexes compiles all normalization regexes once at boot.
func initRegexes() {
	initOnce.Do(func() {
		// ISO 8601 timestamps: YYYY-MM-DDTHH:MM:SS.sssZ or with timezone
		isoTimestampRegex = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3,6})?(Z|[+-]\d{2}:\d{2})?`)

		// UUIDs: standard format with hyphens
		uuidRegex = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

		// Email addresses
		emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

		// Phone numbers: requires explicit delimiters (parens, dashes, dots, spaces, or leading +).
		// Will NOT match bare 10-digit runs like token IDs or sequence numbers.
		// Matches: (123) 456-7890, 123-456-7890, +1-555-123-4567, 555.123.4567
		phoneRegex = regexp.MustCompile(`(\+\d{1,3}[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}`)

		// Dollar amounts: $123.45, $1,234.56, etc.
		dollarRegex = regexp.MustCompile(`\$\d{1,3}(,\d{3})*(\.\d{2})?`)
	})
}

// NormalizePrompt strips dynamic data from a prompt to enable deduplication.
// Removes: ISO timestamps, UUIDs, emails, phone numbers, dollar amounts.
// Returns the normalized string.
func NormalizePrompt(prompt string) string {
	initRegexes()

	normalized := prompt
	normalized = isoTimestampRegex.ReplaceAllString(normalized, "<TIMESTAMP>")
	normalized = uuidRegex.ReplaceAllString(normalized, "<UUID>")
	normalized = emailRegex.ReplaceAllString(normalized, "<EMAIL>")
	normalized = phoneRegex.ReplaceAllString(normalized, "<PHONE>")
	normalized = dollarRegex.ReplaceAllString(normalized, "<DOLLAR>")

	return normalized
}

// HashNormalizedPrompt normalizes a prompt and returns its SHA256 hash (16 hex chars).
func HashNormalizedPrompt(prompt string) string {
	normalized := NormalizePrompt(prompt)
	h := sha256.Sum256([]byte(normalized))
	// Return first 8 bytes as 16 hex characters
	return fmt.Sprintf("%x", h[:8])
}

// NormalizationRatio computes the ratio of normalized length to original length.
// A ratio < 0.5 indicates the prompt is mostly dynamic data (low dedup potential).
func NormalizationRatio(prompt string) float64 {
	if len(prompt) == 0 {
		return 1.0
	}
	normalized := NormalizePrompt(prompt)
	return float64(len(normalized)) / float64(len(prompt))
}
