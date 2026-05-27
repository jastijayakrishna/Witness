package attribution

import (
	"strings"
	"testing"
)

func TestNormalizePrompt(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		contains string
		notContains string
	}{
		{
			name:        "ISO timestamp",
			input:       "Log at 2025-01-15T10:30:45.123Z shows error",
			contains:    "<TIMESTAMP>",
			notContains: "2025-01-15",
		},
		{
			name:        "UUID",
			input:       "Request ID: 550e8400-e29b-41d4-a716-446655440000",
			contains:    "<UUID>",
			notContains: "550e8400",
		},
		{
			name:        "Email",
			input:       "Contact john.doe@example.com for support",
			contains:    "<EMAIL>",
			notContains: "john.doe@example.com",
		},
		{
			name:        "Phone US format",
			input:       "Call us at (555) 123-4567",
			contains:    "<PHONE>",
			notContains: "555",
		},
		{
			name:        "Phone dashes",
			input:       "Mobile: 555-123-4567",
			contains:    "<PHONE>",
			notContains: "555-123",
		},
		{
			name:        "Dollar amount",
			input:       "Total cost: $1,234.56",
			contains:    "<DOLLAR>",
			notContains: "$1,234",
		},
		{
			name:        "Multiple timestamps",
			input:       "From 2025-01-15T10:00:00Z to 2025-01-15T11:00:00Z",
			contains:    "<TIMESTAMP>",
			notContains: "2025-01-15",
		},
		{
			name:     "No dynamic data",
			input:    "What is the capital of France?",
			contains: "France",
		},
		{
			name:        "Mixed dynamic data",
			input:       "User 550e8400-e29b-41d4-a716-446655440000 paid $99.99 on 2025-01-15T10:30:45Z",
			contains:    "<UUID>",
			notContains: "550e8400",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePrompt(tt.input)

			if tt.contains != "" && !strings.Contains(result, tt.contains) {
				t.Errorf("expected result to contain %q, got %q", tt.contains, result)
			}

			if tt.notContains != "" && strings.Contains(result, tt.notContains) {
				t.Errorf("expected result to not contain %q, got %q", tt.notContains, result)
			}
		})
	}
}

func TestHashNormalizedPrompt(t *testing.T) {
	// Same content with different dynamic data should hash to same value
	prompt1 := `{"message": "User 550e8400-e29b-41d4-a716-446655440000 logged in at 2025-01-15T10:30:45Z"}`
	prompt2 := `{"message": "User 660e8400-e29b-41d4-a716-446655440001 logged in at 2025-01-15T11:45:30Z"}`

	hash1 := HashNormalizedPrompt(prompt1)
	hash2 := HashNormalizedPrompt(prompt2)

	if hash1 != hash2 {
		t.Errorf("normalized hashes should match: %s != %s", hash1, hash2)
	}

	// Different content should hash differently
	prompt3 := `{"message": "User logged out"}`
	hash3 := HashNormalizedPrompt(prompt3)

	if hash1 == hash3 {
		t.Error("different content should produce different hashes")
	}

	// Hash should be 16 hex characters
	if len(hash1) != 16 {
		t.Errorf("expected 16-char hash, got %d: %s", len(hash1), hash1)
	}
}

func TestHashNormalizedPromptDeterministic(t *testing.T) {
	prompt := `{"messages": [{"role": "user", "content": "Hello at 2025-01-15T10:30:45Z"}]}`

	hash1 := HashNormalizedPrompt(prompt)
	hash2 := HashNormalizedPrompt(prompt)

	if hash1 != hash2 {
		t.Errorf("hashing same prompt twice should produce same result: %s != %s", hash1, hash2)
	}
}

func TestNormalizationRatio(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedRatio float64
		tolerance     float64
	}{
		{
			name:          "No dynamic data",
			input:         "What is the capital of France?",
			expectedRatio: 1.0,
			tolerance:     0.01,
		},
		{
			name:          "All dynamic data",
			input:         "2025-01-15T10:30:45Z",
			expectedRatio: 0.6, // <TIMESTAMP> is shorter than the original
			tolerance:     0.2,
		},
		{
			name:          "Mixed data",
			input:         "User 550e8400-e29b-41d4-a716-446655440000 sent message at 2025-01-15T10:30:45Z",
			expectedRatio: 0.6,
			tolerance:     0.2,
		},
		{
			name:          "Empty string",
			input:         "",
			expectedRatio: 1.0,
			tolerance:     0.01,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratio := NormalizationRatio(tt.input)

			if ratio < tt.expectedRatio-tt.tolerance || ratio > tt.expectedRatio+tt.tolerance {
				t.Errorf("expected ratio ~%.2f, got %.2f", tt.expectedRatio, ratio)
			}
		})
	}
}

func TestNormalizePromptEdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t   "},
		{"very long", strings.Repeat("a", 10000)},
		{"unicode", "User 550e8400-e29b-41d4-a716-446655440000 said: 你好世界 🌍"},
		{"multiple UUIDs", "ID1: 550e8400-e29b-41d4-a716-446655440000 ID2: 660e8400-e29b-41d4-a716-446655440001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			result := NormalizePrompt(tt.input)

			// Result should not be empty for non-empty input (except whitespace-only)
			if tt.name != "empty" && tt.name != "whitespace only" && result == "" {
				t.Error("normalization should not produce empty result for non-empty input")
			}
		})
	}
}

func TestNormalizeTimestampFormats(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"ISO with Z", "2025-01-15T10:30:45Z"},
		{"ISO with millis", "2025-01-15T10:30:45.123Z"},
		{"ISO with micros", "2025-01-15T10:30:45.123456Z"},
		{"ISO with timezone", "2025-01-15T10:30:45+05:30"},
		{"ISO with negative timezone", "2025-01-15T10:30:45-08:00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePrompt(tt.input)

			if !strings.Contains(result, "<TIMESTAMP>") {
				t.Errorf("failed to normalize %q, got %q", tt.input, result)
			}

			if strings.Contains(result, "2025") {
				t.Errorf("timestamp not fully removed: %q", result)
			}
		})
	}
}

func TestNormalizeEmail(t *testing.T) {
	emails := []string{
		"simple@example.com",
		"user.name@example.com",
		"user+tag@example.co.uk",
		"user123@sub.example.com",
	}

	for _, email := range emails {
		result := NormalizePrompt(email)
		if !strings.Contains(result, "<EMAIL>") {
			t.Errorf("failed to normalize email %q, got %q", email, result)
		}
		if strings.Contains(result, "@") {
			t.Errorf("email not fully removed: %q", result)
		}
	}
}

func TestNormalizePhone(t *testing.T) {
	shouldMatch := []string{
		"(555) 123-4567",
		"555-123-4567",
		"555.123.4567",
		"+1-555-123-4567",
	}
	for _, phone := range shouldMatch {
		result := NormalizePrompt(phone)
		if !strings.Contains(result, "<PHONE>") {
			t.Errorf("expected <PHONE> for %q, got %q", phone, result)
		}
	}

	// Bare digit runs must NOT match — they collide with token IDs, sequence numbers, etc.
	shouldNotMatch := []string{
		"5551234567",
		"1234567890",
		"token_id: 9876543210",
	}
	for _, input := range shouldNotMatch {
		result := NormalizePrompt(input)
		if strings.Contains(result, "<PHONE>") {
			t.Errorf("bare digit run %q should NOT be normalized as phone, got %q", input, result)
		}
	}
}

func BenchmarkNormalizePrompt(b *testing.B) {
	prompt := `{"messages": [{"role": "user", "content": "User 550e8400-e29b-41d4-a716-446655440000 sent email to john@example.com with invoice $1,234.56 on 2025-01-15T10:30:45.123Z"}]}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NormalizePrompt(prompt)
	}
}

func BenchmarkHashNormalizedPrompt(b *testing.B) {
	prompt := `{"messages": [{"role": "user", "content": "User 550e8400-e29b-41d4-a716-446655440000 sent email to john@example.com"}]}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HashNormalizedPrompt(prompt)
	}
}

func BenchmarkNormalizationRatio(b *testing.B) {
	prompt := `{"messages": [{"role": "user", "content": "User sent message at 2025-01-15T10:30:45Z"}]}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NormalizationRatio(prompt)
	}
}
