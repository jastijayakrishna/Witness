package wal

import "testing"

func BenchmarkWALWrite(b *testing.B) {
	dir := b.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		b.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	rec := Record{
		Project:      "bench-project",
		Provider:     "openai",
		Model:        "gpt-4o-mini",
		PromptHash:   "abcdef0123456789",
		InputTokens:  100,
		OutputTokens: 50,
		TotalTokens:  150,
		Cost:         0.000045,
		LatencyMs:    200,
		StatusCode:   200,
		CacheHit:     false,
		Stream:       false,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := w.Write(rec); err != nil {
			b.Fatalf("write: %v", err)
		}
	}
}

func BenchmarkWALWrite_Parallel(b *testing.B) {
	dir := b.TempDir()
	w, err := NewWriter(dir)
	if err != nil {
		b.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	rec := Record{
		Project:      "bench-parallel",
		Provider:     "openai",
		Model:        "gpt-4o-mini",
		PromptHash:   "abcdef0123456789",
		InputTokens:  100,
		OutputTokens: 50,
		TotalTokens:  150,
		Cost:         0.000045,
		StatusCode:   200,
	}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := w.Write(rec); err != nil {
				b.Fatalf("write: %v", err)
			}
		}
	})
}
