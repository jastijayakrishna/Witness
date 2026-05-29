package loop

import "testing"

// BenchmarkObserve_Runaway measures Observe throughput on the worst case:
// identical args, accelerating cost, all signals firing. This is the path
// that does the most work (hashing, velocity calc, cycle detection).
func BenchmarkObserve_Runaway(b *testing.B) {
	cfg := DefaultConfig()
	obs := makeRunaway(12, "bench")

	b.ResetTimer()
	for range b.N {
		s := State{}
		for _, o := range obs {
			s, _ = Observe(s, o, cfg)
		}
	}
}

// BenchmarkObserve_Batch measures Observe throughput on the best case:
// changing args, flat cost, no signals fired. This is the hot path for
// legitimate high-volume batch jobs.
func BenchmarkObserve_Batch(b *testing.B) {
	cfg := DefaultConfig()
	obs := makeBatch(50, "bench")

	b.ResetTimer()
	for range b.N {
		s := State{}
		for _, o := range obs {
			s, _ = Observe(s, o, cfg)
		}
	}
}

// BenchmarkObserve_500Calls measures end-to-end throughput of 500 calls.
// Verifies that bounded history (historyCap=12) keeps per-call cost constant.
func BenchmarkObserve_500Calls(b *testing.B) {
	cfg := DefaultConfig()
	obs := makeBatch(500, "bench")

	b.ResetTimer()
	for range b.N {
		s := State{}
		for _, o := range obs {
			s, _ = Observe(s, o, cfg)
		}
	}
}
