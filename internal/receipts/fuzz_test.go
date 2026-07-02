package receipts

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/hubbleops/hubbleops/internal/wal"
)

func FuzzCanonicalPayload(f *testing.F) {
	f.Add([]byte(`{"seq":1,"prev_hash":"genesis","decision_id":"dec_seed","decision":"block","risk_score":95}`))
	f.Add([]byte(`{"evidence_hashes":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var rec wal.Record
		_ = json.Unmarshal(data, &rec)
		first, err := canonicalPayload(rec)
		if err != nil {
			return
		}
		second, err := canonicalPayload(rec)
		if err != nil {
			t.Fatalf("second canonical payload failed: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("canonical payload is not deterministic\nfirst=%s\nsecond=%s", first, second)
		}
	})
}
