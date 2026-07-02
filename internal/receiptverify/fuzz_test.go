package receiptverify

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func FuzzVerifierAddStream(f *testing.F) {
	f.Add([]byte(`{"seq":1,"decision_id":"dec_seed","prev_hash":"genesis","record_hash":"bad","receipt_signature":"bad"}` + "\n"))
	f.Add([]byte(`{"seq":`))
	pub := receipts.NewSigner("fuzz", []byte("fuzz-secret")).PublicKeyBase64()
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := NewVerifier(Options{
			ReceiptPublicKey:  pub,
			RequireSignatures: true,
		})
		if err != nil {
			t.Fatalf("new verifier: %v", err)
		}
		if err := v.AddStream(bytes.NewReader(data)); err != nil {
			return
		}
		report := v.Report()
		if report.Verified && report.ActionReceipts > 0 {
			if report.UnsignedReceipts > 0 || report.SignatureMismatches > 0 || report.SignedReceipts != report.ActionReceipts {
				t.Fatalf("verified=true without valid signatures: %+v", report)
			}
		}
	})
}

func FuzzWALDecode(f *testing.F) {
	f.Add([]byte(`{"seq":1,"prev_hash":"genesis","record_hash":"bad"}` + "\n"))
	f.Add([]byte(`not-json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		dec := json.NewDecoder(bytes.NewReader(data))
		for {
			var rec wal.Record
			if err := dec.Decode(&rec); err != nil {
				if err == io.EOF {
					return
				}
				return
			}
		}
	})
}
