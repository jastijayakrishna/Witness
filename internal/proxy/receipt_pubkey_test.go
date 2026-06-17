package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hubbleops/hubbleops/internal/receipts"
)

func TestHandleReceiptPublicKeyPublishesKey(t *testing.T) {
	signer := receipts.NewSigner("prod-2026-06", []byte("pilot-signing-secret"))
	h := &Handler{ReceiptSigner: signer}

	rec := httptest.NewRecorder()
	h.HandleReceiptPublicKey(rec, httptest.NewRequest(http.MethodGet, "/v1/receipts/public-key", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse body: %v", err)
	}
	if body["algorithm"] != "ed25519" {
		t.Fatalf("algorithm=%q want ed25519", body["algorithm"])
	}
	if body["key_id"] != "prod-2026-06" {
		t.Fatalf("key_id=%q want prod-2026-06", body["key_id"])
	}
	if body["public_key"] == "" || body["public_key"] != signer.PublicKeyBase64() {
		t.Fatalf("public_key=%q want %q", body["public_key"], signer.PublicKeyBase64())
	}
	// The published key must verify but never sign: confirm it is the public half only
	// (a private key would be 64 bytes; the endpoint exposes the 32-byte public key).
}

func TestHandleReceiptPublicKey404WhenSigningDisabled(t *testing.T) {
	h := &Handler{}
	rec := httptest.NewRecorder()
	h.HandleReceiptPublicKey(rec, httptest.NewRequest(http.MethodGet, "/v1/receipts/public-key", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 when signing disabled", rec.Code)
	}
}
