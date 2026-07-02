//go:build integration && docker
// +build integration,docker

package receipts_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

const (
	kmsIntegrationAccessKey = "AKIDEXAMPLE"
	kmsIntegrationSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	kmsIntegrationRegion    = "us-east-1"
)

var kmsIntegrationNow = time.Date(2026, 7, 2, 10, 30, 0, 0, time.UTC)

func TestAwsKmsHTTPClientStrictSigV4Conformance(t *testing.T) {
	harness := newStrictKMSHarness(t)
	defer harness.Close()

	signer := harness.NewSigner(t, "kms-2026", "key-a")
	rec := kmsIntegrationRecord("decision-1", 1, "genesis")
	sig, keyID, err := signer.SignRecord(rec)
	if err != nil {
		t.Fatalf("sign record through strict KMS harness: %v", err)
	}
	rec.ReceiptSignature = sig
	rec.ReceiptKeyID = keyID

	pub, err := receipts.ParsePublicKey(signer.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse published public key: %v", err)
	}
	if err := receipts.VerifyRecordWithPublicKey(pub, rec); err != nil {
		t.Fatalf("verify KMS-signed receipt with public key only: %v", err)
	}

	tampered := rec
	tampered.Target = "prod-db/attacker"
	if err := receipts.VerifyRecordWithPublicKey(pub, tampered); err == nil {
		t.Fatalf("tampered KMS-signed receipt verified")
	}

	cp, err := signer.SignCheckpoint(wal.Checkpoint{
		Seq:      3,
		HeadHash: "head-3",
		Count:    3,
		SignedAt: kmsIntegrationNow,
	})
	if err != nil {
		t.Fatalf("sign checkpoint through strict KMS harness: %v", err)
	}
	if err := receipts.VerifyCheckpointWithPublicKey(pub, cp); err != nil {
		t.Fatalf("verify KMS-signed checkpoint with public key only: %v", err)
	}
	tamperedCP := cp
	tamperedCP.Count++
	if err := receipts.VerifyCheckpointWithPublicKey(pub, tamperedCP); err == nil {
		t.Fatalf("tampered KMS-signed checkpoint verified")
	}
}

func TestAwsKmsHTTPClientRandomBatchVerifiesWithPublishedPublicKeyOnly(t *testing.T) {
	harness := newStrictKMSHarness(t)
	defer harness.Close()

	signer := harness.NewSigner(t, "kms-batch", "key-a")
	pub, err := receipts.ParsePublicKey(signer.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse published public key: %v", err)
	}

	rng := rand.New(rand.NewSource(20260702))
	prevHash := "genesis"
	for i := 0; i < 50; i++ {
		rec := kmsIntegrationRecord(fmt.Sprintf("random-%02d-%d", i, rng.Int63()), uint64(i+1), prevHash)
		rec.RiskScore = rng.Intn(100)
		rec.AmountCents = int64(rng.Intn(10_000_000))
		rec.EvidenceHashes = []string{fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(rec.DecisionID)))}

		sig, keyID, err := signer.SignRecord(rec)
		if err != nil {
			t.Fatalf("sign random record %d: %v", i, err)
		}
		rec.ReceiptSignature = sig
		rec.ReceiptKeyID = keyID
		if err := receipts.VerifyRecordWithPublicKey(pub, rec); err != nil {
			t.Fatalf("verify random record %d with public key only: %v", i, err)
		}

		prev := sha256.Sum256([]byte(rec.DecisionID + rec.PrevHash))
		prevHash = hex.EncodeToString(prev[:])
	}
}

func TestAwsKmsHTTPClientStrictSigV4Rotation(t *testing.T) {
	harness := newStrictKMSHarness(t)
	defer harness.Close()

	oldSigner := harness.NewSigner(t, "kms-2025", "key-old")
	newSigner := harness.NewSigner(t, "kms-2026", "key-new")

	oldRec := signKMSIntegrationRecord(t, oldSigner, kmsIntegrationRecord("old-decision", 1, "genesis"))
	newRec := signKMSIntegrationRecord(t, newSigner, kmsIntegrationRecord("new-decision", 2, "old-hash"))

	oldPub, err := receipts.ParsePublicKey(oldSigner.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse old public key: %v", err)
	}
	newPub, err := receipts.ParsePublicKey(newSigner.PublicKeyBase64())
	if err != nil {
		t.Fatalf("parse new public key: %v", err)
	}

	keyset := receipts.NewKeySet()
	keyset.Add("kms-2025", oldPub)
	keyset.Add("kms-2026", newPub)
	if err := keyset.VerifyRecord(oldRec); err != nil {
		t.Fatalf("old KMS receipt failed rotation verify: %v", err)
	}
	if err := keyset.VerifyRecord(newRec); err != nil {
		t.Fatalf("new KMS receipt failed rotation verify: %v", err)
	}
}

func TestStrictKMSHarnessRejectsMiscanonicalizedSignature(t *testing.T) {
	harness := newStrictKMSHarness(t)
	defer harness.Close()

	body := []byte(`{"KeyId":"key-a"}`)
	req, err := http.NewRequest(http.MethodPost, harness.URL(), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "TrentService.GetPublicKey")
	signKMSIntegrationRequest(t, req, body, "/wrong-canonical-path")

	resp, err := harness.Client().Do(req)
	if err != nil {
		t.Fatalf("send miscanonicalized request: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("miscanonicalized request status=%d body=%s, want 403", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if !strings.Contains(string(raw), "signature mismatch") {
		t.Fatalf("miscanonicalized request body=%q, want signature mismatch", string(raw))
	}
}

type strictKMSHarness struct {
	t      *testing.T
	server *httptest.Server
	keys   map[string]ed25519.PrivateKey
}

func newStrictKMSHarness(t *testing.T) *strictKMSHarness {
	t.Helper()
	h := &strictKMSHarness{
		t: t,
		keys: map[string]ed25519.PrivateKey{
			"key-a":   kmsIntegrationPrivateKey("key-a"),
			"key-old": kmsIntegrationPrivateKey("key-old"),
			"key-new": kmsIntegrationPrivateKey("key-new"),
		},
	}
	h.server = httptest.NewServer(http.HandlerFunc(h.handle))
	return h
}

func (h *strictKMSHarness) URL() string {
	return h.server.URL
}

func (h *strictKMSHarness) Client() *http.Client {
	return h.server.Client()
}

func (h *strictKMSHarness) Close() {
	h.server.Close()
}

func (h *strictKMSHarness) NewSigner(t *testing.T, receiptKeyID, keyRef string) *receipts.AwsKmsSigner {
	t.Helper()
	client := &receipts.AwsKmsHTTPClient{
		Region:          kmsIntegrationRegion,
		Endpoint:        h.URL(),
		AccessKeyID:     kmsIntegrationAccessKey,
		SecretAccessKey: kmsIntegrationSecretKey,
		HTTPClient:      h.Client(),
		Now:             func() time.Time { return kmsIntegrationNow },
	}
	signer, err := receipts.NewAwsKmsSigner(context.Background(), receiptKeyID, keyRef, client)
	if err != nil {
		t.Fatalf("new KMS signer: %v", err)
	}
	return signer
}

func (h *strictKMSHarness) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.verifySigV4(r, body); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	switch r.Header.Get("X-Amz-Target") {
	case "TrentService.Sign":
		var in struct {
			KeyID            string `json:"KeyId"`
			Message          string `json:"Message"`
			MessageType      string `json:"MessageType"`
			SigningAlgorithm string `json:"SigningAlgorithm"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		priv, ok := h.keys[in.KeyID]
		if !ok {
			http.Error(w, "unknown key", http.StatusNotFound)
			return
		}
		if in.MessageType != "RAW" || in.SigningAlgorithm != "EDDSA" {
			http.Error(w, "unsupported signing request", http.StatusBadRequest)
			return
		}
		payload, err := base64.StdEncoding.DecodeString(in.Message)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"Signature": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
		})
	case "TrentService.GetPublicKey":
		var in struct {
			KeyID string `json:"KeyId"`
		}
		if err := json.Unmarshal(body, &in); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		priv, ok := h.keys[in.KeyID]
		if !ok {
			http.Error(w, "unknown key", http.StatusNotFound)
			return
		}
		der, err := x509.MarshalPKIXPublicKey(priv.Public().(ed25519.PublicKey))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"PublicKey": base64.StdEncoding.EncodeToString(der),
		})
	default:
		http.Error(w, "unknown target", http.StatusBadRequest)
	}
}

func (h *strictKMSHarness) verifySigV4(r *http.Request, body []byte) error {
	auth, err := parseKMSIntegrationAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return err
	}
	credParts := strings.Split(auth.Credential, "/")
	if len(credParts) != 5 {
		return fmt.Errorf("invalid credential scope")
	}
	accessKey, dateStamp, region, service, terminal := credParts[0], credParts[1], credParts[2], credParts[3], credParts[4]
	if accessKey != kmsIntegrationAccessKey || region != kmsIntegrationRegion || service != "kms" || terminal != "aws4_request" {
		return fmt.Errorf("invalid credential scope")
	}
	amzDate := strings.TrimSpace(r.Header.Get("X-Amz-Date"))
	if amzDate == "" || !strings.HasPrefix(amzDate, dateStamp) {
		return fmt.Errorf("invalid x-amz-date")
	}
	payloadHash := kmsIntegrationSHA256Hex(body)
	if got := strings.TrimSpace(r.Header.Get("X-Amz-Content-Sha256")); got != payloadHash {
		return fmt.Errorf("payload hash mismatch")
	}

	signedHeaders := strings.Split(auth.SignedHeaders, ";")
	if len(signedHeaders) == 0 || !sort.StringsAreSorted(signedHeaders) {
		return fmt.Errorf("signed headers are not sorted")
	}
	var canonicalHeaders strings.Builder
	for _, name := range signedHeaders {
		if strings.TrimSpace(name) == "" || name != strings.ToLower(name) {
			return fmt.Errorf("invalid signed header %q", name)
		}
		value, ok := kmsIntegrationHeaderValue(r, name)
		if !ok {
			return fmt.Errorf("missing signed header %q", name)
		}
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(value)
		canonicalHeaders.WriteByte('\n')
	}

	canonicalRequest := strings.Join([]string{
		r.Method,
		kmsIntegrationCanonicalURI(r.URL),
		kmsIntegrationCanonicalQuery(r.URL.Query()),
		canonicalHeaders.String(),
		auth.SignedHeaders,
		payloadHash,
	}, "\n")
	scope := strings.Join([]string{dateStamp, region, service, terminal}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		kmsIntegrationSHA256Hex([]byte(canonicalRequest)),
	}, "\n")
	signingKey := kmsIntegrationSigningKey(kmsIntegrationSecretKey, dateStamp, region, service)
	wantSignature := kmsIntegrationHMACHex(signingKey, []byte(stringToSign))
	got, err := hex.DecodeString(auth.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding")
	}
	want, err := hex.DecodeString(wantSignature)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

type kmsIntegrationAuthorization struct {
	Credential    string
	SignedHeaders string
	Signature     string
}

func parseKMSIntegrationAuthorization(header string) (kmsIntegrationAuthorization, error) {
	header = strings.TrimSpace(header)
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(header, prefix) {
		return kmsIntegrationAuthorization{}, fmt.Errorf("missing AWS4 authorization")
	}
	attrs := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(header, prefix), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return kmsIntegrationAuthorization{}, fmt.Errorf("invalid authorization attribute")
		}
		attrs[key] = value
	}
	out := kmsIntegrationAuthorization{
		Credential:    attrs["Credential"],
		SignedHeaders: attrs["SignedHeaders"],
		Signature:     attrs["Signature"],
	}
	if out.Credential == "" || out.SignedHeaders == "" || out.Signature == "" {
		return kmsIntegrationAuthorization{}, fmt.Errorf("incomplete authorization header")
	}
	return out, nil
}

func kmsIntegrationHeaderValue(r *http.Request, name string) (string, bool) {
	if name == "host" {
		if strings.TrimSpace(r.Host) == "" {
			return "", false
		}
		return strings.Join(strings.Fields(r.Host), " "), true
	}
	values := r.Header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	sort.Strings(values)
	clean := make([]string, 0, len(values))
	for _, value := range values {
		clean = append(clean, strings.Join(strings.Fields(value), " "))
	}
	return strings.Join(clean, ","), true
}

func signKMSIntegrationRequest(t *testing.T, req *http.Request, body []byte, canonicalPath string) {
	t.Helper()
	amzDate := kmsIntegrationNow.Format("20060102T150405Z")
	dateStamp := kmsIntegrationNow.Format("20060102")
	payloadHash := kmsIntegrationSHA256Hex(body)
	req.Host = req.URL.Host
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signedHeaders := "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target"
	canonicalHeaders := strings.Join([]string{
		"content-type:" + strings.Join(strings.Fields(req.Header.Get("Content-Type")), " "),
		"host:" + req.URL.Host,
		"x-amz-content-sha256:" + payloadHash,
		"x-amz-date:" + amzDate,
		"x-amz-target:" + strings.Join(strings.Fields(req.Header.Get("X-Amz-Target")), " "),
		"",
	}, "\n")
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalPath,
		kmsIntegrationCanonicalQuery(req.URL.Query()),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	scope := strings.Join([]string{dateStamp, kmsIntegrationRegion, "kms", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		kmsIntegrationSHA256Hex([]byte(canonicalRequest)),
	}, "\n")
	signature := kmsIntegrationHMACHex(
		kmsIntegrationSigningKey(kmsIntegrationSecretKey, dateStamp, kmsIntegrationRegion, "kms"),
		[]byte(stringToSign),
	)
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		kmsIntegrationAccessKey,
		scope,
		signedHeaders,
		signature,
	))
}

func signKMSIntegrationRecord(t *testing.T, signer receipts.ReceiptSigner, rec wal.Record) wal.Record {
	t.Helper()
	sig, keyID, err := signer.SignRecord(rec)
	if err != nil {
		t.Fatalf("sign record: %v", err)
	}
	rec.ReceiptSignature = sig
	rec.ReceiptKeyID = keyID
	return rec
}

func kmsIntegrationRecord(decisionID string, seq uint64, prevHash string) wal.Record {
	return wal.Record{
		Seq:               seq,
		PrevHash:          prevHash,
		Project:           "project-a",
		SessionID:         "session-a",
		DecisionID:        decisionID,
		Actor:             "agent:integration",
		Action:            "terraform.apply",
		Target:            "prod-db",
		Environment:       "production",
		Decision:          "block",
		RiskScore:         95,
		PolicyVersion:     "kms-integration",
		DecisionReason:    "destructive production change",
		RequiredApprovers: []string{"sre"},
		EvidenceHashes:    []string{"sha256:evidence"},
	}
}

func kmsIntegrationPrivateKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("kms-integration:" + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

func kmsIntegrationCanonicalURI(u *url.URL) string {
	if u == nil || u.EscapedPath() == "" {
		return "/"
	}
	return u.EscapedPath()
}

func kmsIntegrationCanonicalQuery(values url.Values) string {
	var parts []string
	for key, vals := range values {
		escapedKey := kmsIntegrationQueryEscape(key)
		sort.Strings(vals)
		for _, value := range vals {
			parts = append(parts, escapedKey+"="+kmsIntegrationQueryEscape(value))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

func kmsIntegrationQueryEscape(value string) string {
	escaped := url.QueryEscape(value)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}

func kmsIntegrationSigningKey(secret, dateStamp, region, service string) []byte {
	kDate := kmsIntegrationHMAC([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := kmsIntegrationHMAC(kDate, []byte(region))
	kService := kmsIntegrationHMAC(kRegion, []byte(service))
	return kmsIntegrationHMAC(kService, []byte("aws4_request"))
}

func kmsIntegrationHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

func kmsIntegrationHMACHex(key, data []byte) string {
	return hex.EncodeToString(kmsIntegrationHMAC(key, data))
}

func kmsIntegrationSHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
