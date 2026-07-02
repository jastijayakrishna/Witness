package receipts

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hubbleops/hubbleops/internal/wal"
)

var ErrExternalSignerNotImplemented = errors.New("external signer is not implemented")

type AwsKmsClient interface {
	Sign(ctx context.Context, keyRef string, payload []byte) ([]byte, error)
	PublicKey(ctx context.Context, keyRef string) (ed25519.PublicKey, error)
}

type AwsKmsSigner struct {
	receiptKeyID string
	keyRef       string
	client       AwsKmsClient

	mu        sync.Mutex
	publicKey ed25519.PublicKey
}

func NewAwsKmsSigner(ctx context.Context, receiptKeyID, keyRef string, client AwsKmsClient) (*AwsKmsSigner, error) {
	signer := NewLazyAwsKmsSigner(receiptKeyID, keyRef, client)
	if err := signer.ensurePublicKey(ctx); err != nil {
		return nil, err
	}
	return signer, nil
}

func NewLazyAwsKmsSigner(receiptKeyID, keyRef string, client AwsKmsClient) *AwsKmsSigner {
	return &AwsKmsSigner{
		receiptKeyID: normalizeKeyID(receiptKeyID),
		keyRef:       strings.TrimSpace(keyRef),
		client:       client,
	}
}

func NewAwsKmsSignerFromEnv(receiptKeyID, keyRef string) (*AwsKmsSigner, error) {
	keyRef = strings.TrimSpace(keyRef)
	if keyRef == "" {
		return nil, fmt.Errorf("AWS KMS key id is required")
	}
	client, err := NewAwsKmsHTTPClientFromEnv()
	if err != nil {
		return nil, err
	}
	return NewLazyAwsKmsSigner(receiptKeyID, keyRef, client), nil
}

func (s *AwsKmsSigner) PublicKeyBase64() string {
	if err := s.ensurePublicKey(context.Background()); err != nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return base64.RawURLEncoding.EncodeToString(s.publicKey)
}

func (s *AwsKmsSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.receiptKeyID
}

func (s *AwsKmsSigner) SignRecord(rec wal.Record) (string, string, error) {
	if s == nil || s.client == nil {
		return "", "", fmt.Errorf("AWS KMS signer is not configured")
	}
	rec.ReceiptKeyID = s.receiptKeyID
	payload, err := canonicalPayload(rec)
	if err != nil {
		return "", "", err
	}
	sig, err := s.client.Sign(context.Background(), s.keyRef, payload)
	if err != nil {
		return "", "", err
	}
	if len(sig) != ed25519.SignatureSize {
		return "", "", fmt.Errorf("AWS KMS returned invalid Ed25519 signature length %d", len(sig))
	}
	return encodeRecordSignature(sig), s.receiptKeyID, nil
}

func (s *AwsKmsSigner) SignCheckpoint(cp wal.Checkpoint) (wal.Checkpoint, error) {
	if s == nil || s.client == nil {
		return cp, fmt.Errorf("AWS KMS signer is not configured")
	}
	cp.KeyID = s.receiptKeyID
	if cp.SignedAt.IsZero() {
		cp.SignedAt = nowUTC()
	}
	payload, err := canonicalCheckpointPayload(cp)
	if err != nil {
		return cp, err
	}
	sig, err := s.client.Sign(context.Background(), s.keyRef, payload)
	if err != nil {
		return cp, err
	}
	if len(sig) != ed25519.SignatureSize {
		return cp, fmt.Errorf("AWS KMS returned invalid Ed25519 signature length %d", len(sig))
	}
	cp.Signature = encodeCheckpointSignature(sig)
	return cp, nil
}

func (s *AwsKmsSigner) ensurePublicKey(ctx context.Context) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("AWS KMS signer is not configured")
	}
	s.mu.Lock()
	if len(s.publicKey) == ed25519.PublicKeySize {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	pub, err := s.client.PublicKey(ctx, s.keyRef)
	if err != nil {
		return err
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("AWS KMS returned invalid Ed25519 public key length %d", len(pub))
	}

	s.mu.Lock()
	s.publicKey = append(ed25519.PublicKey(nil), pub...)
	s.mu.Unlock()
	return nil
}

type AwsKmsHTTPClient struct {
	Region          string
	Endpoint        string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	HTTPClient      *http.Client
	Now             func() time.Time
}

func NewAwsKmsHTTPClientFromEnv() (*AwsKmsHTTPClient, error) {
	region := firstNonEmpty(
		os.Getenv("HUBBLEOPS_RECEIPT_KMS_REGION"),
		os.Getenv("AWS_REGION"),
		os.Getenv("AWS_DEFAULT_REGION"),
	)
	if strings.TrimSpace(region) == "" {
		return nil, fmt.Errorf("AWS KMS region is required")
	}
	endpoint := strings.TrimSpace(os.Getenv("HUBBLEOPS_RECEIPT_KMS_ENDPOINT"))
	if endpoint == "" {
		endpoint = "https://kms." + region + ".amazonaws.com/"
	}
	return &AwsKmsHTTPClient{
		Region:          region,
		Endpoint:        endpoint,
		AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
		SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
		SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		HTTPClient:      &http.Client{Timeout: 15 * time.Second},
		Now:             time.Now,
	}, nil
}

func (c *AwsKmsHTTPClient) Sign(ctx context.Context, keyRef string, payload []byte) ([]byte, error) {
	var out struct {
		Signature string `json:"Signature"`
	}
	if err := c.invoke(ctx, "TrentService.Sign", map[string]string{
		"KeyId":            keyRef,
		"Message":          base64.StdEncoding.EncodeToString(payload),
		"MessageType":      "RAW",
		"SigningAlgorithm": "EDDSA",
	}, &out); err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(out.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode AWS KMS signature: %w", err)
	}
	return sig, nil
}

func (c *AwsKmsHTTPClient) PublicKey(ctx context.Context, keyRef string) (ed25519.PublicKey, error) {
	var out struct {
		PublicKey string `json:"PublicKey"`
	}
	if err := c.invoke(ctx, "TrentService.GetPublicKey", map[string]string{
		"KeyId": keyRef,
	}, &out); err != nil {
		return nil, err
	}
	der, err := base64.StdEncoding.DecodeString(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode AWS KMS public key: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse AWS KMS public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("AWS KMS key is %T, want Ed25519", parsed)
	}
	return append(ed25519.PublicKey(nil), pub...), nil
}

func (c *AwsKmsHTTPClient) invoke(ctx context.Context, target string, input any, output any) error {
	if c == nil {
		return fmt.Errorf("AWS KMS client is nil")
	}
	endpoint := strings.TrimSpace(c.Endpoint)
	if endpoint == "" {
		if strings.TrimSpace(c.Region) == "" {
			return fmt.Errorf("AWS KMS region is required")
		}
		endpoint = "https://kms." + c.Region + ".amazonaws.com/"
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	if err := c.signRequest(req, body, target); err != nil {
		return err
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("AWS KMS %s failed: status=%d body=%s", target, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return json.NewDecoder(resp.Body).Decode(output)
}

func (c *AwsKmsHTTPClient) signRequest(req *http.Request, body []byte, target string) error {
	if strings.TrimSpace(c.AccessKeyID) == "" || strings.TrimSpace(c.SecretAccessKey) == "" {
		return fmt.Errorf("AWS KMS credentials are required")
	}
	region := strings.TrimSpace(c.Region)
	if region == "" {
		return fmt.Errorf("AWS KMS region is required")
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	t := now().UTC()
	amzDate := t.Format("20060102T150405Z")
	dateStamp := t.Format("20060102")
	payloadHash := sha256Hex(body)

	req.URL = ensureRootPath(req.URL)
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if strings.TrimSpace(c.SessionToken) != "" {
		req.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}

	signedHeaderNames := []string{
		"content-type",
		"host",
		"x-amz-content-sha256",
		"x-amz-date",
		"x-amz-target",
	}
	if strings.TrimSpace(c.SessionToken) != "" {
		signedHeaderNames = append(signedHeaderNames, "x-amz-security-token")
	}
	sort.Strings(signedHeaderNames)

	var canonicalHeaders strings.Builder
	for _, name := range signedHeaderNames {
		canonicalHeaders.WriteString(name)
		canonicalHeaders.WriteByte(':')
		canonicalHeaders.WriteString(strings.TrimSpace(req.Header.Get(name)))
		canonicalHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(signedHeaderNames, ";")
	canonicalRequest := strings.Join([]string{
		req.Method,
		awsCanonicalURI(req.URL),
		req.URL.RawQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")
	credentialScope := strings.Join([]string{dateStamp, region, "kms", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signingKey := awsV4SigningKey(c.SecretAccessKey, dateStamp, region, "kms")
	signature := hmacHex(signingKey, []byte(stringToSign))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKeyID,
		credentialScope,
		signedHeaders,
		signature,
	))
	req.Header.Set("X-Amz-Target", target)
	return nil
}

func ensureRootPath(u *url.URL) *url.URL {
	if u.Path == "" {
		copy := *u
		copy.Path = "/"
		return &copy
	}
	return u
}

func awsCanonicalURI(u *url.URL) string {
	if u == nil || u.EscapedPath() == "" {
		return "/"
	}
	return u.EscapedPath()
}

func awsV4SigningKey(secret, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacHex(key, data []byte) string {
	return hex.EncodeToString(hmacSHA256(key, data))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// GCPKMSSigner is RESERVED and NOT YET IMPLEMENTED: SignRecord and
// SignCheckpoint always return ErrExternalSignerNotImplemented. Configuration
// paths (config.CheckReceiptSignerImplemented) reject "gcp-kms" before this
// type is ever constructed in production; it exists so the signer taxonomy and
// tests keep a stable name for the planned implementation. See
// docs/ROADMAP-SIGNERS.md for the contract a real implementation must satisfy.
type GCPKMSSigner struct {
	keyID  string
	keyRef string
}

func NewGCPKMSSigner(keyID, keyRef string) *GCPKMSSigner {
	return &GCPKMSSigner{keyID: normalizeKeyID(keyID), keyRef: strings.TrimSpace(keyRef)}
}

func (s *GCPKMSSigner) SignRecord(wal.Record) (string, string, error) {
	return "", "", ErrExternalSignerNotImplemented
}

func (s *GCPKMSSigner) SignCheckpoint(cp wal.Checkpoint) (wal.Checkpoint, error) {
	return cp, ErrExternalSignerNotImplemented
}

func (s *GCPKMSSigner) PublicKeyBase64() string {
	return ""
}

func (s *GCPKMSSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// VaultTransitSigner is RESERVED and NOT YET IMPLEMENTED: SignRecord and
// SignCheckpoint always return ErrExternalSignerNotImplemented. Configuration
// paths (config.CheckReceiptSignerImplemented) reject "vault-transit" before
// this type is ever constructed in production. See docs/ROADMAP-SIGNERS.md.
type VaultTransitSigner struct {
	keyID  string
	keyRef string
}

func NewVaultTransitSigner(keyID, keyRef string) *VaultTransitSigner {
	return &VaultTransitSigner{keyID: normalizeKeyID(keyID), keyRef: strings.TrimSpace(keyRef)}
}

func (s *VaultTransitSigner) SignRecord(wal.Record) (string, string, error) {
	return "", "", ErrExternalSignerNotImplemented
}

func (s *VaultTransitSigner) SignCheckpoint(cp wal.Checkpoint) (wal.Checkpoint, error) {
	return cp, ErrExternalSignerNotImplemented
}

func (s *VaultTransitSigner) PublicKeyBase64() string {
	return ""
}

func (s *VaultTransitSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}
