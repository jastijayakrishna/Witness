package wal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrS3AnchorObjectExists = errors.New("s3 checkpoint object already exists")

type S3AnchorClient interface {
	PutCheckpoint(ctx context.Context, bucket, key string, body []byte, retentionUntil time.Time) error
	ListCheckpoints(ctx context.Context, bucket, prefix string) ([]string, error)
	GetCheckpoint(ctx context.Context, bucket, key string) ([]byte, error)
}

type S3ObjectLockAnchor struct {
	Bucket         string
	Prefix         string
	Region         string
	RetentionDays  int
	Endpoint       string
	ForcePathStyle bool
	Client         S3AnchorClient
	Now            func() time.Time
}

func NewS3ObjectLockAnchor(raw string) (*S3ObjectLockAnchor, error) {
	a := &S3ObjectLockAnchor{
		Bucket:         strings.TrimSpace(os.Getenv("HUBBLEOPS_S3_ANCHOR_BUCKET")),
		Prefix:         strings.Trim(strings.TrimSpace(os.Getenv("HUBBLEOPS_S3_ANCHOR_PREFIX")), "/"),
		Region:         firstNonEmptyEnv("HUBBLEOPS_S3_ANCHOR_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"),
		Endpoint:       strings.TrimSpace(os.Getenv("HUBBLEOPS_S3_ANCHOR_ENDPOINT")),
		ForcePathStyle: parseEnvBool("HUBBLEOPS_S3_ANCHOR_FORCE_PATH_STYLE"),
		RetentionDays:  envIntDefault("HUBBLEOPS_S3_ANCHOR_RETENTION_DAYS", 30),
	}
	if a.Endpoint != "" && os.Getenv("HUBBLEOPS_S3_ANCHOR_FORCE_PATH_STYLE") == "" {
		a.ForcePathStyle = true
	}

	raw = strings.TrimSpace(raw)
	if raw != "" {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parse s3 anchor: %w", err)
		}
		if u.Scheme != "s3" {
			return nil, fmt.Errorf("s3 anchor must use s3:// URL")
		}
		if strings.TrimSpace(u.Host) != "" {
			a.Bucket = strings.TrimSpace(u.Host)
		}
		if prefix := strings.Trim(strings.TrimSpace(u.Path), "/"); prefix != "" {
			a.Prefix = prefix
		}
		q := u.Query()
		if v := strings.TrimSpace(q.Get("region")); v != "" {
			a.Region = v
		}
		if v := strings.TrimSpace(q.Get("retention_days")); v != "" {
			days, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("parse s3 retention_days: %w", err)
			}
			a.RetentionDays = days
		}
		if v := strings.TrimSpace(q.Get("endpoint")); v != "" {
			a.Endpoint = v
		}
		if v := strings.TrimSpace(q.Get("path_style")); v != "" {
			a.ForcePathStyle = parseBoolString(v)
		}
	}
	if a.Prefix == "" {
		a.Prefix = "checkpoints"
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *S3ObjectLockAnchor) Publish(ctx context.Context, checkpoint Checkpoint) error {
	if err := a.validate(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if checkpoint.SignedAt.IsZero() {
		checkpoint.SignedAt = a.now().UTC()
	}
	body, err := json.Marshal(checkpoint)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	retentionUntil := a.now().UTC().Add(time.Duration(a.RetentionDays) * 24 * time.Hour)
	if err := a.client().PutCheckpoint(ctx, a.Bucket, a.checkpointKey(checkpoint.Seq), body, retentionUntil); err != nil {
		return fmt.Errorf("put s3 checkpoint: %w", err)
	}
	return nil
}

func (a *S3ObjectLockAnchor) Latest(ctx context.Context) (Checkpoint, error) {
	if err := a.validate(); err != nil {
		return Checkpoint{}, err
	}
	select {
	case <-ctx.Done():
		return Checkpoint{}, ctx.Err()
	default:
	}
	keys, err := a.client().ListCheckpoints(ctx, a.Bucket, a.keyPrefix())
	if err != nil {
		return Checkpoint{}, fmt.Errorf("list s3 checkpoints: %w", err)
	}
	latestKey, latestSeq := "", uint64(0)
	for _, key := range keys {
		seq, ok := checkpointSeqFromKey(a.keyPrefix(), key)
		if !ok {
			continue
		}
		if seq > latestSeq {
			latestSeq = seq
			latestKey = key
		}
	}
	if latestKey == "" {
		return Checkpoint{}, fmt.Errorf("s3 anchor has no checkpoints")
	}
	body, err := a.client().GetCheckpoint(ctx, a.Bucket, latestKey)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("read s3 checkpoint: %w", err)
	}
	var cp Checkpoint
	if err := json.Unmarshal(body, &cp); err != nil {
		return Checkpoint{}, fmt.Errorf("parse s3 checkpoint: %w", err)
	}
	return cp, nil
}

func (a *S3ObjectLockAnchor) validate() error {
	if a == nil {
		return fmt.Errorf("s3 anchor is required")
	}
	if strings.TrimSpace(a.Bucket) == "" {
		return fmt.Errorf("s3 anchor bucket is required")
	}
	if strings.TrimSpace(a.Region) == "" {
		return fmt.Errorf("s3 anchor region is required")
	}
	if a.RetentionDays <= 0 {
		return fmt.Errorf("s3 anchor retention days must be positive")
	}
	return nil
}

func (a *S3ObjectLockAnchor) client() S3AnchorClient {
	if a.Client != nil {
		return a.Client
	}
	return &s3SigV4Client{
		region:         a.Region,
		endpoint:       a.Endpoint,
		forcePathStyle: a.ForcePathStyle,
		httpClient:     http.DefaultClient,
	}
}

func (a *S3ObjectLockAnchor) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now().UTC()
}

func (a *S3ObjectLockAnchor) keyPrefix() string {
	return strings.Trim(strings.TrimSpace(a.Prefix), "/")
}

func (a *S3ObjectLockAnchor) checkpointKey(seq uint64) string {
	prefix := a.keyPrefix()
	name := fmt.Sprintf("%020d.json", seq)
	if prefix == "" {
		return name
	}
	return prefix + "/" + name
}

func checkpointSeqFromKey(prefix, key string) (uint64, bool) {
	prefix = strings.Trim(strings.TrimSpace(prefix), "/")
	if prefix != "" {
		prefix += "/"
		if !strings.HasPrefix(key, prefix) {
			return 0, false
		}
		key = strings.TrimPrefix(key, prefix)
	}
	if strings.Contains(key, "/") || !strings.HasSuffix(key, ".json") {
		return 0, false
	}
	raw := strings.TrimSuffix(key, ".json")
	if len(raw) != 20 {
		return 0, false
	}
	seq, err := strconv.ParseUint(raw, 10, 64)
	return seq, err == nil
}

type s3SigV4Client struct {
	region         string
	endpoint       string
	forcePathStyle bool
	httpClient     *http.Client
}

func (c *s3SigV4Client) PutCheckpoint(ctx context.Context, bucket, key string, body []byte, retentionUntil time.Time) error {
	req, err := c.newRequest(ctx, http.MethodPut, bucket, key, nil, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-None-Match", "*")
	req.Header.Set("x-amz-object-lock-mode", "COMPLIANCE")
	req.Header.Set("x-amz-object-lock-retain-until-date", retentionUntil.UTC().Format(time.RFC3339))
	if err := c.sign(req, body); err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusPreconditionFailed || resp.StatusCode == http.StatusConflict {
		return ErrS3AnchorObjectExists
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return s3StatusError(resp)
	}
	return nil
}

func (c *s3SigV4Client) ListCheckpoints(ctx context.Context, bucket, prefix string) ([]string, error) {
	var keys []string
	token := ""
	for {
		q := url.Values{}
		q.Set("list-type", "2")
		listPrefix := strings.Trim(prefix, "/")
		if listPrefix != "" {
			listPrefix += "/"
		}
		q.Set("prefix", listPrefix)
		if token != "" {
			q.Set("continuation-token", token)
		}
		req, err := c.newRequest(ctx, http.MethodGet, bucket, "", q, nil)
		if err != nil {
			return nil, err
		}
		if err := c.sign(req, nil); err != nil {
			return nil, err
		}
		resp, err := c.do(req)
		if err != nil {
			return nil, err
		}
		body, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, s3StatusBodyError(resp.StatusCode, body)
		}
		var parsed s3ListBucketResult
		if err := xml.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("parse s3 list response: %w", err)
		}
		for _, item := range parsed.Contents {
			keys = append(keys, item.Key)
		}
		if !parsed.IsTruncated || strings.TrimSpace(parsed.NextContinuationToken) == "" {
			break
		}
		token = parsed.NextContinuationToken
	}
	return keys, nil
}

func (c *s3SigV4Client) GetCheckpoint(ctx context.Context, bucket, key string) ([]byte, error) {
	req, err := c.newRequest(ctx, http.MethodGet, bucket, key, nil, nil)
	if err != nil {
		return nil, err
	}
	if err := c.sign(req, nil); err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, s3StatusBodyError(resp.StatusCode, body)
	}
	return body, nil
}

func (c *s3SigV4Client) newRequest(ctx context.Context, method, bucket, key string, q url.Values, body io.Reader) (*http.Request, error) {
	u, err := c.objectURL(bucket, key)
	if err != nil {
		return nil, err
	}
	if q != nil {
		u.RawQuery = q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	req.Host = req.URL.Host
	return req, nil
}

func (c *s3SigV4Client) objectURL(bucket, key string) (*url.URL, error) {
	bucket = strings.TrimSpace(bucket)
	key = strings.Trim(key, "/")
	if c.endpoint != "" {
		base, err := url.Parse(c.endpoint)
		if err != nil {
			return nil, fmt.Errorf("parse s3 endpoint: %w", err)
		}
		if c.forcePathStyle {
			base.Path = joinURLPath(base.Path, bucket, key)
		} else {
			base.Host = bucket + "." + base.Host
			base.Path = joinURLPath(base.Path, key)
		}
		return base, nil
	}
	u := &url.URL{Scheme: "https"}
	if c.forcePathStyle {
		u.Host = fmt.Sprintf("s3.%s.amazonaws.com", c.region)
		u.Path = joinURLPath("", bucket, key)
	} else {
		u.Host = fmt.Sprintf("%s.s3.%s.amazonaws.com", bucket, c.region)
		u.Path = joinURLPath("", key)
	}
	return u, nil
}

func joinURLPath(parts ...string) string {
	var clean []string
	for _, part := range parts {
		part = strings.Trim(part, "/")
		if part != "" {
			clean = append(clean, part)
		}
	}
	return "/" + strings.Join(clean, "/")
}

func (c *s3SigV4Client) sign(req *http.Request, body []byte) error {
	accessKey := strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID"))
	secretKey := strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY"))
	sessionToken := strings.TrimSpace(os.Getenv("AWS_SESSION_TOKEN"))
	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required for s3 anchor")
	}
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")
	payloadHash := sha256Hex(body)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("x-amz-date", amzDate)
	if sessionToken != "" {
		req.Header.Set("x-amz-security-token", sessionToken)
	}
	if req.Host != "" {
		req.Header.Set("host", req.Host)
	} else {
		req.Header.Set("host", req.URL.Host)
	}

	canonicalHeaders, signedHeaders := canonicalS3Headers(req.Header)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.EscapedPath()),
		canonicalQuery(req.URL.Query()),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	scope := strings.Join([]string{dateStamp, c.region, "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signingKey := awsSigningKey(secretKey, dateStamp, c.region, "s3")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))
	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey,
		scope,
		signedHeaders,
		signature,
	))
	return nil
}

func (c *s3SigV4Client) do(req *http.Request) (*http.Response, error) {
	client := c.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	return client.Do(req)
}

type s3ListBucketResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

func canonicalS3Headers(headers http.Header) (string, string) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, strings.ToLower(key))
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, key := range keys {
		values := headers.Values(key)
		sort.Strings(values)
		canonical.WriteString(key)
		canonical.WriteByte(':')
		canonical.WriteString(strings.Join(canonicalHeaderValues(values), ","))
		canonical.WriteByte('\n')
	}
	return canonical.String(), strings.Join(keys, ";")
}

func canonicalHeaderValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.Join(strings.Fields(value), " "))
	}
	return out
}

func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func canonicalQuery(values url.Values) string {
	var parts []string
	for key, vals := range values {
		escapedKey := awsQueryEscape(key)
		sort.Strings(vals)
		for _, value := range vals {
			parts = append(parts, escapedKey+"="+awsQueryEscape(value))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

func awsQueryEscape(value string) string {
	escaped := url.QueryEscape(value)
	escaped = strings.ReplaceAll(escaped, "+", "%20")
	escaped = strings.ReplaceAll(escaped, "%7E", "~")
	return escaped
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func awsSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}

func s3StatusError(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	return s3StatusBodyError(resp.StatusCode, body)
}

func s3StatusBodyError(status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		msg = http.StatusText(status)
	}
	return fmt.Errorf("s3 returned status %d: %s", status, msg)
}

func firstNonEmptyEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func envIntDefault(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func parseEnvBool(key string) bool {
	return parseBoolString(os.Getenv(key))
}

func parseBoolString(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
