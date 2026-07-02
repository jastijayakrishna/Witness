package wal

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestS3ObjectLockAnchorPublishesImmutableAndLatest(t *testing.T) {
	fake := newWORMS3Fake()
	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	anchor := &S3ObjectLockAnchor{
		Bucket:        "audit-bucket",
		Prefix:        "hubbleops/checkpoints",
		Region:        "us-east-1",
		RetentionDays: 7,
		Client:        fake,
		Now:           func() time.Time { return now },
	}

	cp1 := Checkpoint{Seq: 1, HeadHash: "hash-1", Count: 1, SignedAt: now}
	cp2 := Checkpoint{Seq: 2, HeadHash: "hash-2", Count: 2, SignedAt: now}
	if err := anchor.Publish(context.Background(), cp1); err != nil {
		t.Fatalf("publish cp1: %v", err)
	}
	if err := anchor.Publish(context.Background(), cp2); err != nil {
		t.Fatalf("publish cp2: %v", err)
	}
	err := anchor.Publish(context.Background(), cp1)
	if !errors.Is(err, ErrS3AnchorObjectExists) {
		t.Fatalf("overwrite error=%v want ErrS3AnchorObjectExists", err)
	}
	got, err := anchor.Latest(context.Background())
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if got.Seq != 2 || got.HeadHash != "hash-2" {
		t.Fatalf("latest=%+v want seq=2/hash-2", got)
	}
	if fake.retentionFor("audit-bucket", "hubbleops/checkpoints/00000000000000000001.json") != now.Add(7*24*time.Hour) {
		t.Fatalf("retention was not set in compliance window")
	}
}

func TestNewS3ObjectLockAnchorReadsEnvAndURLOverrides(t *testing.T) {
	t.Setenv("HUBBLEOPS_S3_ANCHOR_BUCKET", "env-bucket")
	t.Setenv("HUBBLEOPS_S3_ANCHOR_PREFIX", "env/checkpoints")
	t.Setenv("HUBBLEOPS_S3_ANCHOR_REGION", "us-east-1")
	t.Setenv("HUBBLEOPS_S3_ANCHOR_RETENTION_DAYS", "12")

	fromEnv, err := NewS3ObjectLockAnchor("")
	if err != nil {
		t.Fatalf("env anchor: %v", err)
	}
	if fromEnv.Bucket != "env-bucket" ||
		fromEnv.Prefix != "env/checkpoints" ||
		fromEnv.Region != "us-east-1" ||
		fromEnv.RetentionDays != 12 {
		t.Fatalf("env anchor config=%+v", fromEnv)
	}

	fromURL, err := NewS3ObjectLockAnchor("s3://url-bucket/url/checkpoints?region=us-west-2&retention_days=9&endpoint=http://127.0.0.1:4566&path_style=true")
	if err != nil {
		t.Fatalf("url anchor: %v", err)
	}
	if fromURL.Bucket != "url-bucket" ||
		fromURL.Prefix != "url/checkpoints" ||
		fromURL.Region != "us-west-2" ||
		fromURL.RetentionDays != 9 ||
		fromURL.Endpoint != "http://127.0.0.1:4566" ||
		!fromURL.ForcePathStyle {
		t.Fatalf("url anchor config=%+v", fromURL)
	}
}

func TestS3SigV4ClientPutCheckpointSendsObjectLockHeaders(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")

	var calls int
	var gotPath string
	var gotIfNoneMatch string
	var gotLockMode string
	var gotRetention string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		gotPath = r.URL.Path
		gotIfNoneMatch = r.Header.Get("If-None-Match")
		gotLockMode = r.Header.Get("x-amz-object-lock-mode")
		gotRetention = r.Header.Get("x-amz-object-lock-retain-until-date")
		if calls > 1 {
			http.Error(w, "already exists", http.StatusPreconditionFailed)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := &s3SigV4Client{
		region:         "us-east-1",
		endpoint:       srv.URL,
		forcePathStyle: true,
		httpClient:     srv.Client(),
	}
	retentionUntil := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	if err := client.PutCheckpoint(context.Background(), "audit-bucket", "checkpoints/00000000000000000001.json", []byte(`{"seq":1}`), retentionUntil); err != nil {
		t.Fatalf("put checkpoint: %v", err)
	}
	if gotPath != "/audit-bucket/checkpoints/00000000000000000001.json" {
		t.Fatalf("path=%q", gotPath)
	}
	if gotIfNoneMatch != "*" {
		t.Fatalf("If-None-Match=%q want *", gotIfNoneMatch)
	}
	if gotLockMode != "COMPLIANCE" {
		t.Fatalf("lock mode=%q want COMPLIANCE", gotLockMode)
	}
	if gotRetention != retentionUntil.Format(time.RFC3339) {
		t.Fatalf("retention=%q want %q", gotRetention, retentionUntil.Format(time.RFC3339))
	}

	err := client.PutCheckpoint(context.Background(), "audit-bucket", "checkpoints/00000000000000000001.json", []byte(`{"seq":1}`), retentionUntil)
	if !errors.Is(err, ErrS3AnchorObjectExists) {
		t.Fatalf("duplicate put error=%v want ErrS3AnchorObjectExists", err)
	}
}

type wormS3Fake struct {
	mu        sync.Mutex
	objects   map[string][]byte
	retention map[string]time.Time
}

func newWORMS3Fake() *wormS3Fake {
	return &wormS3Fake{
		objects:   map[string][]byte{},
		retention: map[string]time.Time{},
	}
}

func (f *wormS3Fake) PutCheckpoint(ctx context.Context, bucket, key string, body []byte, retentionUntil time.Time) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	id := bucket + "/" + key
	if _, ok := f.objects[id]; ok {
		return ErrS3AnchorObjectExists
	}
	f.objects[id] = append([]byte(nil), body...)
	f.retention[id] = retentionUntil
	return nil
}

func (f *wormS3Fake) ListCheckpoints(ctx context.Context, bucket, prefix string) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for id := range f.objects {
		keyBucket, key, _ := strings.Cut(id, "/")
		if keyBucket == bucket && (prefix == "" || strings.HasPrefix(key, prefix)) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys, nil
}

func (f *wormS3Fake) GetCheckpoint(ctx context.Context, bucket, key string) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	body, ok := f.objects[bucket+"/"+key]
	if !ok {
		return nil, errors.New("not found")
	}
	return append([]byte(nil), body...), nil
}

func (f *wormS3Fake) retentionFor(bucket, key string) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.retention[bucket+"/"+key]
}

var _ S3AnchorClient = (*wormS3Fake)(nil)
