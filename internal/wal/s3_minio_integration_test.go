//go:build integration && docker
// +build integration,docker

package wal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMinIOS3ObjectLockAnchorSigV4AndWORM(t *testing.T) {
	endpoint, bucket, region := minioIntegrationConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	anchor := &S3ObjectLockAnchor{
		Bucket:         bucket,
		Prefix:         minioIntegrationPrefix(t),
		Region:         region,
		RetentionDays:  1,
		Endpoint:       endpoint,
		ForcePathStyle: true,
		Now:            func() time.Time { return now },
	}
	client := &s3SigV4Client{
		region:         region,
		endpoint:       endpoint,
		forcePathStyle: true,
		httpClient:     &http.Client{Timeout: 15 * time.Second},
	}

	for seq := uint64(1); seq <= 3; seq++ {
		cp := Checkpoint{
			Seq:      seq,
			HeadHash: fmt.Sprintf("head-%d", seq),
			Count:    seq,
			SignedAt: now,
		}
		if err := anchor.Publish(ctx, cp); err != nil {
			t.Fatalf("publish checkpoint %d through real s3SigV4Client: %v", seq, err)
		}
	}

	keys, err := client.ListCheckpoints(ctx, bucket, anchor.keyPrefix())
	if err != nil {
		t.Fatalf("list checkpoints through real s3SigV4Client: %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("list checkpoints count=%d keys=%v, want 3", len(keys), keys)
	}
	for i, key := range keys {
		want := anchor.checkpointKey(uint64(i + 1))
		if key != want {
			t.Fatalf("key[%d]=%q want %q", i, key, want)
		}
	}

	latest, err := anchor.Latest(ctx)
	if err != nil {
		t.Fatalf("latest checkpoint through real s3SigV4Client: %v", err)
	}
	if latest.Seq != 3 || latest.HeadHash != "head-3" {
		t.Fatalf("latest=%+v, want seq=3/head-3", latest)
	}

	err = anchor.Publish(ctx, Checkpoint{Seq: 2, HeadHash: "attacker", Count: 2, SignedAt: now})
	if !errors.Is(err, ErrS3AnchorObjectExists) {
		t.Fatalf("duplicate seq-2 publish error=%v, want ErrS3AnchorObjectExists", err)
	}

	status, body, err := minioIntegrationDeleteObject(ctx, client, bucket, anchor.checkpointKey(2))
	if err != nil {
		t.Fatalf("delete seq-2 checkpoint: %v", err)
	}
	if status >= 200 && status < 300 {
		t.Fatalf("delete seq-2 checkpoint unexpectedly succeeded with status=%d body=%s", status, body)
	}
	if status != http.StatusForbidden && !strings.Contains(strings.ToLower(body), "accessdenied") && !strings.Contains(strings.ToLower(body), "objectlock") {
		t.Fatalf("delete seq-2 checkpoint status=%d body=%s, want Object Lock/access denied failure", status, body)
	}
}

func minioIntegrationConfig(t *testing.T) (endpoint, bucket, region string) {
	t.Helper()
	endpoint = strings.TrimSpace(os.Getenv("HUBBLEOPS_INTEGRATION_S3_ENDPOINT"))
	bucket = strings.TrimSpace(os.Getenv("HUBBLEOPS_INTEGRATION_S3_BUCKET"))
	region = strings.TrimSpace(os.Getenv("HUBBLEOPS_INTEGRATION_S3_REGION"))
	if region == "" {
		region = strings.TrimSpace(os.Getenv("AWS_REGION"))
	}
	if region == "" {
		region = "us-east-1"
	}
	if endpoint == "" || bucket == "" || strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID")) == "" || strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY")) == "" {
		t.Skip("MinIO integration env not configured; run deploy/minio-objectlock-compose.yml and set HUBBLEOPS_INTEGRATION_S3_ENDPOINT, HUBBLEOPS_INTEGRATION_S3_BUCKET, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
	}
	return endpoint, bucket, region
}

func minioIntegrationPrefix(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "\\", "-", " ", "-", ":", "-").Replace(t.Name())
	return fmt.Sprintf("integration/%s/%d", strings.ToLower(name), time.Now().UnixNano())
}

func minioIntegrationDeleteObject(ctx context.Context, client *s3SigV4Client, bucket, key string) (int, string, error) {
	req, err := client.newRequest(ctx, http.MethodDelete, bucket, key, nil, nil)
	if err != nil {
		return 0, "", err
	}
	if err := client.sign(req, nil); err != nil {
		return 0, "", err
	}
	resp, err := client.do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, strings.TrimSpace(string(body)), nil
}
