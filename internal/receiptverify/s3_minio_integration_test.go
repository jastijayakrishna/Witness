//go:build integration && docker
// +build integration,docker

package receiptverify

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hubbleops/hubbleops/internal/receipts"
	"github.com/hubbleops/hubbleops/internal/wal"
)

func TestMinIOS3AnchorDetectsTruncatedWALWithPublicKeyVerifier(t *testing.T) {
	endpoint, bucket, region := minioReceiptVerifyConfig(t)
	now := time.Date(2026, 7, 2, 13, 0, 0, 0, time.UTC)
	anchor := &wal.S3ObjectLockAnchor{
		Bucket:         bucket,
		Prefix:         minioReceiptVerifyPrefix(t),
		Region:         region,
		RetentionDays:  1,
		Endpoint:       endpoint,
		ForcePathStyle: true,
		Now:            func() time.Time { return now },
	}
	signer := receipts.NewSigner("minio-kms-public-path", []byte("minio-integration-receipt-secret"))

	walDir := t.TempDir()
	writer, err := wal.NewWriterWithOptions(walDir, wal.WriterOptions{
		SyncMode:         wal.SyncModeSync,
		Anchor:           anchor,
		CheckpointSigner: signer.SignCheckpoint,
		CheckpointEveryN: 1000,
	})
	if err != nil {
		t.Fatalf("new writer: %v", err)
	}
	for i := 1; i <= 4; i++ {
		rec := wal.Record{
			Project:        "project-a",
			Provider:       "_preflight",
			Model:          "preflight",
			StatusCode:     200,
			SessionID:      "session-a",
			Actor:          "agent:integration",
			DecisionID:     fmt.Sprintf("decision-%d", i),
			Decision:       "allow",
			Action:         "deploy.release",
			PolicyVersion:  "s3-minio-integration",
			DecisionReason: "integration test",
		}
		if err := writer.WriteSigned(rec, signer.SignRecord); err != nil {
			t.Fatalf("write signed record %d: %v", i, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer and publish S3 checkpoint: %v", err)
	}

	records := readS3AnchorWALRecords(t, walDir)
	if len(records) != 4 {
		t.Fatalf("records=%d want 4", len(records))
	}
	report := VerifyWithOptions(records[:3], Options{
		ReceiptPublicKey:  signer.PublicKeyBase64(),
		RequireSignatures: true,
		Anchor:            anchor,
	})
	if report.Verified {
		t.Fatalf("truncated WAL verified unexpectedly: %+v", report)
	}
	if report.AnchorMismatches == 0 {
		t.Fatalf("report=%+v, want anchor mismatch", report)
	}
	if !strings.Contains(report.Recommendation, "truncation detected: anchored seq=4, wal max seq=3") {
		t.Fatalf("recommendation=%q", report.Recommendation)
	}
}

func minioReceiptVerifyConfig(t *testing.T) (endpoint, bucket, region string) {
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

func minioReceiptVerifyPrefix(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "\\", "-", " ", "-", ":", "-").Replace(t.Name())
	return fmt.Sprintf("integration/%s/%d", strings.ToLower(name), time.Now().UnixNano())
}
