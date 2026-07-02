package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type SlackNotifier struct {
	WebhookURL string
	Client     *http.Client
}

func (n SlackNotifier) NotifyApprovalRequested(ctx context.Context, rec Record) error {
	if strings.TrimSpace(n.WebhookURL) == "" {
		return nil
	}
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	body, err := json.Marshal(map[string]string{
		"text": fmt.Sprintf(
			"HubbleOps approval requested: %s decision=%s action=%s risk=%d approvers=%s",
			rec.ApprovalID,
			rec.DecisionID,
			rec.Action,
			rec.RiskScore,
			strings.Join(rec.RequiredApprovers, ","),
		),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned %s", resp.Status)
	}
	return nil
}
