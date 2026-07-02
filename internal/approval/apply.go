package approval

import (
	"strings"

	"github.com/hubbleops/hubbleops/internal/action"
)

func ApplyDecision(decision action.Decision, rec Record) action.Decision {
	switch rec.Status {
	case StatusApproved:
		decision.Decision = action.DecisionAllow
		decision.Reason = "approval granted by reviewer"
		decision.RequiredApprovers = nil
		decision.AllowedNextActions = []string{"continue"}
		decision.Approvals = approvalActors(rec)
		decision.Evidence = appendUnique(decision.Evidence,
			"approval_status=approved",
			"approval_id="+rec.ApprovalID,
			"reviewer_fingerprint="+rec.ReviewerFingerprint,
			"approval_source="+rec.ReviewerSource,
		)
		decision.RequiresReceipt = false
	case StatusRejected:
		decision.Decision = action.DecisionBlock
		decision.Reason = "approval rejected by reviewer"
		if decision.RiskScore < 90 {
			decision.RiskScore = 90
			decision.RiskClass = action.RiskClass(decision.RiskScore)
		}
		decision.RequiredApprovers = nil
		decision.AllowedNextActions = []string{"open_review"}
		decision.Approvals = approvalActors(rec)
		decision.Evidence = appendUnique(decision.Evidence,
			"approval_status=rejected",
			"approval_id="+rec.ApprovalID,
			"reviewer_fingerprint="+rec.ReviewerFingerprint,
			"approval_source="+rec.ReviewerSource,
		)
		decision.RequiresReceipt = true
	}
	return decision
}

func approvalActors(rec Record) []string {
	if strings.TrimSpace(rec.ReviewerFingerprint) != "" {
		return []string{rec.ReviewerFingerprint}
	}
	if strings.TrimSpace(rec.Reviewer) != "" {
		return []string{rec.Reviewer}
	}
	return nil
}

func appendUnique(base []string, values ...string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range append(append([]string{}, base...), values...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
