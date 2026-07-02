package approval

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hubbleops/hubbleops/internal/privacy"
)

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
)

var (
	ErrNotFound      = errors.New("approval not found")
	ErrInvalidReview = errors.New("approval review requires reviewer, source, and approved/rejected decision")
)

// GitHubCheck carries the repo coordinates needed to re-issue a PR check run when an
// approval is granted or rejected. These are repository coordinates (not user PII), so they
// are stored as-is after light validation rather than fingerprinted.
type GitHubCheck struct {
	InstallationID int64  `json:"installation_id,omitempty"`
	CheckRunID     int64  `json:"check_run_id,omitempty"`
	Owner          string `json:"owner,omitempty"`
	Repo           string `json:"repo,omitempty"`
	HeadSHA        string `json:"head_sha,omitempty"`
	CheckName      string `json:"check_name,omitempty"`
}

type Request struct {
	Project             string       `json:"project"`
	SessionID           string       `json:"session_id"`
	DecisionID          string       `json:"decision_id"`
	ReceiptID           string       `json:"receipt_id"`
	Action              string       `json:"action"`
	TargetFingerprint   string       `json:"target_fingerprint,omitempty"`
	RequiredApprovers   []string     `json:"required_approvers,omitempty"`
	Reason              string       `json:"reason,omitempty"`
	RiskScore           int          `json:"risk_score,omitempty"`
	RequestedBy         string       `json:"requested_by,omitempty"`
	Source              string       `json:"source,omitempty"`
	RequestedAt         time.Time    `json:"requested_at,omitempty"`
	NotificationURLHint string       `json:"notification_url_hint,omitempty"`
	GitHub              *GitHubCheck `json:"github,omitempty"`
}

type Record struct {
	ApprovalID          string       `json:"approval_id"`
	Status              string       `json:"status"`
	Project             string       `json:"project"`
	SessionID           string       `json:"session_id"`
	DecisionID          string       `json:"decision_id"`
	ReceiptID           string       `json:"receipt_id"`
	Action              string       `json:"action"`
	TargetFingerprint   string       `json:"target_fingerprint,omitempty"`
	RequiredApprovers   []string     `json:"required_approvers,omitempty"`
	Reason              string       `json:"reason,omitempty"`
	RiskScore           int          `json:"risk_score,omitempty"`
	RequestedBy         string       `json:"requested_by,omitempty"`
	Source              string       `json:"source"`
	RequestedAt         time.Time    `json:"requested_at"`
	ReviewedAt          time.Time    `json:"reviewed_at,omitempty"`
	Reviewer            string       `json:"reviewer,omitempty"`
	ReviewerFingerprint string       `json:"reviewer_fingerprint,omitempty"`
	ReviewerSource      string       `json:"reviewer_source,omitempty"`
	ReviewCommentHash   string       `json:"review_comment_hash,omitempty"`
	GitHub              *GitHubCheck `json:"github,omitempty"`
}

type ReviewInput struct {
	ApprovalID string `json:"approval_id,omitempty"`
	DecisionID string `json:"decision_id,omitempty"`
	Reviewer   string `json:"reviewer"`
	Source     string `json:"source"`
	Decision   string `json:"decision"`
	Comment    string `json:"comment,omitempty"`
}

type Store interface {
	Request(ctx context.Context, req Request) (Record, bool, error)
	Get(ctx context.Context, approvalID string) (Record, error)
	GetByDecision(ctx context.Context, decisionID string) (Record, error)
	Review(ctx context.Context, input ReviewInput) (Record, error)
	SetGitHubCheckRunID(ctx context.Context, approvalID string, checkRunID int64) (Record, error)
}

type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (s *FileStore) Request(ctx context.Context, req Request) (Record, bool, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, false, err
	}
	if err := validateRequest(req); err != nil {
		return Record{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	state, err := s.load()
	if err != nil {
		return Record{}, false, err
	}
	id := approvalID(req.DecisionID)
	if existing, ok := state.Approvals[id]; ok {
		return existing, false, nil
	}
	now := req.RequestedAt.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	rec := Record{
		ApprovalID:        id,
		Status:            StatusPending,
		Project:           safeIdentifier(req.Project),
		SessionID:         safeIdentifier(req.SessionID),
		DecisionID:        safeIdentifier(req.DecisionID),
		ReceiptID:         safeIdentifier(req.ReceiptID),
		Action:            safeIdentifier(req.Action),
		TargetFingerprint: safeFingerprint(req.TargetFingerprint),
		RequiredApprovers: safeIdentifiers(req.RequiredApprovers),
		Reason:            safeText(req.Reason),
		RiskScore:         req.RiskScore,
		RequestedBy:       safeIdentifier(req.RequestedBy),
		Source:            safeSource(firstNonEmpty(req.Source, "api")),
		RequestedAt:       now,
		GitHub:            sanitizeGitHubCheck(req.GitHub),
	}
	state.Approvals[id] = rec
	state.Decisions[rec.DecisionID] = id
	if err := s.save(state); err != nil {
		return Record{}, false, err
	}
	return rec, true, nil
}

func (s *FileStore) Get(ctx context.Context, approvalID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.load()
	if err != nil {
		return Record{}, err
	}
	rec, ok := state.Approvals[strings.TrimSpace(approvalID)]
	if !ok {
		return Record{}, ErrNotFound
	}
	return rec, nil
}

func (s *FileStore) GetByDecision(ctx context.Context, decisionID string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.load()
	if err != nil {
		return Record{}, err
	}
	decisionID = safeIdentifier(decisionID)
	id, ok := state.Decisions[decisionID]
	if !ok {
		return Record{}, ErrNotFound
	}
	rec, ok := state.Approvals[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	return rec, nil
}

func (s *FileStore) Review(ctx context.Context, input ReviewInput) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	status := normalizeReviewDecision(input.Decision)
	if strings.TrimSpace(input.Reviewer) == "" || strings.TrimSpace(input.Source) == "" || status == "" {
		return Record{}, ErrInvalidReview
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.load()
	if err != nil {
		return Record{}, err
	}
	id := strings.TrimSpace(input.ApprovalID)
	if id == "" && strings.TrimSpace(input.DecisionID) != "" {
		id = state.Decisions[safeIdentifier(input.DecisionID)]
	}
	rec, ok := state.Approvals[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if rec.Status != StatusPending {
		return rec, nil
	}
	rec.Status = status
	rec.Reviewer = safeIdentifier(input.Reviewer)
	rec.ReviewerFingerprint = privacy.FingerprintString(input.Reviewer)
	rec.ReviewerSource = safeSource(input.Source)
	rec.ReviewedAt = time.Now().UTC()
	if strings.TrimSpace(input.Comment) != "" {
		rec.ReviewCommentHash = privacy.FingerprintString(input.Comment)
	}
	state.Approvals[id] = rec
	state.Decisions[rec.DecisionID] = id
	if err := s.save(state); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func (s *FileStore) SetGitHubCheckRunID(ctx context.Context, approvalID string, checkRunID int64) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	if checkRunID <= 0 {
		return Record{}, fmt.Errorf("check_run_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.load()
	if err != nil {
		return Record{}, err
	}
	id := strings.TrimSpace(approvalID)
	rec, ok := state.Approvals[id]
	if !ok {
		return Record{}, ErrNotFound
	}
	if rec.GitHub == nil {
		return Record{}, fmt.Errorf("approval has no github check metadata")
	}
	rec.GitHub.CheckRunID = checkRunID
	state.Approvals[id] = rec
	state.Decisions[rec.DecisionID] = id
	if err := s.save(state); err != nil {
		return Record{}, err
	}
	return rec, nil
}

type fileState struct {
	Approvals map[string]Record `json:"approvals"`
	Decisions map[string]string `json:"decisions"`
}

func (s *FileStore) load() (fileState, error) {
	if strings.TrimSpace(s.path) == "" {
		return fileState{}, fmt.Errorf("approval store path is required")
	}
	data, err := os.ReadFile(filepath.Clean(s.path))
	if errors.Is(err, os.ErrNotExist) {
		return fileState{Approvals: map[string]Record{}, Decisions: map[string]string{}}, nil
	}
	if err != nil {
		return fileState{}, err
	}
	state := fileState{Approvals: map[string]Record{}, Decisions: map[string]string{}}
	if len(data) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return fileState{}, err
	}
	if state.Approvals == nil {
		state.Approvals = map[string]Record{}
	}
	if state.Decisions == nil {
		state.Decisions = map[string]string{}
	}
	for id, rec := range state.Approvals {
		if rec.DecisionID != "" {
			state.Decisions[rec.DecisionID] = id
		}
	}
	return state, nil
}

func (s *FileStore) save(state fileState) error {
	path := filepath.Clean(s.path)
	if strings.TrimSpace(path) == "" || path == "." {
		return fmt.Errorf("approval store path is required")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".approval-store-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Chmod(path, 0600)
}

func validateRequest(req Request) error {
	missing := []string{}
	if strings.TrimSpace(req.Project) == "" {
		missing = append(missing, "project")
	}
	if strings.TrimSpace(req.SessionID) == "" {
		missing = append(missing, "session_id")
	}
	if strings.TrimSpace(req.DecisionID) == "" {
		missing = append(missing, "decision_id")
	}
	if strings.TrimSpace(req.ReceiptID) == "" {
		missing = append(missing, "receipt_id")
	}
	if strings.TrimSpace(req.Action) == "" {
		missing = append(missing, "action")
	}
	if len(missing) > 0 {
		return fmt.Errorf("approval request missing %s", strings.Join(missing, ", "))
	}
	return nil
}

func approvalID(decisionID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(decisionID)))
	return fmt.Sprintf("appr_%x", sum[:12])
}

func normalizeReviewDecision(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "approve", StatusApproved:
		return StatusApproved
	case "reject", "deny", StatusRejected:
		return StatusRejected
	default:
		return ""
	}
}

func safeIdentifiers(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		safe := safeIdentifier(value)
		if safe == "" {
			continue
		}
		if _, ok := seen[safe]; ok {
			continue
		}
		seen[safe] = struct{}{}
		out = append(out, safe)
	}
	return out
}

func safeIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) > 160 || privacy.ContainsSensitiveText(value) || !hasOnlySafeIdentifierChars(value) || hasUnsafeAtSign(value) {
		return fingerprintMarker(value)
	}
	return value
}

func safeSource(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "api"
	}
	return safeIdentifier(value)
}

func safeText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) > 512 || privacy.ContainsSensitiveText(value) || containsLineBreakOrControl(value) {
		return fingerprintMarker(value)
	}
	return value
}

func safeFingerprint(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if privacy.IsFingerprint(value) {
		return value
	}
	return privacy.FingerprintString(value)
}

func hasOnlySafeIdentifierChars(value string) bool {
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == ':' || r == '/' || r == '#' || r == '-' || r == '@':
		default:
			return false
		}
	}
	return true
}

func hasUnsafeAtSign(value string) bool {
	return strings.IndexByte(value, '@') > 0
}

func containsLineBreakOrControl(value string) bool {
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func fingerprintMarker(value string) string {
	return "fingerprint:" + privacy.FingerprintString(value)
}

// sanitizeGitHubCheck validates the repo coordinates. Owner/repo/sha must be present and
// well-formed, or the whole struct is dropped (so we never store junk we'd later call the
// GitHub API with).
func sanitizeGitHubCheck(c *GitHubCheck) *GitHubCheck {
	if c == nil {
		return nil
	}
	owner, repo, sha := safeCoordinate(c.Owner), safeCoordinate(c.Repo), safeCoordinate(c.HeadSHA)
	if owner == "" || repo == "" || sha == "" {
		return nil
	}
	name := strings.TrimSpace(c.CheckName)
	if name == "" || len(name) > 120 || containsLineBreakOrControl(name) {
		name = "HubbleOps Action Firewall"
	}
	return &GitHubCheck{InstallationID: c.InstallationID, CheckRunID: c.CheckRunID, Owner: owner, Repo: repo, HeadSHA: sha, CheckName: name}
}

func safeCoordinate(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 100 {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-' || r == '/':
		default:
			return ""
		}
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
