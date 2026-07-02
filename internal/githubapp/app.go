package githubapp

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	pregithub "github.com/hubbleops/hubbleops/internal/preflight/github"
)

var errContentNotFound = errors.New("github content not found")

const (
	maxTerraformPlanArtifactBytes = 10 << 20
	maxTerraformPlanFileBytes     = 8 << 20
)

type Client struct {
	AppID      string
	PrivateKey []byte
	BaseURL    string
	HTTPClient *http.Client
}

type CheckRun struct {
	ID         int64
	Owner      string
	Repo       string
	HeadSHA    string
	Name       string
	Conclusion string
	Title      string
	Summary    string
}

func VerifyWebhook(secret string, body []byte, signature string) bool {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return true
	}
	const prefix = "sha256="
	signature = strings.TrimSpace(signature)
	if !strings.HasPrefix(signature, prefix) {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(signature, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	want := mac.Sum(nil)
	return hmac.Equal(got, want)
}

func (c Client) AppJWT(now time.Time) (string, error) {
	if strings.TrimSpace(c.AppID) == "" {
		return "", fmt.Errorf("github app id is required")
	}
	key, err := ParsePrivateKey(c.PrivateKey)
	if err != nil {
		return "", err
	}
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	claims := map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": c.AppID,
	}
	headerBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func ParsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(bytes.TrimSpace(data))
	if block == nil {
		return nil, fmt.Errorf("parse github app private key: PEM block not found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse github app private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parse github app private key: expected RSA key")
	}
	return key, nil
}

func (c Client) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	if installationID <= 0 {
		return "", fmt.Errorf("installation id is required")
	}
	jwt, err := c.AppJWT(time.Now().UTC())
	if err != nil {
		return "", err
	}
	path := fmt.Sprintf("/app/installations/%d/access_tokens", installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(path), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	res, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return "", fmt.Errorf("github installation token: status %d: %s", res.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.Token) == "" {
		return "", fmt.Errorf("github installation token response missing token")
	}
	return out.Token, nil
}

func (c Client) ListPullRequestFiles(ctx context.Context, token, owner, repo string, number int) ([]pregithub.ChangedFile, error) {
	var out []pregithub.ChangedFile
	for page := 1; page <= 100; page++ {
		path := fmt.Sprintf("/repos/%s/%s/pulls/%d/files?per_page=100&page=%d", url.PathEscape(owner), url.PathEscape(repo), number, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(path), nil)
		if err != nil {
			return nil, err
		}
		addGitHubHeaders(req, token)
		res, err := c.httpClient().Do(req)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		closeErr := res.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return nil, fmt.Errorf("github list pull files: status %d: %s", res.StatusCode, strings.TrimSpace(string(data)))
		}
		var pageFiles []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
		}
		if err := json.Unmarshal(data, &pageFiles); err != nil {
			return nil, err
		}
		for _, file := range pageFiles {
			out = append(out, pregithub.ChangedFile{Filename: file.Filename, Status: file.Status})
		}
		if len(pageFiles) < 100 {
			break
		}
	}
	return out, nil
}

// GetFileContent returns the decoded contents of a file at ref, or "" if the file does
// not exist (e.g. it was removed in the PR). Used to run content detectors on PR blobs.
func (c Client) GetFileContent(ctx context.Context, token, owner, repo, path, ref string) (string, error) {
	body, err := c.getContents(ctx, token, owner, repo, path, ref)
	if errors.Is(err, errContentNotFound) {
		return "", nil
	}
	return body, err
}

func (c Client) GetCodeOwners(ctx context.Context, token, owner, repo, ref string) (string, error) {
	for _, path := range []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"} {
		body, err := c.getContents(ctx, token, owner, repo, path, ref)
		if err == nil {
			return body, nil
		}
		if !errors.Is(err, errContentNotFound) {
			return "", err
		}
	}
	return "", nil
}

// GetTerraformPlan fetches a PR-scoped terraform show -json artifact. The GitHub
// required check consumes this server-side, so deleting the CLI step cannot silently skip
// the strong Terraform detector. Artifacts are expected to be named with the PR number and
// ideally the head SHA, for example:
//
//	hubbleops-terraform-plan-pr-42-deadbeef...
//
// The zip should contain terraform-plan.json or plan.json.
func (c Client) GetTerraformPlan(ctx context.Context, token, owner, repo string, number int, headSHA string) (string, bool, error) {
	if number <= 0 {
		return "", false, nil
	}
	artifacts, err := c.listArtifacts(ctx, token, owner, repo)
	if err != nil {
		return "", false, err
	}
	candidates := terraformPlanArtifactNames(number, headSHA)
	for _, candidate := range candidates {
		for _, artifact := range artifacts {
			if artifact.Expired || !strings.EqualFold(strings.TrimSpace(artifact.Name), candidate) {
				continue
			}
			body, ok, err := c.downloadTerraformPlanArtifact(ctx, token, owner, repo, artifact)
			if err != nil {
				return "", false, err
			}
			if ok {
				return body, true, nil
			}
		}
	}
	return "", false, nil
}

func (c Client) CreateCheckRun(ctx context.Context, token string, run CheckRun) (int64, error) {
	if strings.TrimSpace(run.HeadSHA) == "" {
		return 0, fmt.Errorf("check run head sha is required")
	}
	payload := map[string]any{
		"name":       firstNonEmpty(run.Name, "HubbleOps Action Firewall"),
		"head_sha":   run.HeadSHA,
		"status":     "completed",
		"conclusion": run.Conclusion,
		"output": map[string]string{
			"title":   run.Title,
			"summary": run.Summary,
		},
	}
	data, _ := json.Marshal(payload)
	path := fmt.Sprintf("/repos/%s/%s/check-runs", url.PathEscape(run.Owner), url.PathEscape(run.Repo))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(path), bytes.NewReader(data))
	if err != nil {
		return 0, err
	}
	addGitHubHeaders(req, token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.httpClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return 0, fmt.Errorf("github create check run: status %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			return 0, fmt.Errorf("parse github create check run response: %w", err)
		}
	}
	return out.ID, nil
}

func (c Client) PatchCheckRun(ctx context.Context, token string, run CheckRun) error {
	if run.ID <= 0 {
		return fmt.Errorf("check run id is required")
	}
	payload := map[string]any{
		"name":       firstNonEmpty(run.Name, "HubbleOps Action Firewall"),
		"status":     "completed",
		"conclusion": run.Conclusion,
		"output": map[string]string{
			"title":   run.Title,
			"summary": run.Summary,
		},
	}
	data, _ := json.Marshal(payload)
	path := fmt.Sprintf("/repos/%s/%s/check-runs/%d", url.PathEscape(run.Owner), url.PathEscape(run.Repo), run.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.endpoint(path), bytes.NewReader(data))
	if err != nil {
		return err
	}
	addGitHubHeaders(req, token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return fmt.Errorf("github patch check run: status %d: %s", res.StatusCode, strings.TrimSpace(string(data)))
	}
	return nil
}

func (c Client) getContents(ctx context.Context, token, owner, repo, path, ref string) (string, error) {
	query := ""
	if strings.TrimSpace(ref) != "" {
		query = "?ref=" + url.QueryEscape(ref)
	}
	endpoint := fmt.Sprintf("/repos/%s/%s/contents/%s%s", url.PathEscape(owner), url.PathEscape(repo), path, query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(endpoint), nil)
	if err != nil {
		return "", err
	}
	addGitHubHeaders(req, token)
	res, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotFound {
		return "", errContentNotFound
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("github contents %s: status %d", path, res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var payload struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(data, &payload); err == nil && strings.EqualFold(payload.Encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(payload.Content, "\n", ""))
		if err == nil {
			return string(decoded), nil
		}
	}
	return string(data), nil
}

type githubArtifact struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Expired            bool   `json:"expired"`
	ArchiveDownloadURL string `json:"archive_download_url"`
}

func (c Client) listArtifacts(ctx context.Context, token, owner, repo string) ([]githubArtifact, error) {
	var out []githubArtifact
	for page := 1; page <= 10; page++ {
		endpoint := fmt.Sprintf("/repos/%s/%s/actions/artifacts?per_page=100&page=%d", url.PathEscape(owner), url.PathEscape(repo), page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(endpoint), nil)
		if err != nil {
			return nil, err
		}
		addGitHubHeaders(req, token)
		res, err := c.httpClient().Do(req)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		closeErr := res.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return nil, fmt.Errorf("github list artifacts: status %d: %s", res.StatusCode, strings.TrimSpace(string(data)))
		}
		var pageArtifacts struct {
			Artifacts []githubArtifact `json:"artifacts"`
		}
		if err := json.Unmarshal(data, &pageArtifacts); err != nil {
			return nil, err
		}
		out = append(out, pageArtifacts.Artifacts...)
		if len(pageArtifacts.Artifacts) < 100 {
			break
		}
	}
	return out, nil
}

func (c Client) downloadTerraformPlanArtifact(ctx context.Context, token, owner, repo string, artifact githubArtifact) (string, bool, error) {
	endpoint := strings.TrimSpace(artifact.ArchiveDownloadURL)
	if endpoint == "" {
		endpoint = fmt.Sprintf("/repos/%s/%s/actions/artifacts/%d/zip", url.PathEscape(owner), url.PathEscape(repo), artifact.ID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(endpoint), nil)
	if err != nil {
		return "", false, err
	}
	addGitHubHeaders(req, token)
	req.Header.Set("Accept", "application/zip")
	res, err := c.httpClient().Do(req)
	if err != nil {
		return "", false, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
		return "", false, fmt.Errorf("github download terraform plan artifact: status %d: %s", res.StatusCode, strings.TrimSpace(string(data)))
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxTerraformPlanArtifactBytes+1))
	if err != nil {
		return "", false, err
	}
	if len(data) > maxTerraformPlanArtifactBytes {
		return "", false, fmt.Errorf("terraform plan artifact exceeds %d bytes", maxTerraformPlanArtifactBytes)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", false, fmt.Errorf("read terraform plan artifact zip: %w", err)
	}
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || !terraformPlanFileName(file.Name) {
			continue
		}
		body, err := readZipFileLimited(file, maxTerraformPlanFileBytes)
		if err != nil {
			return "", false, err
		}
		return body, true, nil
	}
	return "", false, nil
}

func terraformPlanArtifactNames(number int, headSHA string) []string {
	rawSHA := strings.ToLower(strings.TrimSpace(headSHA))
	shortSHA := rawSHA
	if len(shortSHA) > 12 {
		shortSHA = shortSHA[:12]
	}
	base := fmt.Sprintf("hubbleops-terraform-plan-pr-%d", number)
	names := []string{}
	if rawSHA != "" {
		names = append(names, base+"-"+rawSHA)
	}
	if shortSHA != "" && shortSHA != rawSHA {
		names = append(names, base+"-"+shortSHA)
	}
	names = append(names,
		base,
		fmt.Sprintf("terraform-plan-pr-%d", number),
		"terraform-plan",
	)
	return names
}

func terraformPlanFileName(name string) bool {
	base := strings.ToLower(path.Base(strings.TrimSpace(name)))
	return base == "terraform-plan.json" || base == "plan.json" || strings.HasSuffix(base, ".tfplan.json")
}

func readZipFileLimited(file *zip.File, limit int64) (string, error) {
	rc, err := file.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", fmt.Errorf("terraform plan file %s exceeds %d bytes", file.Name, limit)
	}
	return string(data), nil
}

func (c Client) endpoint(path string) string {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://api.github.com"
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return base + "/" + strings.TrimLeft(path, "/")
}

func (c Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func addGitHubHeaders(req *http.Request, token string) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
}

func Conclusion(decision string) string {
	switch decision {
	case "allow":
		return "success"
	case "require_approval":
		return "action_required"
	case "block":
		return "failure"
	default:
		return "failure"
	}
}

func Summary(decision, reason string, riskScore int, receiptID string) string {
	var b strings.Builder
	b.WriteString("decision=")
	b.WriteString(decision)
	b.WriteString(" risk_score=")
	b.WriteString(strconv.Itoa(riskScore))
	if receiptID != "" {
		b.WriteString(" receipt_id=")
		b.WriteString(receiptID)
	}
	if reason != "" {
		b.WriteString("\n\n")
		b.WriteString(reason)
	}
	return b.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
