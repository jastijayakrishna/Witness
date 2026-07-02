package githubapp

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVerifyWebhook(t *testing.T) {
	body := []byte(`{"zen":"keep it logically safe"}`)
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !VerifyWebhook("secret", body, sig) {
		t.Fatalf("valid signature rejected")
	}
	if VerifyWebhook("secret", body, sig[:len(sig)-2]+"00") {
		t.Fatalf("tampered signature accepted")
	}
}

func TestAppJWTSignsRS256(t *testing.T) {
	keyPEM := testPrivateKeyPEM(t)
	token, err := Client{AppID: "12345", PrivateKey: keyPEM}.AppJWT(time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("app jwt: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt parts=%d want 3", len(parts))
	}
	var header map[string]string
	if err := decodeJWTPart(parts[0], &header); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if header["alg"] != "RS256" {
		t.Fatalf("alg=%q want RS256", header["alg"])
	}
	var claims map[string]any
	if err := decodeJWTPart(parts[1], &claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	if claims["iss"] != "12345" {
		t.Fatalf("issuer=%v want app id", claims["iss"])
	}
}

func TestClientListsFilesGetsCodeownersAndCreatesCheck(t *testing.T) {
	var sawCheck bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/acme/checkout/pulls/842/files":
			_, _ = w.Write([]byte(`[{"filename":"infra/main.tf","status":"modified"}]`))
		case r.URL.Path == "/repos/acme/checkout/contents/.github/CODEOWNERS":
			_, _ = w.Write([]byte(`{"encoding":"base64","content":"L2luZnJhLyBAb3JnL3BsYXRmb3JtCg=="}`))
		case r.URL.Path == "/repos/acme/checkout/check-runs" && r.Method == http.MethodPost:
			sawCheck = true
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode check payload: %v", err)
			}
			if payload["conclusion"] != "action_required" {
				t.Fatalf("conclusion=%v want action_required", payload["conclusion"])
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":1234}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, HTTPClient: server.Client()}
	files, err := client.ListPullRequestFiles(context.Background(), "token", "acme", "checkout", 842)
	if err != nil {
		t.Fatalf("list files: %v", err)
	}
	if len(files) != 1 || files[0].Filename != "infra/main.tf" {
		t.Fatalf("files=%+v", files)
	}
	codeowners, err := client.GetCodeOwners(context.Background(), "token", "acme", "checkout", "main")
	if err != nil {
		t.Fatalf("codeowners: %v", err)
	}
	if !strings.Contains(codeowners, "@org/platform") {
		t.Fatalf("codeowners=%q", codeowners)
	}
	checkRunID, err := client.CreateCheckRun(context.Background(), "token", CheckRun{
		Owner:      "acme",
		Repo:       "checkout",
		HeadSHA:    "abc123",
		Conclusion: "action_required",
		Title:      "Review required",
		Summary:    "decision=require_approval",
	})
	if err != nil {
		t.Fatalf("create check: %v", err)
	}
	if checkRunID != 1234 {
		t.Fatalf("checkRunID=%d want 1234", checkRunID)
	}
	if !sawCheck {
		t.Fatalf("check run was not created")
	}
}

func TestClientGetsTerraformPlanArtifact(t *testing.T) {
	plan := `{"resource_changes":[{"address":"aws_db_instance.prod","type":"aws_db_instance","change":{"actions":["delete"]}}]}`
	zipBody := terraformPlanZip(t, "terraform-plan.json", plan)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/acme/checkout/actions/artifacts":
			_, _ = w.Write([]byte(`{"artifacts":[{"id":77,"name":"hubbleops-terraform-plan-pr-42-deadbeef","expired":false}]}`))
		case r.URL.Path == "/repos/acme/checkout/actions/artifacts/77/zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, HTTPClient: server.Client()}
	got, ok, err := client.GetTerraformPlan(context.Background(), "token", "acme", "checkout", 42, "deadbeef")
	if err != nil {
		t.Fatalf("get terraform plan: %v", err)
	}
	if !ok {
		t.Fatalf("terraform plan artifact not found")
	}
	if got != plan {
		t.Fatalf("plan=%q want %q", got, plan)
	}
}

func TestConclusionExactMapping(t *testing.T) {
	for _, tc := range []struct {
		decision string
		want     string
	}{
		{decision: "allow", want: "success"},
		{decision: "block", want: "failure"},
		{decision: "require_approval", want: "action_required"},
		{decision: "unknown", want: "failure"},
		{decision: "", want: "failure"},
	} {
		if got := Conclusion(tc.decision); got != tc.want {
			t.Fatalf("Conclusion(%q)=%q want %q", tc.decision, got, tc.want)
		}
	}
}

func TestClientCreateCheckRunEmitsExactConclusions(t *testing.T) {
	want := []string{"success", "failure", "action_required", "failure"}
	var got []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/checkout/check-runs" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode check payload: %v", err)
		}
		got = append(got, payload["conclusion"].(string))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":99}`))
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, HTTPClient: server.Client()}
	for _, decision := range []string{"allow", "block", "require_approval", "unexpected"} {
		if _, err := client.CreateCheckRun(context.Background(), "token", CheckRun{
			Owner:      "acme",
			Repo:       "checkout",
			HeadSHA:    "abc123",
			Conclusion: Conclusion(decision),
			Title:      "HubbleOps: " + decision,
			Summary:    "decision=" + decision,
		}); err != nil {
			t.Fatalf("create check for %s: %v", decision, err)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("conclusions=%v want %v", got, want)
	}
}

func TestClientPatchCheckRun(t *testing.T) {
	var sawPatch bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/checkout/check-runs/1234" || r.Method != http.MethodPatch {
			http.NotFound(w, r)
			return
		}
		sawPatch = true
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode patch payload: %v", err)
		}
		if payload["conclusion"] != "success" {
			t.Fatalf("patched conclusion=%v want success", payload["conclusion"])
		}
		output := payload["output"].(map[string]any)
		if !strings.Contains(output["summary"].(string), "post_approval_receipt_id=dec_123") {
			t.Fatalf("patch summary missing receipt id: %v", output["summary"])
		}
		_, _ = w.Write([]byte(`{"id":1234}`))
	}))
	defer server.Close()

	client := Client{BaseURL: server.URL, HTTPClient: server.Client()}
	if err := client.PatchCheckRun(context.Background(), "token", CheckRun{
		ID:         1234,
		Owner:      "acme",
		Repo:       "checkout",
		Conclusion: "success",
		Title:      "HubbleOps: allow",
		Summary:    "post_approval_receipt_id=dec_123",
	}); err != nil {
		t.Fatalf("patch check: %v", err)
	}
	if !sawPatch {
		t.Fatalf("check run was not patched")
	}
}

func terraformPlanZip(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create(name)
	if err != nil {
		t.Fatalf("create zip entry: %v", err)
	}
	if _, err := f.Write([]byte(body)); err != nil {
		t.Fatalf("write zip entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

func testPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func decodeJWTPart(part string, out any) error {
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}
