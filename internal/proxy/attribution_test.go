package proxy

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestResolveProject_XProjectHeader(t *testing.T) {
	r, _ := http.NewRequest("POST", "/openai/v1/chat/completions", nil)
	r.Header.Set("X-Project", "my-cool-project")
	r.Header.Set("Authorization", "Bearer sk-12345")

	project := ResolveProject(r)
	if project != "my-cool-project" {
		t.Errorf("project = %q, want %q", project, "my-cool-project")
	}
}

func TestResolveProject_AuthorizationFallback(t *testing.T) {
	r, _ := http.NewRequest("POST", "/openai/v1/chat/completions", nil)
	r.Header.Set("Authorization", "Bearer sk-test-key-12345")

	project := ResolveProject(r)

	// Verify it's a SHA256 hash prefix
	if !strings.HasPrefix(project, "key:") {
		t.Fatalf("project = %q, expected key: prefix", project)
	}

	// Verify the hash is deterministic
	hash := sha256.Sum256([]byte("Bearer sk-test-key-12345"))
	expected := fmt.Sprintf("key:%x", hash[:16])
	if project != expected {
		t.Errorf("project = %q, want %q", project, expected)
	}
}

func TestResolveProject_DeterministicHash(t *testing.T) {
	// Same auth header should always produce the same project
	r1, _ := http.NewRequest("POST", "/", nil)
	r1.Header.Set("Authorization", "Bearer sk-abc")
	r2, _ := http.NewRequest("POST", "/", nil)
	r2.Header.Set("Authorization", "Bearer sk-abc")

	p1 := ResolveProject(r1)
	p2 := ResolveProject(r2)

	if p1 != p2 {
		t.Errorf("same auth produced different projects: %q vs %q", p1, p2)
	}
}

func TestResolveProject_DifferentKeysProduceDifferentHashes(t *testing.T) {
	r1, _ := http.NewRequest("POST", "/", nil)
	r1.Header.Set("Authorization", "Bearer sk-key-one")
	r2, _ := http.NewRequest("POST", "/", nil)
	r2.Header.Set("Authorization", "Bearer sk-key-two")

	p1 := ResolveProject(r1)
	p2 := ResolveProject(r2)

	if p1 == p2 {
		t.Errorf("different keys produced same project: %q", p1)
	}
}

func TestResolveProject_DefaultUnknown(t *testing.T) {
	r, _ := http.NewRequest("POST", "/openai/v1/chat/completions", nil)

	project := ResolveProject(r)
	if project != "unknown" {
		t.Errorf("project = %q, want %q", project, "unknown")
	}
}

func TestResolveProject_XProjectTakesPriority(t *testing.T) {
	// Even with Authorization present, X-Project wins
	r, _ := http.NewRequest("POST", "/", nil)
	r.Header.Set("X-Project", "explicit")
	r.Header.Set("Authorization", "Bearer sk-something")

	project := ResolveProject(r)
	if project != "explicit" {
		t.Errorf("project = %q, want %q (X-Project should take priority)", project, "explicit")
	}
}

func TestResolveProject_EmptyXProject(t *testing.T) {
	// Empty X-Project header should fall through to Authorization
	r, _ := http.NewRequest("POST", "/", nil)
	r.Header.Set("X-Project", "")
	r.Header.Set("Authorization", "Bearer sk-abc")

	project := ResolveProject(r)
	if !strings.HasPrefix(project, "key:") {
		t.Errorf("empty X-Project should fall through to auth hash, got %q", project)
	}
}
