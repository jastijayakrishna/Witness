package auth

import (
	"strings"
	"testing"
)

func TestHashAPIKeyIsStableAndPrefixed(t *testing.T) {
	first := HashAPIKey(" hubbleops_live_test ")
	second := HashAPIKey("hubbleops_live_test")
	if first != second {
		t.Fatalf("hash not stable across surrounding whitespace")
	}
	if !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("hash=%q missing sha256 prefix", first)
	}
	if strings.Contains(first, "hubbleops_live_test") {
		t.Fatalf("hash leaked raw key")
	}
}
