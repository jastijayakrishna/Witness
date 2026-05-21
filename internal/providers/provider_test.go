package providers

import "testing"

func TestLookup_OpenAI(t *testing.T) {
	p := Lookup("/openai/v1/chat/completions")
	if p == nil {
		t.Fatal("expected openai provider, got nil")
	}
	if p.Name != "openai" {
		t.Errorf("name = %q, want %q", p.Name, "openai")
	}
}

func TestLookup_Anthropic(t *testing.T) {
	p := Lookup("/anthropic/v1/messages")
	if p == nil {
		t.Fatal("expected anthropic provider, got nil")
	}
	if p.Name != "anthropic" {
		t.Errorf("name = %q, want %q", p.Name, "anthropic")
	}
}

func TestLookup_Unknown(t *testing.T) {
	p := Lookup("/google/v1/models")
	if p != nil {
		t.Errorf("expected nil for unknown path, got %q", p.Name)
	}
}

func TestLookup_ExactPrefix(t *testing.T) {
	// Just the prefix with nothing after
	p := Lookup("/openai")
	if p == nil {
		t.Fatal("expected openai provider for exact prefix match")
	}
}

func TestLookup_EmptyPath(t *testing.T) {
	p := Lookup("")
	if p != nil {
		t.Error("expected nil for empty path")
	}
}

func TestLookup_ShortPath(t *testing.T) {
	p := Lookup("/o")
	if p != nil {
		t.Error("expected nil for path shorter than any prefix")
	}
}

func TestRegistry_ContainsBothProviders(t *testing.T) {
	if _, ok := Registry["/openai"]; !ok {
		t.Error("registry missing /openai")
	}
	if _, ok := Registry["/anthropic"]; !ok {
		t.Error("registry missing /anthropic")
	}
}
