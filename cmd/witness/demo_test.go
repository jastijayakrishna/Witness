package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderDemoReportShowsIncidentsAndDollars(t *testing.T) {
	var buf bytes.Buffer
	missed, err := renderDemoReport(&buf, false)
	if err != nil {
		t.Fatalf("render demo: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"Cloudflare", "Replit", "synthetic", "$"} {
		if !strings.Contains(out, want) {
			t.Fatalf("demo output missing %q:\n%s", want, out)
		}
	}
	_ = missed // 8/8 is enforced by the famous-eight gate, not this rendering test
}
