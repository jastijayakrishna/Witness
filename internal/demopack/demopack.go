// Package demopack embeds the famous-eight incident replays so `witness demo`
// works from the bare binary — install → wow with zero setup.
package demopack

import (
	"embed"
	"fmt"
	"sort"

	"github.com/witness-proxy/witness-proxy/internal/synthcorpus"
)

//go:embed data/*.jsonl
var dataFS embed.FS

// Incident is one replayed famous incident with its ground truth.
type Incident struct {
	Label          string
	SourceIncident string
	ExpectedSignal string
	Events         []synthcorpus.Event
}

// Incidents parses every embedded demo file, sorted by filename for stable order.
func Incidents() ([]Incident, error) {
	entries, err := dataFS.ReadDir("data")
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out []Incident
	for _, entry := range entries {
		f, err := dataFS.Open("data/" + entry.Name())
		if err != nil {
			return nil, err
		}
		events, err := synthcorpus.ReadJSONL(f, entry.Name())
		f.Close()
		if err != nil {
			return nil, err
		}
		if len(events) == 0 {
			return nil, fmt.Errorf("%s: empty demo file", entry.Name())
		}
		first := events[0]
		out = append(out, Incident{
			Label:          first.Label,
			SourceIncident: first.SourceIncident,
			ExpectedSignal: first.ExpectedSignal,
			Events:         events,
		})
	}
	return out, nil
}
