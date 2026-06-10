package synthcorpus

import (
	"fmt"
	"sort"
	"strings"
)

// FamilyRow aggregates one corpus family. Positive families (expected block)
// report Detected; negative families (expected allow) report FalseBlocks/Warns.
type FamilyRow struct {
	Family      string
	Expected    string // "block" | "allow"
	Sessions    int
	Detected    int
	FalseBlocks int
	Warns       int
}

type Scoreboard struct {
	Rows   []FamilyRow
	Misses []SessionResult // missed positives + false-flagged negatives (blocks and warns)

	TruePositives  int
	FalsePositives int
	Positives      int
	Negatives      int
}

func Score(results []SessionResult) Scoreboard {
	rows := map[string]*FamilyRow{}
	var sb Scoreboard
	for _, r := range results {
		row, ok := rows[r.Label]
		if !ok {
			row = &FamilyRow{Family: r.Label, Expected: r.ExpectedAction}
			rows[r.Label] = row
		}
		row.Sessions++
		if r.ExpectedAction == "block" {
			sb.Positives++
			if r.Verdict == "block" {
				row.Detected++
				sb.TruePositives++
			} else {
				sb.Misses = append(sb.Misses, r)
			}
		} else {
			sb.Negatives++
			switch r.Verdict {
			case "block":
				row.FalseBlocks++
				sb.FalsePositives++
				sb.Misses = append(sb.Misses, r)
			case "warn":
				row.Warns++
				sb.Misses = append(sb.Misses, r)
			}
		}
	}
	for _, row := range rows {
		sb.Rows = append(sb.Rows, *row)
	}
	sort.Slice(sb.Rows, func(i, j int) bool { return sb.Rows[i].Family < sb.Rows[j].Family })
	return sb
}

// GateFailures enforces the world-class bar: every positive family >= minDetect
// detected, every negative family 0 blocks and <= maxWarnRate warns.
func (sb Scoreboard) GateFailures(minDetect, maxWarnRate float64) []string {
	var failures []string
	for _, row := range sb.Rows {
		if row.Sessions == 0 {
			continue
		}
		if row.Expected == "block" {
			rate := float64(row.Detected) / float64(row.Sessions)
			if rate < minDetect {
				failures = append(failures, fmt.Sprintf(
					"positive family %s detected %d/%d (%.1f%%) < %.0f%%",
					row.Family, row.Detected, row.Sessions, rate*100, minDetect*100))
			}
		} else {
			if row.FalseBlocks > 0 {
				failures = append(failures, fmt.Sprintf(
					"negative family %s has %d false blocks (must be 0)",
					row.Family, row.FalseBlocks))
			}
			warnRate := float64(row.Warns) / float64(row.Sessions)
			if warnRate > maxWarnRate {
				failures = append(failures, fmt.Sprintf(
					"negative family %s warn rate %d/%d (%.1f%%) > %.0f%%",
					row.Family, row.Warns, row.Sessions, warnRate*100, maxWarnRate*100))
			}
		}
	}
	return failures
}

func (sb Scoreboard) Precision() float64 {
	if sb.TruePositives+sb.FalsePositives == 0 {
		return 0
	}
	return float64(sb.TruePositives) / float64(sb.TruePositives+sb.FalsePositives)
}

func (sb Scoreboard) Recall() float64 {
	if sb.Positives == 0 {
		return 0
	}
	return float64(sb.TruePositives) / float64(sb.Positives)
}

func (sb Scoreboard) Format() string {
	var b strings.Builder
	b.WriteString("SYNTHETIC CORPUS SCOREBOARD (synthetic data — not pilot traffic)\n")
	b.WriteString(fmt.Sprintf("%-36s %-8s %10s %12s %8s\n", "family", "expect", "detected", "false_blocks", "warns"))
	for _, row := range sb.Rows {
		if row.Expected == "block" {
			b.WriteString(fmt.Sprintf("%-36s %-8s %7d/%d %12s %8s\n",
				row.Family, row.Expected, row.Detected, row.Sessions, "-", "-"))
		} else {
			b.WriteString(fmt.Sprintf("%-36s %-8s %10s %9d/%d %5d/%d\n",
				row.Family, row.Expected, "-", row.FalseBlocks, row.Sessions, row.Warns, row.Sessions))
		}
	}
	b.WriteString(fmt.Sprintf("overall (synthetic): precision=%.4f recall=%.4f positives=%d negatives=%d\n",
		sb.Precision(), sb.Recall(), sb.Positives, sb.Negatives))
	return b.String()
}
