package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"minesweep/findings"
)

type RuleStats struct {
	RuleID   string
	RuleName string
	HitCount int
	Severity findings.Severity
	AvgConf  float64
	Files    map[string]bool
}

type Dashboard struct {
	Rules       []*RuleStats
	TotalHits   int
	TotalFiles  int
	SeverityMap map[findings.Severity]int
}

func GenerateDashboard(data *findings.RiskReport) *Dashboard {
	if data == nil || len(data.Findings) == 0 {
		return &Dashboard{
			SeverityMap: make(map[findings.Severity]int),
		}
	}

	d := &Dashboard{
		SeverityMap: make(map[findings.Severity]int),
	}

	ruleMap := make(map[string]*RuleStats)

	for _, f := range data.Findings {
		d.TotalHits++
		d.SeverityMap[f.Severity]++

		stats, exists := ruleMap[f.RuleID]
		if !exists {
			stats = &RuleStats{
				RuleID:   f.RuleID,
				RuleName: f.Type,
				Severity: f.Severity,
				Files:    make(map[string]bool),
			}
			ruleMap[f.RuleID] = stats
		}

		stats.HitCount++
		stats.AvgConf = (stats.AvgConf*float64(stats.HitCount-1) + f.Confidence) / float64(stats.HitCount)
		stats.Files[f.File] = true
	}

	for _, stats := range ruleMap {
		d.Rules = append(d.Rules, stats)
	}

	sort.SliceStable(d.Rules, func(i, j int) bool {
		if d.Rules[i].HitCount != d.Rules[j].HitCount {
			return d.Rules[i].HitCount > d.Rules[j].HitCount
		}
		return d.Rules[i].RuleID < d.Rules[j].RuleID
	})

	seenFiles := make(map[string]bool)
	for _, f := range data.Findings {
		if !seenFiles[f.File] {
			seenFiles[f.File] = true
			d.TotalFiles++
		}
	}

	return d
}

func WriteDashboard(w io.Writer, d *Dashboard, verbose bool) error {
	if d == nil {
		fmt.Fprintln(w, "No data for dashboard")
		return nil
	}

	fmt.Fprintln(w, "╔════════════════════════════════════════════════════════════╗")
	fmt.Fprintln(w, "║                  Rule Health Dashboard                     ║")
	fmt.Fprintln(w, "╚════════════════════════════════════════════════════════════╝")
	fmt.Fprintln(w)

	fmt.Fprintf(w, "  Total Findings: %d\n", d.TotalHits)
	fmt.Fprintf(w, "  Files Affected: %d\n", d.TotalFiles)
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  Severity Distribution:")
	for _, sev := range []findings.Severity{findings.SeverityCritical, findings.SeverityHigh, findings.SeverityMedium, findings.SeverityLow, findings.SeverityInfo} {
		count := d.SeverityMap[sev]
		if count > 0 {
			bar := strings.Repeat("█", min(count, 30))
			fmt.Fprintf(w, "    %-10s %3d %s\n", sev, count, bar)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "  Top Rules:")
	fmt.Fprintf(w, "  %-20s %-8s %-6s %-10s\n", "RULE", "HITS", "CONF", "FILES")
	fmt.Fprintln(w, "  "+strings.Repeat("-", 50))

	displayCount := len(d.Rules)
	if displayCount > 20 {
		displayCount = 20
	}

	for i := 0; i < displayCount; i++ {
		stats := d.Rules[i]
		ruleID := truncateRunes(SanitizeTerminalInline(stats.RuleID), 18, "...")
		fmt.Fprintf(w, "  %-20s %-8d %-6.2f %-10d\n",
			ruleID, stats.HitCount, stats.AvgConf, len(stats.Files))
	}

	if len(d.Rules) > 20 {
		fmt.Fprintf(w, "  ... and %d more rules\n", len(d.Rules)-20)
	}

	if verbose {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "  Detailed Rule Stats:")
		for _, stats := range d.Rules {
			// Rule names come from rule files and file paths come from the
			// scanned tree; both are attacker-controlled and both reach a
			// terminal here. This renderer sanitized nothing, while the text
			// report sanitized every one of these fields.
			fmt.Fprintf(w, "    %s (%s)\n", SanitizeTerminalInline(stats.RuleName), SanitizeTerminalInline(stats.RuleID))
			fmt.Fprintf(w, "      Hits: %d, Avg Confidence: %.2f\n", stats.HitCount, stats.AvgConf)
			fmt.Fprintf(w, "      Files: %d\n", len(stats.Files))
			fileList := make([]string, 0, len(stats.Files))
			for f := range stats.Files {
				fileList = append(fileList, SanitizeTerminalInline(f))
			}
			sort.Strings(fileList)
			if len(fileList) > 5 {
				fileList = fileList[:5]
				fileList = append(fileList, fmt.Sprintf("... and %d more", len(stats.Files)-5))
			}
			fmt.Fprintf(w, "      %s\n", strings.Join(fileList, ", "))
		}
	}

	return nil
}

// truncateRunes shortens s to at most maxRunes characters, appending suffix.
// Byte slicing produced replacement characters when a rule ID contained a
// multi-byte rune at the cut point.
func truncateRunes(s string, maxRunes int, suffix string) string {
	if maxRunes <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxRunes {
		return s
	}
	runes := []rune(s)
	cut := maxRunes - utf8.RuneCountInString(suffix)
	if cut < 0 {
		cut = 0
	}
	return string(runes[:cut]) + suffix
}
