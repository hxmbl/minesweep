package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"minesweep/findings"
)

func WriteJSON(w io.Writer, report *findings.RiskReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

type TextOptions struct {
	Verbose bool
	Color   ColorMode
	Hints   []string
}

type severityGroup struct {
	sev      findings.Severity
	label    string
	findings []findings.Finding
}

func WriteText(w io.Writer, report *findings.RiskReport, opts TextOptions) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}

	tw := &textWriter{w: w}
	p := palette{enabled: colorEnabled(opts.Color, w)}

	if len(report.Findings) == 0 {
		return writeCleanReport(tw, p, report)
	}

	grouped := groupBySeverity(report.Findings)

	writeHeader(tw, p, report)
	writeLegend(tw, p, grouped)
	writeGroups(tw, p, opts, grouped)
	writeBoundaries(tw, p, report, opts)
	writeRiskFactors(tw, p, report, opts)
	writeNextSteps(tw, p, opts)

	return tw.err
}

func writeCleanReport(tw *textWriter, p palette, report *findings.RiskReport) error {
	tw.writeln(p.green("✓") + " No secrets or sensitive data detected.")
	if report.FilesScanned > 0 {
		stats := fmt.Sprintf("%d file", report.FilesScanned)
		if report.FilesScanned != 1 {
			stats += "s"
		}
		if report.DurationMs > 0 {
			stats += fmt.Sprintf(" in %.1fs", float64(report.DurationMs)/1000.0)
		}
		tw.writeln(p.dim("  Scanned " + stats + "."))
	}
	return tw.err
}

func writeHeader(tw *textWriter, p palette, report *findings.RiskReport) {
	score := strings.ToUpper(report.RiskScore.Label())
	header := fmt.Sprintf("Risk score: %s (%d/100)", score, int(report.RiskScore))
	switch {
	case report.RiskScore >= findings.RiskScoreCritical:
		tw.writeln(p.boldRed(header) + p.gray(" — credentials detected, rotation required"))
	case report.RiskScore >= findings.RiskScoreHigh:
		tw.writeln(p.boldYellow(header) + p.gray(" — not safe to share publicly or with AI tools"))
	case report.RiskScore >= findings.RiskScoreMedium:
		tw.writeln(p.yellow(header) + p.gray(" — review before sharing"))
	default:
		tw.writeln(p.cyan(header) + p.gray(" — verify findings before sharing"))
	}
	tw.writefmt("%s\n\n", pluralize(report.Findings, "finding"))
	writeCounts(tw, p, groupBySeverity(report.Findings))
	tw.writeln("")
}

func writeCounts(tw *textWriter, p palette, groups []severityGroup) {
	var parts []string
	for _, g := range groups {
		text := fmt.Sprintf("%d %s", len(g.findings), g.label)
		var styled string
		switch g.sev {
		case findings.SeverityCritical:
			styled = p.boldRed(text)
		case findings.SeverityHigh:
			styled = p.red(text)
		case findings.SeverityMedium:
			styled = p.yellow(text)
		case findings.SeverityLow:
			styled = p.cyan(text)
		default:
			styled = p.gray(text)
		}
		parts = append(parts, styled)
	}
	tw.writeln(strings.Join(parts, p.dim("  ·  ")))
}

func writeLegend(tw *textWriter, p palette, groups []severityGroup) {
	seen := map[findings.Action]bool{}
	for _, g := range groups {
		for _, f := range g.findings {
			seen[f.Action] = true
		}
	}
	var legend []string
	if seen[findings.ActionBlock] {
		legend = append(legend, "block: must fix before sharing")
	}
	if seen[findings.ActionRedact] {
		legend = append(legend, "redact: value hidden")
	}
	if seen[findings.ActionWarn] {
		legend = append(legend, "warn: review recommended")
	}
	if len(legend) == 0 {
		return
	}
	tw.writeln(p.dim(strings.Join(legend, "  ·  ")))
	tw.writeln("")
}

func writeGroups(tw *textWriter, p palette, opts TextOptions, groups []severityGroup) {
	for _, g := range groups {
		tw.writeln(sectionHeader(p, g.sev, g.label))
		for _, f := range g.findings {
			writeFinding(tw, p, opts, f)
		}
		tw.writeln("")
	}
}

func writeFinding(tw *textWriter, p palette, opts TextOptions, f findings.Finding) {
	action := actionLabel(p, f.Action)
	conf := fmt.Sprintf("%.0f%%", f.Confidence*findings.ConfidenceScale)
	tw.writefmt("  %s %s\n", action, p.bold(f.Type))
	loc := fmt.Sprintf("%s:%d · %s confident", f.File, f.Line, conf)
	if len(f.Commit) >= 7 {
		loc += fmt.Sprintf(" · commit %s", shortHash(f.Commit))
	}
	tw.writeln(p.dim(loc))
	if f.Author != "" || f.Date != "" {
		who := strings.TrimSpace(f.Author)
		if who != "" {
			who = "by " + who
		}
		tw.writeln(p.dim(fmt.Sprintf("          introduced %s %s", f.Date, who)))
	}
	if f.CommitSummary != "" {
		tw.writefmt("          %s\n", p.dim(wrapText("\""+f.CommitSummary+"\"", 12)))
	}

	if opts.Verbose && f.Value != "" {
		val := f.Value
		if len(val) > 60 {
			val = val[:60] + "..."
		}
		tw.writefmt("          Value: %s\n", val)
	}
	if txt := remediationFor(f); txt != "" {
		tw.writefmt("          %s %s\n", p.cyan("↳"), wrapText(txt, 12))
	} else if f.Reason != "" {
		tw.writefmt("          %s %s\n", p.cyan("↳"), wrapText(f.Reason, 12))
	}
	if opts.Verbose && f.Context != "" {
		tw.writeln(p.dim("          Context:"))
		for _, line := range splitLines(f.Context) {
			tw.writefmt("            %s\n", p.dim(line))
		}
	}
}

func writeBoundaries(tw *textWriter, p palette, report *findings.RiskReport, opts TextOptions) {
	if !opts.Verbose || len(report.SafeToShare) == 0 {
		return
	}
	tw.writeln(sectionTitle(p, "Boundary checks"))
	names := make([]string, 0, len(report.SafeToShare))
	for b := range report.SafeToShare {
		names = append(names, b)
	}
	sort.Strings(names)
	for _, b := range names {
		status := p.red("✗ Unsafe")
		if report.SafeToShare[b] {
			status = p.green("✓ Safe")
		}
		tw.writefmt("  %-20s %s\n", b+":", status)
	}
	tw.writeln("")
}

func writeRiskFactors(tw *textWriter, p palette, report *findings.RiskReport, opts TextOptions) {
	if !opts.Verbose || len(report.Reasons) == 0 {
		return
	}
	tw.writeln(sectionTitle(p, "Risk factors"))
	for _, r := range report.Reasons {
		tw.writefmt("  %s %s\n", p.yellow("•"), r)
	}
	tw.writeln("")
}

func writeNextSteps(tw *textWriter, p palette, opts TextOptions) {
	hints := opts.Hints
	if len(hints) == 0 {
		hints = []string{"Run with -v to see matched values and context."}
	}
	tw.writeln(sectionTitle(p, "Next steps"))
	for _, h := range hints {
		tw.writefmt("  %s %s\n", p.dim("•"), h)
	}
}

func groupBySeverity(fs []findings.Finding) []severityGroup {
	labels := map[findings.Severity]string{
		findings.SeverityCritical: "critical",
		findings.SeverityHigh:     "high",
		findings.SeverityMedium:   "medium",
		findings.SeverityLow:      "low",
		findings.SeverityInfo:     "info",
	}
	var groups []severityGroup
	for sev := findings.SeverityCritical; sev >= findings.SeverityInfo; sev-- {
		g := severityGroup{sev: sev, label: labels[sev]}
		for _, f := range fs {
			if f.Severity == sev {
				g.findings = append(g.findings, f)
			}
		}
		if len(g.findings) > 0 {
			groups = append(groups, g)
		}
	}
	return groups
}

func sectionHeader(p palette, sev findings.Severity, label string) string {
	title := strings.ToUpper(label)
	var colored string
	switch sev {
	case findings.SeverityCritical:
		colored = p.boldRed(title)
	case findings.SeverityHigh:
		colored = p.bold(title)
	case findings.SeverityMedium:
		colored = p.boldYellow(title)
	default:
		colored = p.dim(title)
	}
	return colored + p.dim(" "+strings.Repeat("─", max(3, 58-len(title))))
}

func sectionTitle(p palette, title string) string {
	return p.dim(strings.Repeat("─", 8) + " " + title + " " + strings.Repeat("─", max(3, 50-len(title))))
}

func actionLabel(p palette, a findings.Action) string {
	s := "[" + string(a) + "]"
	switch a {
	case findings.ActionBlock:
		return p.boldRed(s)
	case findings.ActionRedact:
		return p.cyan(s)
	case findings.ActionWarn:
		return p.yellow(s)
	case findings.ActionAllow:
		return p.green(s)
	default:
		return s
	}
}

const wrapWidth = 96

func wrapText(s string, indent int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := words[0]
	pad := strings.Repeat(" ", indent)
	for _, w := range words[1:] {
		if len(line)+1+len(w) > wrapWidth {
			b.WriteString(line + "\n" + pad)
			line = w
			continue
		}
		line += " " + w
	}
	b.WriteString(line)
	return b.String()
}

func shortHash(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func pluralize(items []findings.Finding, noun string) string {
	if len(items) == 1 {
		return "Found 1 " + noun + "."
	}
	return fmt.Sprintf("Found %d %ss.", len(items), noun)
}

type textWriter struct {
	w   io.Writer
	err error
}

func (tw *textWriter) writeln(s string) {
	if tw.err != nil {
		return
	}
	_, tw.err = fmt.Fprintln(tw.w, s)
}

func (tw *textWriter) writefmt(format string, args ...interface{}) {
	if tw.err != nil {
		return
	}
	_, tw.err = fmt.Fprintf(tw.w, format, args...)
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
