package report

import (
	"encoding/json"
	"fmt"
	"io"

	"minesweep/findings"
)

func WriteJSON(w io.Writer, report *findings.RiskReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func WriteText(w io.Writer, report *findings.RiskReport, verbose bool) error {
	if report == nil {
		return fmt.Errorf("report is nil")
	}

	tw := &textWriter{w: w}

	tw.writeln(report.Summary)
	tw.writeln("")

	if len(report.Findings) == 0 {
		return tw.err
	}

	tw.writeln("Findings:")
	tw.writeln("")

	for _, f := range report.Findings {
		tw.writefmt("  [%s] %s\n", f.Action, f.Type)
		tw.writefmt("        File: %s:%d\n", f.File, f.Line)
		if f.SourceLine != "" {
			sourceLine := f.SourceLine
			if len(sourceLine) > 80 {
				sourceLine = sourceLine[:80] + "..."
			}
			tw.writefmt("        Line: %s\n", sourceLine)
		}
		if verbose {
			val := f.Value
			if len(val) > 60 {
				val = val[:60] + "..."
			}
			tw.writefmt("        Value: %s\n", val)
			if f.Context != "" {
				tw.writeln("        Context:")
				for _, line := range splitLines(f.Context) {
					tw.writefmt("          %s\n", line)
				}
			}
		}
		tw.writefmt("        Severity: %s | Confidence: %.0f%%\n", f.Severity, f.Confidence*findings.ConfidenceScale)
		tw.writeln("")
	}

	if len(report.Reasons) > 0 {
		tw.writeln("Risk factors:")
		for _, r := range report.Reasons {
			tw.writefmt("  \u2022 %s\n", r)
		}
		tw.writeln("")
	}

	if len(report.SafeToShare) > 0 {
		tw.writeln("Boundary checks:")
		for boundary, safe := range report.SafeToShare {
			status := "\u26A0 Unsafe"
			if safe {
				status = "\u2713 Safe"
			}
			tw.writefmt("  %-20s %s\n", boundary+":", status)
		}
	}

	return tw.err
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
