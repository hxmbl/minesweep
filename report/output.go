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

func WriteText(w io.Writer, report *findings.RiskReport, verbose bool) {
	fmt.Fprintln(w, report.Summary)
	fmt.Fprintln(w)

	if len(report.Findings) == 0 {
		return
	}

	fmt.Fprintln(w, "Findings:")
	fmt.Fprintln(w)

	for _, f := range report.Findings {
		fmt.Fprintf(w, "  [%s] %s\n", f.Action, f.Type)
		fmt.Fprintf(w, "        File: %s:%d\n", f.File, f.Line)
		if verbose {
			val := f.Value
			if len(val) > 60 {
				val = val[:60] + "..."
			}
			fmt.Fprintf(w, "        Value: %s\n", val)
		}
		fmt.Fprintf(w, "        Severity: %s | Confidence: %.0f%%\n", f.Severity, f.Confidence*100)
		fmt.Fprintln(w)
	}

	if len(report.Reasons) > 0 {
		fmt.Fprintln(w, "Risk factors:")
		for _, r := range report.Reasons {
			fmt.Fprintf(w, "  \u2022 %s\n", r)
		}
		fmt.Fprintln(w)
	}

	if len(report.SafeToShare) > 0 {
		fmt.Fprintln(w, "Boundary checks:")
		for boundary, safe := range report.SafeToShare {
			status := "\u26A0 Unsafe"
			if safe {
				status = "\u2713 Safe"
			}
			fmt.Fprintf(w, "  %-20s %s\n", boundary+":", status)
		}
	}
}
