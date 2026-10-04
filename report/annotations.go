package report

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"minesweep/findings"
)

var unsafeChars = regexp.MustCompile(`[\n\r]`)

type GitHubAnnotation struct {
	Path    string
	Line    int
	Level   string
	Message string
}

func GenerateAnnotations(findingsList []findings.Finding, minSeverity findings.Severity) []GitHubAnnotation {
	var annotations []GitHubAnnotation

	for _, f := range findingsList {
		if f.Severity < minSeverity {
			continue
		}

		level := "warning"
		if f.Severity >= findings.SeverityHigh {
			level = "error"
		}

		annotations = append(annotations, GitHubAnnotation{
			Path:  f.File,
			Line:  f.Line,
			Level: level,
			// Sanitized here rather than only at render time: these strings are
			// also compared by extractRuleID, which indexes bytes, so a value
			// containing "]" would otherwise make the table attribute the wrong
			// rule.
			Message: fmt.Sprintf("[%s] %s (confidence: %.0f%%)",
				SanitizeTerminalInline(f.RuleID), SanitizeTerminalInline(f.Reason),
				f.Confidence*findings.ConfidenceScale),
		})
	}

	return annotations
}

// WriteGitHubAnnotations renders GitHub Actions workflow commands.
//
// Every write error is propagated. These go to the workflow command channel and
// to the job summary file: a partial write there is a partial *gate*, so a
// failure must not be reported as a completed annotation run.
func WriteGitHubAnnotations(w io.Writer, annotations []GitHubAnnotation) error {
	for _, a := range annotations {
		// Sanitize to prevent log injection.
		safePath := strings.ReplaceAll(
			unsafeChars.ReplaceAllString(SanitizeTerminalInline(a.Path), "_"), "::", "_")
		safeMsg := unsafeChars.ReplaceAllString(SanitizeTerminalInline(a.Message), " ")
		// Sanitize level to only valid GitHub Actions annotation levels.
		level := "warning"
		if a.Level == "error" {
			level = "error"
		}
		if _, err := fmt.Fprintf(w, "::%s file=%s,line=%d::%s\n",
			level, safePath, a.Line, safeMsg); err != nil {
			return fmt.Errorf("write annotation for %s: %w", a.Path, err)
		}
	}
	return nil
}

// WriteGitHubWorkflowSummary renders the job summary table.
//
// Write errors are propagated: a truncated summary that shows fewer findings
// than were reported is worse than no summary, because a reader stops looking.
func WriteGitHubWorkflowSummary(w io.Writer, annotations []GitHubAnnotation) error {
	if len(annotations) == 0 {
		_, err := fmt.Fprintln(w, "No secrets detected!")
		return err
	}

	if _, err := fmt.Fprint(w, "## MineSweep Results\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Found **%d** potential secrets:\n\n", len(annotations)); err != nil {
		return err
	}

	errors := 0
	warnings := 0
	for _, a := range annotations {
		if a.Level == "error" {
			errors++
		} else {
			warnings++
		}
	}

	if errors > 0 {
		if _, err := fmt.Fprintf(w, "- 🔴 **%d** high severity\n", errors); err != nil {
			return err
		}
	}
	if warnings > 0 {
		if _, err := fmt.Fprintf(w, "- 🟡 **%d** medium/low severity\n", warnings); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "| Severity | File | Line | Rule | Message |"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "|----------|------|------|------|---------|"); err != nil {
		return err
	}
	for _, a := range annotations {
		icon := "🟡"
		if a.Level == "error" {
			icon = "🔴"
		}
		// Truncate on a rune boundary: byte slicing split multi-byte
		// characters into replacement bytes inside a Markdown table cell.
		msg := truncateRunes(a.Message, 60, "...")
		if _, err := fmt.Fprintf(w, "| %s | `%s` | %d | %s | %s |\n",
			icon, a.Path, a.Line, extractRuleID(a.Message), msg); err != nil {
			return err
		}
	}

	return nil
}

func extractRuleID(msg string) string {
	if idx := strings.Index(msg, "]"); idx > 0 {
		return msg[1:idx]
	}
	return ""
}

func WriteAnnotationsToFile(path string, annotations []GitHubAnnotation) error {
	f, err := os.Create(path) //nolint:gosec // the caller named this output path
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-back only; the write error below is the one that matters

	return WriteGitHubAnnotations(f, annotations)
}
