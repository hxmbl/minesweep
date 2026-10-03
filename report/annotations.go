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
		// Respect the policy action. A finding the policy allows is one the user
		// has already decided not to act on, and annotating it red on the pull
		// request contradicts that decision -- a scan that reports exit 0 and then
		// posts errors anyway.
		if f.Action == findings.ActionAllow {
			continue
		}

		level := "warning"
		if f.Severity >= findings.SeverityHigh {
			level = "error"
		}

		annotations = append(annotations, GitHubAnnotation{
			Path:    f.File,
			Line:    f.Line,
			Level:   level,
			Message: fmt.Sprintf("[%s] %s (confidence: %.0f%%)", f.RuleID, f.Reason, f.Confidence*100),
		})
	}

	return annotations
}

func WriteGitHubAnnotations(w io.Writer, annotations []GitHubAnnotation) error {
	for _, a := range annotations {
		// Sanitize to prevent log injection
		safePath := unsafeChars.ReplaceAllString(SanitizeTerminal(a.Path), "_")
		safeMsg := unsafeChars.ReplaceAllString(SanitizeTerminal(a.Message), " ")
		// Sanitize level to only valid GitHub Actions annotation levels
		level := "warning"
		if a.Level == "error" {
			level = "error"
		}
		// Also strip :: from path to prevent breaking the annotation format
		safePath = strings.ReplaceAll(safePath, "::", "_")
		_, _ = fmt.Fprintf(w, "::%s file=%s,line=%d::%s\n", level, safePath, a.Line, safeMsg)
	}
	return nil
}

func WriteGitHubWorkflowSummary(w io.Writer, annotations []GitHubAnnotation) error {
	if len(annotations) == 0 {
		_, _ = fmt.Fprintln(w, "No secrets detected!")
		return nil
	}

	_, _ = fmt.Fprintf(w, "## MineSweep Results\n\n")
	_, _ = fmt.Fprintf(w, "Found **%d** potential secrets:\n\n", len(annotations))

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
		_, _ = fmt.Fprintf(w, "- 🔴 **%d** high severity\n", errors)
	}
	if warnings > 0 {
		_, _ = fmt.Fprintf(w, "- 🟡 **%d** medium/low severity\n", warnings)
	}
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintln(w, "| Severity | File | Line | Rule | Message |")
	_, _ = fmt.Fprintln(w, "|----------|------|------|------|---------|")
	for _, a := range annotations {
		icon := "🟡"
		if a.Level == "error" {
			icon = "🔴"
		}
		msg := a.Message
		if len(msg) > 60 {
			msg = msg[:57] + "..."
		}
		_, _ = fmt.Fprintf(w, "| %s | `%s` | %d | %s | %s |\n",
			icon, a.Path, a.Line, extractRuleID(a.Message), msg)
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
	// G304: path is the annotations file the caller asked to write.
	f, err := os.Create(path) //nolint:gosec
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return WriteGitHubAnnotations(f, annotations)
}
