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
		safePath := unsafeChars.ReplaceAllString(a.Path, "_")
		safeMsg := unsafeChars.ReplaceAllString(a.Message, " ")
		// Sanitize level to only valid GitHub Actions annotation levels
		level := "warning"
		if a.Level == "error" {
			level = "error"
		}
		// Also strip :: from path to prevent breaking the annotation format
		safePath = strings.ReplaceAll(safePath, "::", "_")
		fmt.Fprintf(w, "::%s file=%s,line=%d::%s\n", level, safePath, a.Line, safeMsg)
	}
	return nil
}

func WriteGitHubWorkflowSummary(w io.Writer, annotations []GitHubAnnotation) error {
	if len(annotations) == 0 {
		fmt.Fprintln(w, "No secrets detected!")
		return nil
	}

	fmt.Fprintf(w, "## MineSweep Results\n\n")
	fmt.Fprintf(w, "Found **%d** potential secrets:\n\n", len(annotations))

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
		fmt.Fprintf(w, "- 🔴 **%d** high severity\n", errors)
	}
	if warnings > 0 {
		fmt.Fprintf(w, "- 🟡 **%d** medium/low severity\n", warnings)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "| Severity | File | Line | Rule | Message |")
	fmt.Fprintln(w, "|----------|------|------|------|---------|")
	for _, a := range annotations {
		icon := "🟡"
		if a.Level == "error" {
			icon = "🔴"
		}
		msg := a.Message
		if len(msg) > 60 {
			msg = msg[:57] + "..."
		}
		fmt.Fprintf(w, "| %s | `%s` | %d | %s | %s |\n",
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
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return WriteGitHubAnnotations(f, annotations)
}
