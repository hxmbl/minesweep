package report

import (
	"bytes"
	"strings"
	"testing"

	"minesweep/findings"
)

func TestSanitizeTerminalStripsEscapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain.txt", "plain.txt"},
		{"\x1b]0;PWNED\x07file.py", "\\e]0;PWNED^Gfile.py"},
		{"\x1b[31mred\x1b[0m", "\\e[31mred\\e[0m"},
		{"tab\tkept\nnl\nkept", "tab\tkept\nnl\nkept"},
		{"\x00null\x07bell", "^@null^Gbell"},
		{"\x7fdel", "^?del"},
	}
	for _, c := range cases {
		if got := SanitizeTerminal(c.in); got != c.want {
			t.Errorf("SanitizeTerminal(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWriteTextEscapesHostileFilename(t *testing.T) {
	hostile := "\x1b]0;PWNED\x07\x1b[31mevil\x1b[0m.py"
	rep := findings.GenerateRiskReport([]findings.Finding{{
		Type:     "T",
		RuleID:   "t-rule",
		Severity: findings.SeverityCritical,
		File:     hostile,
		Line:     1,
		Action:   findings.ActionBlock,
	}}, nil)

	var buf bytes.Buffer
	if err := WriteText(&buf, &rep, TextOptions{Color: ColorNever}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b]0;") || strings.Contains(out, "\x1b[31m") {
		t.Fatalf("raw escape sequences reached output:\n%q", out)
	}
	if !strings.Contains(out, `\e]0;PWNED`) {
		t.Errorf("expected escaped form in output:\n%s", out)
	}
}

func TestAnnotationsEscapeSequences(t *testing.T) {
	anns := []GitHubAnnotation{{
		Path:    "\x1b[2Jclear.py",
		Line:    3,
		Level:   "error",
		Message: "boom",
	}}
	var buf bytes.Buffer
	if err := WriteGitHubAnnotations(&buf, anns); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "\x1b[2J") {
		t.Fatalf("escape passthrough in annotations: %q", buf.String())
	}
}

func TestSARIFEscapesMessageAndURI(t *testing.T) {
	rep := findings.GenerateRiskReport([]findings.Finding{{
		Type:     "\x1b[31mEvil",
		RuleID:   "evil-rule",
		Severity: findings.SeverityHigh,
		File:     "\x1b]0;t\x07p.go",
		Line:     1,
	}}, nil)

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, &rep, "test"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("raw ESC reached SARIF output:\n%q", out)
	}
}
