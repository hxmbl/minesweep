package report

import (
	"bytes"
	"strings"
	"testing"

	"minesweep/findings"
)

// M3 — syntax highlighting was gated on the *requested* colour mode rather than
// the resolved palette, so a caller writing to a file or a pipe with ColorAuto
// got escape sequences injected into an otherwise plain report. The CLI resolved
// auto before calling WriteText, which is why the command line never showed it.
func TestNoStrayANSIToANonTerminalWriter(t *testing.T) {
	rep := snippetReport("a.py")

	for _, mode := range []ColorMode{ColorAuto, ColorNever} {
		var buf bytes.Buffer
		if err := WriteText(&buf, rep, TextOptions{Color: mode, Snippets: true}); err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(buf.String(), "\x1b["); n != 0 {
			t.Errorf("mode %s: %d ANSI sequences in output meant for a file or pipe", mode, n)
		}
		// The value is censored, so the line survives as a token.
		if !strings.Contains(buf.String(), "const password") || !strings.Contains(buf.String(), "sha256:") {
			t.Errorf("mode %s: the censored source line was lost:\n%s", mode, buf.String())
		}
	}
}

// An explicit --color always must still highlight, or the fix would have
// disabled the feature.
func TestHighlightStillAppliesWhenColorIsForced(t *testing.T) {
	rep := snippetReport("a.py")
	var buf bytes.Buffer
	if err := WriteText(&buf, rep, TextOptions{Color: ColorAlways, Snippets: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[") {
		t.Error("--color always must still highlight")
	}
}

// The gate applies to every recognized file type, not just the ones a probe
// happened to try: the earlier test missed this because the file it used had no
// highlightable tokens.
func TestHighlightGateCoversEveryFileType(t *testing.T) {
	for _, file := range []string{"a.env", "a.py", "a.go", "a.js", "a.rs", "config.yaml", "a.json"} {
		var buf bytes.Buffer
		if err := WriteText(&buf, snippetReport(file), TextOptions{Color: ColorAuto, Snippets: true}); err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(buf.String(), "\x1b["); n != 0 {
			t.Errorf("%s: %d ANSI sequences with ColorAuto to a buffer", file, n)
		}
	}
}

// Snippet evidence must still be censored and sanitized with highlighting on.
func TestSnippetStillCensorsWithColorForced(t *testing.T) {
	raw := "const password = \"hunter2hunter2\""
	rep := &findings.RiskReport{Findings: []findings.Finding{{
		Type: "Password", RuleID: "generic-password",
		Severity: findings.SeverityCritical, Confidence: 0.7,
		File: "a.py", Line: 1, Column: 1, Value: "hunter2hunter2",
		Action: findings.ActionBlock, Reason: "r",
		SourceLine: raw,
		Context:    "> " + raw + "\n  \n",
	}}}
	var buf bytes.Buffer
	if err := WriteText(&buf, rep, TextOptions{Color: ColorAlways, Snippets: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), raw) {
		t.Errorf("the raw value survived censoring with colour forced:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "sha256:") {
		t.Errorf("no token in the snippet:\n%s", buf.String())
	}
}

func snippetReport(file string) *findings.RiskReport {
	const line = "const password = \"hunter2hunter2\""
	return &findings.RiskReport{Findings: []findings.Finding{{
		Type: "Password", RuleID: "generic-password",
		Severity: findings.SeverityCritical, Confidence: 0.7,
		File: file, Line: 1, Column: 1, Value: "hunter2hunter2",
		Action: findings.ActionBlock, Reason: "r",
		SourceLine: line,
		Context:    "> " + line + "\n  \n",
	}}}
}
