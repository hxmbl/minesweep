package report

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"minesweep/findings"
)

// M3 — syntax highlighting was gated on the *requested* colour mode rather than
// the resolved palette, so a caller writing to a file or a pipe with ColorAuto
// got escape sequences injected into an otherwise plain report. The CLI resolved
// auto before calling WriteText, which is why the command line never showed it.
func TestNoStrayANSIToANonTerminalWriter(t *testing.T) {
	rep := CensorReport(snippetReport("a.py"))

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
		if err := WriteText(&buf, CensorReport(snippetReport(file)), TextOptions{Color: ColorAuto, Snippets: true}); err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(buf.String(), "\x1b["); n != 0 {
			t.Errorf("%s: %d ANSI sequences with ColorAuto to a buffer", file, n)
		}
	}
}

// Snippet evidence must still be censored and sanitized with highlighting on.
// Snippet evidence must still be censored and sanitized with highlighting on.
//
// The report is censored by the caller, exactly as scanAndReport does. WriteText
// deliberately does not censor: it used to, which meant the heuristic in
// censorSecretSubstrings ran twice over the same text and, because it is not
// idempotent, produced a different rendering for each finding that referenced a
// line. It also made --dangerously-show-secrets a no-op for snippets.
func TestSnippetStillCensorsWithColorForced(t *testing.T) {
	raw := "const password = \"hunter2hunter2\""
	rep := CensorReport(&findings.RiskReport{Findings: []findings.Finding{{
		Type: "Password", RuleID: "generic-password",
		Severity: findings.SeverityCritical, Confidence: 0.7,
		File: "a.py", Line: 1, Column: 1, Value: "hunter2hunter2",
		Action: findings.ActionBlock, Reason: "r",
		SourceLine: raw,
		Context:    "> " + raw + "\n  \n",
	}}})
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

// The disclosure ladder, end to end, at the layer that owns it. WriteText
// renders what it is given; CensorReport is what removes secrets, and it does
// so once.
//
// Two findings about one secret must agree on its token. Before the engine
// stopped blanking redact-action values to the constant "<REDACTED>", every
// redacted finding in every file hashed that same literal, so a reader could
// not distinguish "the same secret in two places" from "two different secrets
// that were both redacted".
func TestCensorReportIsTheSingleBoundaryAndCorrelatesValues(t *testing.T) {
	const secret = "s3cr3t-value-abcdef123456"
	line := "token = \"" + secret + "\""

	rep := &findings.RiskReport{Findings: []findings.Finding{
		{File: "a.env", Line: 1, Value: secret, SourceLine: line, Context: "> " + line + "\n"},
		{File: "b.env", Line: 9, Value: secret, SourceLine: line, Context: "> " + line + "\n"},
		{File: "c.env", Line: 3, Value: "other-value-9876543210", SourceLine: line, Context: "> " + line + "\n"},
	}}
	got := CensorReport(rep)

	if got.Findings[0].Value != got.Findings[1].Value {
		t.Errorf("one secret produced two tokens: %q and %q",
			got.Findings[0].Value, got.Findings[1].Value)
	}
	if got.Findings[0].Value == got.Findings[2].Value {
		t.Error("two different secrets produced the same token")
	}
	for i, f := range got.Findings {
		if strings.Contains(f.SourceLine, secret) || strings.Contains(f.Context, secret) {
			t.Errorf("finding %d leaked the secret:\n%q / %q", i, f.SourceLine, f.Context)
		}
	}

	// CensorReport must be idempotent: calling it again (a caller that censors
	// defensively, a second format, a retry) must not change anything.
	again := CensorReport(got)
	for i := range got.Findings {
		if !reflect.DeepEqual(again.Findings[i], got.Findings[i]) {
			t.Errorf("finding %d changed on a second censoring pass:\nbefore %+v\nafter  %+v",
				i, got.Findings[i], again.Findings[i])
		}
	}
}

// WriteText must not censor. It is the reason --dangerously-show-secrets works:
// the flag causes the caller to skip CensorReport, and a renderer that censored
// anyway would silently undo the opt-in.
func TestWriteTextRendersRawValuesWhenAskedTo(t *testing.T) {
	const secret = "hunter2hunter2"
	raw := "const password = \"" + secret + "\""
	rep := &findings.RiskReport{Findings: []findings.Finding{{
		Type: "Password", RuleID: "generic-password",
		Severity: findings.SeverityCritical, Confidence: 0.7,
		File: "a.py", Line: 1, Value: secret, Action: findings.ActionRedact,
		Reason: "r", SourceLine: raw, Context: "> " + raw + "\n",
	}}}

	var buf bytes.Buffer
	if err := WriteText(&buf, rep, TextOptions{Snippets: true, ShowRawValues: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), secret) {
		t.Errorf("--dangerously-show-secrets must reveal the value:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "redact: value hidden") {
		t.Error("the legend must not claim a value is hidden while showing it")
	}
}
