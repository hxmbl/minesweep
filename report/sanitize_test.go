package report

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

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

// #27: the C1 range is the 8-bit spelling of the same controls. U+009B is CSI,
// U+009D is OSC, U+0090 is DCS. They survive a UTF-8 decoder untouched, so
// neutralising only the 7-bit ESC form left the injection intact. U+0085 and
// U+2028/U+2029 break the report into forged lines with no escape sequence at
// all.
func TestSanitizeTerminalEscapesC1AndLineSeparators(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"CSI", "bad\u009b31mFAKE", `bad^[[31mFAKE`},
		// OSC 8 hyperlink: introducer, payload, ST terminator. Built from the
		// same arithmetic SanitizeTerminal uses so the expectation cannot
		// drift from the implementation.
		{"OSC", "x\u009d]8;;http://evil\u009c",
			"x^[" + string(rune(0x9d-0x40)) + "]8;;http://evil" + "^[\\"},
		{"DCS", "a\u0090b", "a^[Pb"},
		{"APC", "a\u009fb", "a^[_b"},
		{"SOS", "a\u0098b", "a^[Xb"},
		{"PM", "a\u009eb", "a^[^b"},
		{"NEL", "a\u0085b", "a^[Eb"},
		{"LS", "a b", `a\u2028b`},
		{"PS", "a b", `a\u2029b`},
	}
	for _, c := range cases {
		if got := SanitizeTerminal(c.in); got != c.want {
			t.Errorf("%s: SanitizeTerminal(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// No raw control byte of any kind may survive.
func TestSanitizeTerminalLeavesNoControlBytes(t *testing.T) {
	dirty := "a\u009b]\u0090\u0098\u009e\u009f\u0085b" +
		"c  d" + "\x1b" + "e"
	got := SanitizeTerminal(dirty)
	for _, r := range got {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) ||
			r == 0x2028 || r == 0x2029 {
			t.Errorf("SanitizeTerminal left control byte %U in %q", r, got)
		}
	}
}

// Sanitizing is idempotent, so a value that passes through more than one print
// site is not progressively mangled.
func TestSanitizeTerminalIsIdempotent(t *testing.T) {
	dirty := "bad\u009b31mFAKE\u0085tail"
	once := SanitizeTerminal(dirty)
	if twice := SanitizeTerminal(once); twice != once {
		t.Errorf("not idempotent:\n once:  %q\n twice: %q", once, twice)
	}
}

// #26: with the default --color auto and output redirected to a file, the
// snippet still emitted raw ANSI while every other colour was suppressed.
func TestHighlightIfEnabledRespectsResolvedColour(t *testing.T) {
	line := `key = "AKIAIOSFODNN7EXAMPLE"`
	if got := highlightIfEnabled(palette{enabled: false}, line, "env"); got != line {
		t.Errorf("colour disabled but output was highlighted: %q", got)
	}
	if got := highlightIfEnabled(palette{enabled: true}, line, "env"); !strings.Contains(got, "\x1b") {
		t.Errorf("colour enabled but no highlighting applied: %q", got)
	}
}

// #2f: the same secret must carry the same token in the Value line and in the
// snippet below it. Re-hashing an already-hashed token printed sha256:78314b11be2e
// in one place and sha256:331c0859e192 two lines later.
func TestCensorFindingKeepsTokenConsistentWithEvidence(t *testing.T) {
	const secret = "P@ssw0rd$ecret!2024"
	f := findings.Finding{
		RuleID:     "env-password",
		Value:      "admin_password=" + secret,
		SourceLine: "admin_password=" + secret,
		Context:    "> admin_password=" + secret + "\n",
	}
	got := CensorFinding(f)
	if strings.Contains(got.SourceLine, secret) || strings.Contains(got.Context, secret) {
		t.Errorf("evidence leaked the secret: %q / %q", got.SourceLine, got.Context)
	}
	if !strings.Contains(got.SourceLine, got.Value) {
		t.Errorf("Value token %q does not appear in the snippet %q", got.Value, got.SourceLine)
	}
	if strings.Contains(got.SourceLine, "sha256:sha256:") {
		t.Errorf("token was hashed twice: %q", got.SourceLine)
	}
	if !strings.Contains(got.SourceLine, "admin_password=") {
		t.Errorf("censoring destroyed the key name: %q", got.SourceLine)
	}
}

// #2e: a value that already looks like a token used to switch censoring off for
// the whole finding, leaving the snippet untouched.
func TestCensorFindingStillCensorsEvidenceForTokenShapedValue(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01"
	f := findings.Finding{
		RuleID:     "entropy-high",
		Value:      findings.SecretToken(secret),
		SourceLine: "aws_secret_access_key = " + secret,
		Context:    "> aws_secret_access_key = " + secret + "\n",
	}
	got := CensorFinding(f)
	if strings.Contains(got.SourceLine, secret) || strings.Contains(got.Context, secret) {
		t.Errorf("evidence leaked despite a token-shaped value: %q / %q", got.SourceLine, got.Context)
	}
	if strings.Contains(got.SourceLine, "sha256:sha256:") {
		t.Errorf("token was hashed twice: %q", got.SourceLine)
	}
}

// #14: a field that must occupy one line. SanitizeTerminal deliberately keeps \n
// and \t because a context block needs them, which meant a file name, a git
// author or a commit subject could forge whole report blocks. Those strings come
// from the repository and from git metadata, not from the scanner.
func TestSanitizeLineNeutralisesLineBreaks(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a\nb", `a\nb`},
		{"a\rb", `a\rb`},
		{"a\tb", `a\tb`},
		{"a\r\nb", `a\r\nb`},
		{"a\u2028b", `a\u2028b`}, // line separator
		{"a\u2029b", `a\u2029b`}, // paragraph separator
		{"a\u0085b", "a^[Eb"},    // NEL
		{"a\x1bb", `a\eb`},       // ESC
		{"a\u009bb", "a^[[b"},    // C1 CSI
		{"plain/path.env", "plain/path.env"},
		{"", ""},
	}
	for _, c := range cases {
		if got := SanitizeLine(c.in); got != c.want {
			t.Errorf("SanitizeLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The forged-finding case end to end: an author name and a commit summary must
// not be able to clear the screen or plant a clickable link.
func TestGitMetadataCannotForgeTerminalOutput(t *testing.T) {
	f := findings.Finding{
		Type:          "AWS Secret Access Key",
		RuleID:        "aws-secret-key",
		Severity:      findings.SeverityCritical,
		Confidence:    0.95,
		File:          "a.env",
		Line:          1,
		Author:        "Alice \x1b[31mRED\x1b[0m\x1b]8;;http://evil.example\x1b\\CLICK",
		CommitSummary: "add creds \x1b[2J\x1b[31mFAKE-CRITICAL: 1 critical finding\x1b[0m",
		Context:       "> a.env:1",
	}
	var buf bytes.Buffer
	opts := TextOptions{Verbose: true, Snippets: false, Color: ColorNever}
	if err := WriteText(&buf, &findings.RiskReport{Findings: []findings.Finding{f}}, opts); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Errorf("raw ESC reached the report:\n%q", out)
	}
	// The forged text still appears, but only as inert characters after a \e
	// escape: neutralising a payload must not mean deleting evidence of it.
	if !strings.Contains(out, "FAKE-CRITICAL") {
		t.Error("the commit summary text should still be visible, escaped")
	}
	for _, want := range []string{`Alice \e[31mRED`, `\e]8;;http://evil.example`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q to appear escaped, got:\n%s", want, out)
		}
	}
}

// SkippedBy echoes file names and prints on a CLEAN scan, before any secret is
// found, so it is the widest-reaching injection point of all.
func TestSkippedByNamesCannotForgeLines(t *testing.T) {
	rep := &findings.RiskReport{
		FilesSkipped: 1,
		SkippedBy:    []string{"1 extension: a\u001b[2J.env\n  ✓ SAFE TO SHARE"},
	}
	var buf bytes.Buffer
	if err := WriteText(&buf, rep, TextOptions{Color: ColorNever}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Errorf("raw ESC reached the report:\n%q", out)
	}
	if strings.Contains(out, "\n  ✓ SAFE TO SHARE") {
		t.Error("a skipped file name forged a real line")
	}
	if !strings.Contains(out, `\n  ✓ SAFE TO SHARE`) {
		t.Errorf("expected the line break to be visible, got:\n%s", out)
	}
}

func TestDashboardSanitisesAndTruncatesOnRunes(t *testing.T) {
	d := GenerateDashboard(&findings.RiskReport{Findings: []findings.Finding{
		{RuleID: "r-very-long-rule-identifier-that-overflows", Type: "T\x1b]8;;evil", Severity: findings.SeverityLow, Confidence: 0.5, File: "a\nb.env"},
		{RuleID: "r-very-long-rule-identifier-that-overflows", Type: "T\x1b]8;;evil", Severity: findings.SeverityCritical, Confidence: 0.9, File: "c.env"},
	}})
	var buf bytes.Buffer
	if err := WriteDashboard(&buf, d, true); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Errorf("raw ESC reached the dashboard:\n%q", out)
	}
	if !strings.Contains(out, `\e]8;;evil`) {
		t.Errorf("expected the OSC sequence escaped, got:\n%s", out)
	}
	if !strings.Contains(out, `a\nb.env`) {
		t.Errorf("expected the file name's line break visible, got:\n%s", out)
	}
	if !utf8.ValidString(out) {
		t.Error("dashboard emitted invalid UTF-8 (a rune was split by truncation)")
	}
	// The rule's severity must be the worst one it produced, not whichever
	// finding happened to be first.
	if d.Rules[0].Severity != findings.SeverityCritical {
		t.Errorf("rule severity = %v, want critical", d.Rules[0].Severity)
	}
}
