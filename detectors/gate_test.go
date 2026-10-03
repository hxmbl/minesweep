package detectors

import (
	"bytes"
	"testing"

	"minesweep/filesystem"
)

func TestExtractLiteralGateBasicLiterals(t *testing.T) {
	cases := []struct {
		pattern string
		wantNil bool
	}{
		{`\b(AKIA[0-9A-Z]{16})\b`, false},
		{`[A-Za-z0-9+/]{20,}={0,2}`, true},
		{`^\d{12}$`, true},
	}
	for _, c := range cases {
		g := extractLiteralGate(c.pattern)
		if c.wantNil && g != nil {
			t.Errorf("pattern %q: expected no gate, got %v", c.pattern, g)
		}
		if !c.wantNil && g == nil {
			t.Errorf("pattern %q: expected gate, got nil", c.pattern)
		}
	}
}

func TestGateSoundnessNeverBlocksRealMatches(t *testing.T) {
	cases := []struct {
		pattern string
		input   string
	}{
		{`\b(AKIA[0-9A-Z]{16})\b`, "key = AKIAIOSFODNN7EXAMPLE here"},
		{`(?i)postgres(?:ql)?://([^:\s]+):([^@\s]+)@[^\s]+`, "POSTGRES://u:p@h/db"},
		{`(?i)(?:db|database)[_-]?(?:user|pwd|password)\s*[:=]\s*\S+`, "DB_PASSWORD=hunter2"},
		{`(foo|bar)+baz`, "barbarbaz"},
		{`prefix.*suffix`, "xx prefix middle suffix yy"},
		{`(?:opt)?required`, "required"},
		{`a+b+c+`, "xaaabbbcccx"},
	}
	for _, c := range cases {
		g := extractLiteralGate(c.pattern)
		if g == nil {
			continue
		}
		lowered := []byte(lowerASCII(c.input))
		if !g.satisfied([]byte(c.input), lowered) {
			t.Errorf("gate for %q wrongly rejects matching input %q (gate=%v)", c.pattern, c.input, g)
		}
	}
}

func TestGateRejectsNonMatching(t *testing.T) {
	g := extractLiteralGate(`\bAKIA[0-9A-Z]{16}\b`)
	if g == nil {
		t.Fatal("expected gate")
	}
	in := []byte("nothing to see here, move along")
	if g.satisfied(in, in) {
		t.Fatal("gate should reject input without literal")
	}
}

func TestGateFoldedLiteralCaseNormalization(t *testing.T) {
	g := extractLiteralGate(`(?i)postgres(ql)?://`)
	if g == nil {
		t.Fatal("expected gate")
	}
	content := []byte("URL=PostGreS://host")
	lowered := filesystem.FoldLower(content)
	if !g.satisfied(content, lowered) {
		t.Fatal("folded gate must match mixed-case input via lowered haystack")
	}
}

// The gate must keep its full precision for a fold-safe literal: 'postgres'
// contains 's', which used to force the gate to degrade to '://' only.
func TestGateFoldedLiteralKeepsFullWord(t *testing.T) {
	g := extractLiteralGate(`(?i)postgres(ql)?://`)
	if g == nil {
		t.Fatal("expected gate")
	}
	in := []byte("nothing relevant here")
	if g.satisfied(in, filesystem.FoldLower(in)) {
		t.Error("gate accepted input with no postgres literal; it degraded to '://' only")
	}
}

// Regression (#1): 's' and 'k' each share a Unicode simple-fold orbit with a
// non-ASCII rune (U+017F LONG S, U+212A KELVIN SIGN). Because FoldLower folds
// those content runes onto the ASCII letter too, a gate for a literal containing
// s or k is still sound — and must be KEPT, because dropping it costs a full
// regex execution on every file in the tree.
//
// Only a literal rune with no ASCII member in its orbit has to be refused.
func TestGateKeepsFoldOrbitEscapingLiterals(t *testing.T) {
	for _, lit := range []string{"secret", "password", "aws_secret_access_key", "key", "monkey", "sk", "SESSION_TOKEN"} {
		if _, ok := asciiFoldLiteral(lit); !ok {
			t.Errorf("asciiFoldLiteral(%q) rejected a literal whose orbit FoldLower also folds to ASCII", lit)
		}
	}
	for _, lit := range []string{"credential", "auth", "jwt", "gcp", "oauth", "bearer", "region"} {
		if _, ok := asciiFoldLiteral(lit); !ok {
			t.Errorf("asciiFoldLiteral(%q) rejected an ASCII-only fold orbit", lit)
		}
	}
	for _, lit := range []string{"ARN", "AKIA", "Postgres"} {
		got, ok := asciiFoldLiteral(lit)
		if !ok {
			t.Errorf("asciiFoldLiteral(%q) rejected a fold-safe ASCII literal", lit)
			continue
		}
		if got != lowerASCII(lit) {
			t.Errorf("asciiFoldLiteral(%q) = %q, want %q", lit, got, lowerASCII(lit))
		}
	}
	// Non-ASCII literals have no ASCII fold member, so no sound ASCII needle
	// exists for them and the gate must be declined rather than guessed at.
	for _, lit := range []string{"clé", "Ω", "naïve"} {
		if _, ok := asciiFoldLiteral(lit); ok {
			t.Errorf("asciiFoldLiteral(%q) accepted a non-ASCII literal with no ASCII fold member", lit)
		}
	}
}

// Homoglyph spellings are assembled from named constants rather than written as
// \u escapes inline: Go reads exactly four hex digits after \u, so "\u017ecret"
// silently parses as U+017E followed by "cret" and the test stops testing what
// it claims to.
const (
	longS  = "\u017f" // LATIN SMALL LETTER LONG S, folds to 's'
	kelvin = "\u212a" // KELVIN SIGN, folds to 'k'
)

// The fold-aware haystack is what makes the previous test meaningful: the ASCII
// needle has to actually be present in the folded content when the regexp engine
// would match the homoglyph spelling.
func TestFoldedHaystackRescuesFoldOrbitHomoglyphs(t *testing.T) {
	cases := []struct{ lit, input string }{
		{"secret", "aw" + longS + "_" + longS + "ecret_acce" + longS + longS + "_key=x"},
		{"password", "pa" + longS + longS + "word=x"},
		{"key", "api_" + kelvin + "ey=x"},
		{"aws_secret_access_key", "AWS_" + longS + "ecret_acce" + longS + longS + "_" + kelvin + "EY=x"},
	}
	for _, c := range cases {
		needle, ok := asciiFoldLiteral(c.lit)
		if !ok {
			t.Fatalf("asciiFoldLiteral(%q) declined, cannot test haystack", c.lit)
		}
		hay := filesystem.FoldLower([]byte(c.input))
		if !bytes.Contains(hay, []byte(needle)) {
			t.Errorf("needle %q absent from folded haystack %q for input %q", needle, hay, c.input)
		}
	}
}

// End-to-end soundness: for every embedded rule, an input the regexp engine
// accepts must also satisfy the gate that rule derived. The homoglyph cases are
// the ones that previously produced silent false negatives.
func TestEmbeddedRulesGatesNeverRejectMatchingInput(t *testing.T) {
	rd, err := NewRegexDetector("") // embedded rules only
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	cases := []struct{ label, input string }{
		{"long s in password", "pa" + longS + longS + "word = \"Sup3rS3cretValue123\"\n"},
		{"long s in secret", "aw" + longS + "_" + longS + "ecret_acce" + longS + longS + "_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01\n"},
		{"kelvin in key", "API_" + kelvin + "EY=AKIAIOSFODNN7EXAMPLE\n"},
		{"kelvin in secret keyword", "AWS_" + kelvin + "ecret_acce" + longS + longS + "_" + kelvin + "EY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01\n"},
		{"plain password", "password = \"Sup3rS3cretValue123\"\n"},
		{"uppercase postgres", "POSTGRES://svc:pw@db.internal:5432/app\n"},
	}
	for _, c := range cases {
		content := []byte(c.input)
		lowered := filesystem.FoldLower(content)
		for _, r := range rd.Rules() {
			for _, p := range r.Patterns {
				if p.compiled == nil || p.gate == nil {
					continue
				}
				if p.compiled.Match(content) && !p.gate.satisfied(content, lowered) {
					t.Errorf("rule %q gate rejected input its own regexp matches (%s)", r.ID, c.label)
				}
			}
		}
	}
}

// lowerASCII mirrors production's haystack: filesystem.FoldLower, not
// bytes.ToLower. Tests must fold exactly the way the scanner does, or they
// assert against a haystack that never occurs at runtime.
func lowerASCII(s string) string {
	return string(filesystem.FoldLower([]byte(s)))
}

func TestLineIndexLineCol(t *testing.T) {
	content := []byte("ab\ncdef\n\ngh")
	li := filesystem.NewLineIndex(content)
	cases := []struct {
		pos  int
		line int
		col  int
	}{

		{0, 1, 1}, // 'a'
		{1, 1, 2}, // 'b'
		{3, 2, 1}, // 'c'
		{6, 2, 4}, // 'f'
		{7, 2, 5}, // newline ending line 2 (legacy convention)
		{8, 3, 1}, // empty line
		{9, 4, 1}, // 'g'
	}
	for _, c := range cases {
		line, col := li.LineCol(c.pos)
		if line != c.line || col != c.col {
			t.Errorf("lineCol(%d) = (%d,%d), want (%d,%d)", c.pos, line, col, c.line, c.col)
		}
	}
}

func TestLineIndexContextMatchesLegacyFormat(t *testing.T) {
	content := []byte("one\ntwo\nthree\nfour\nfive\n")
	li := filesystem.NewLineIndex(content)
	got := li.Context(2, 1)
	want := "  two\n> three\n  four\n"
	if got != want {
		t.Errorf("context = %q, want %q", got, want)
	}

	first := li.Context(0, 2)
	if first != "> one\n  two\n  three\n" {
		t.Errorf("edge context = %q", first)
	}
}

func TestLineIndexLineText(t *testing.T) {
	content := []byte("alpha\r\nbeta\ngamma")
	li := filesystem.NewLineIndex(content)
	if got := li.LineText(0); got != "alpha\r" {
		t.Errorf("lineText(0) = %q (raw text keeps \\r; callers TrimSpace)", got)
	}
	if got := li.LineText(2); got != "gamma" {
		t.Errorf("lineText(2) = %q", got)
	}
	if got := li.LineText(99); got != "" {
		t.Errorf("out-of-range lineText = %q", got)
	}
}

// Regression: an alternation branch without literal requirements (anchors,
// classes, $) previously caused sibling branches' literals to be demanded,
// producing false-negative gates. Real-world casualty: gitleaks'
// stripe-access-token pattern.
func TestGateAlternationWithRequirementFreeBranch(t *testing.T) {
	pattern := `\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)`
	g := extractLiteralGate(pattern)
	if g == nil {
		t.Fatal("expected a gate")
	}
	content := []byte(`key = "sk_test_AAAABBBBCCCCDDDDEEEEFFFF00"`)
	lowered := content
	if !g.satisfied(content, lowered) {
		t.Fatalf("gate wrongly rejects input that matches: %v", g)
	}
}

func TestGateAlternationAllBranchesRequired(t *testing.T) {
	// Every branch has literals, so at least one must appear.
	g := extractLiteralGate(`(foo|bar)baz`)
	if g == nil {
		t.Fatal("expected gate")
	}
	if !g.satisfied([]byte("xx foobaz yy"), nil) {
		t.Error("should pass when a branch literal present")
	}
	if g.satisfied([]byte("xx qux baz yy"), nil) {
		t.Error("should reject when no branch literal present")
	}
}
