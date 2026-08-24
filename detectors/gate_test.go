package detectors

import (
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
	lowered := []byte("url=postgres://host")
	if !g.satisfied(content, lowered) {
		t.Fatal("folded gate must match mixed-case input via lowered haystack")
	}
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
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
