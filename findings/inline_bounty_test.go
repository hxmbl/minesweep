package findings

import "testing"

// C3: a bare `# noqa`, `# nosec` or `# noscan` silenced every finding within
// three lines below it, in every scan mode including --diff on an untrusted
// pull request and --staged in the pre-commit hook. The content under
// examination was deciding whether it was examined.
func TestForeignLinterMarkersDoNotSuppress(t *testing.T) {
	foreign := []string{
		"# noqa",
		"#nosec",
		"# nosec(B101)",
		"# noscan",
		"// noqa",
		"//nolint:gosec",
		"  # noqa: E501",
		"# type: ignore  # noqa",
		"# secret: ignore",
		"# secrets: ignore",
		"// minesweep-ignore",
		"/* minesweep: ignore */",
	}
	for _, line := range foreign {
		if got := ParseInlineSuppression(line); got != nil {
			t.Errorf("%q suppressed a finding; only an explicit minesweep form may", line)
		}
	}
}

// The explicit form is the only one honoured, with and without rule IDs.
func TestExplicitMinesweepFormIsHonoured(t *testing.T) {
	cases := []struct {
		line string
		ids  []string
	}{
		{"# minesweep: ignore", nil},
		{"// minesweep: ignore", nil},
		{"#minesweep:ignore", nil},
		{"// minesweep: ignore ", nil},
		{"# minesweep: ignore(aws-access-key-id)", []string{"aws-access-key-id"}},
		{"# minesweep: ignore(aws-access-key-id, env-password)", []string{"aws-access-key-id", "env-password"}},
		{"# minesweep: ignore( aws-access-key-id , env-password )", []string{"aws-access-key-id", "env-password"}},
		{"# minesweep: ignore()", nil},
	}
	for _, c := range cases {
		got := ParseInlineSuppression(c.line)
		if got == nil {
			t.Errorf("%q was not recognised as a suppression", c.line)
			continue
		}
		if len(got.RuleIDs) != len(c.ids) {
			t.Errorf("%q: rule IDs = %v, want %v", c.line, got.RuleIDs, c.ids)
			continue
		}
		for i := range c.ids {
			if got.RuleIDs[i] != c.ids[i] {
				t.Errorf("%q: rule IDs = %v, want %v", c.line, got.RuleIDs, c.ids)
				break
			}
		}
	}
}

// A rule-scoped suppression must not silence a different rule on the same line.
func TestRuleScopedSuppressionIsNarrow(t *testing.T) {
	lines := []string{"header", "# minesweep: ignore(entropy-high)", "payload"}
	fs := []Finding{
		{RuleID: "entropy-high", Line: 3},
		{RuleID: "aws-access-key-id", Line: 3},
		{RuleID: "aws-access-key-id", Line: 2},
	}
	got := FilterInlineSuppressionsLines(fs, fakeLines(lines))
	if len(got) != 2 {
		t.Fatalf("expected 2 survivors, got %d", len(got))
	}
	for _, f := range got {
		if f.RuleID == "entropy-high" {
			t.Error("entropy-high should have been suppressed")
		}
	}
}

// Rule IDs come from user-authored YAML, so matching must be
// case-insensitive; a suppression that silently fails invites a cruder one.
func TestRuleScopedSuppressionIsCaseInsensitive(t *testing.T) {
	lines := []string{"# minesweep: ignore(AWS-Access-Key-Id)", "payload"}
	got := FilterInlineSuppressionsLines([]Finding{{RuleID: "aws-access-key-id", Line: 2}}, fakeLines(lines))
	if len(got) != 0 {
		t.Fatalf("case-differing rule ID was not matched: %+v", got)
	}
}

// Suppression reaches three lines above the finding, and no further.
func TestSuppressionWindow(t *testing.T) {
	lines := []string{"# minesweep: ignore", "a", "b", "c", "d"}
	// Line 4 is three lines below the marker: suppressed.
	// Line 5 is four lines below: not suppressed.
	got := FilterInlineSuppressionsLines([]Finding{
		{RuleID: "x", Line: 4},
		{RuleID: "y", Line: 5},
	}, fakeLines(lines))
	if len(got) != 1 || got[0].RuleID != "y" {
		t.Fatalf("window is wrong: %+v", got)
	}
}

// Suppression must survive an empty rule list and never panic on odd input.
func TestSuppressionEdgeCases(t *testing.T) {
	if got := FilterInlineSuppressionsLines(nil, fakeLines([]string{"a"})); got != nil {
		t.Fatal("nil input should return nil")
	}
	if got := ParseInlineSuppression(""); got != nil {
		t.Fatal("empty line is not a suppression")
	}
	// A finding on line 0 or past the end must be left alone, not suppressed
	// and not dropped.
	lines := []string{"# minesweep: ignore", "x"}
	got := FilterInlineSuppressionsLines([]Finding{{RuleID: "a", Line: 0}, {RuleID: "b", Line: 99}}, fakeLines(lines))
	if len(got) != 2 {
		t.Fatalf("out-of-range findings must survive: %+v", got)
	}
}

type fakeIndex struct{ lines []string }

func fakeLines(lines []string) LineLookup { return &fakeIndex{lines: lines} }

func (f *fakeIndex) LineCount() int { return len(f.lines) }
func (f *fakeIndex) LineText(i int) string {
	if i < 0 || i >= len(f.lines) {
		return ""
	}
	return f.lines[i]
}
