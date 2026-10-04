package findings

import "testing"

// Class-level suppression. The reviewer's point was that the only escape hatch
// was per-finding baseline acceptance, which spends a budget that does not grow
// and cannot express a class — so a rule that recurs by construction had to be
// paid for one occurrence at a time.
func TestSuppressionByRuleIDAlone(t *testing.T) {
	in := []Finding{
		{RuleID: "env-password", File: "a.env", Value: "one"},
		{RuleID: "env-password", File: "b.env", Value: "two"},
		{RuleID: "env-token", File: "c.env", Value: "three"},
	}
	got := FilterSuppressed(in, &SuppressionList{Suppression: []Suppression{
		{ID: "noisy rule", RuleID: "env-password"},
	}})
	if len(got) != 1 || got[0].RuleID != "env-token" {
		t.Errorf("got %d findings, want only env-token: %+v", len(got), got)
	}
}

func TestSuppressionByTag(t *testing.T) {
	in := []Finding{
		{RuleID: "postgres-uri", Tags: []string{"database", "credentials"}, File: "a.go"},
		{RuleID: "aws-key", Tags: []string{"cloud", "credentials"}, File: "b.go"},
		{RuleID: "plain", Tags: []string{"misc"}, File: "c.go"},
	}
	got := FilterSuppressed(in, &SuppressionList{Suppression: []Suppression{
		{ID: "db", Tags: []string{"database"}},
	}})
	if len(got) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(got), got)
	}
	for _, f := range got {
		if f.RuleID == "postgres-uri" {
			t.Error("a finding tagged database survived a database suppression")
		}
	}
}

func TestSuppressionByPathGlob(t *testing.T) {
	in := []Finding{
		{RuleID: "r", File: "README.md"},
		{RuleID: "r", File: "docs/guide.md"},
		{RuleID: "r", File: "docs/nested/deep/setup.md"},
		{RuleID: "r", File: "docs/guide.rst"},
		{RuleID: "r", File: "src/main.go"},
	}
	cases := []struct {
		pattern string
		want    []string // survivors, in input order
	}{
		{"**/*.md", []string{"docs/guide.rst", "src/main.go"}},
		// A separator-free wildcard matches at any depth, because path.Match
		// will not let * cross a separator and *.md is what people write.
		{"*.md", []string{"docs/guide.rst", "src/main.go"}},
		{"docs/**", []string{"README.md", "src/main.go"}},
		// A single * does not cross a separator, so the nested file survives.
		{"docs/*", []string{"README.md", "docs/nested/deep/setup.md", "src/main.go"}},
		{"docs/nested/**", []string{"README.md", "docs/guide.md", "docs/guide.rst", "src/main.go"}},
		{"**/setup.md", []string{"README.md", "docs/guide.md", "docs/guide.rst", "src/main.go"}},
	}
	for _, tc := range cases {
		got := FilterSuppressed(in, &SuppressionList{Suppression: []Suppression{
			{ID: tc.pattern, File: tc.pattern},
		}})
		var names []string
		for _, f := range got {
			names = append(names, f.File)
		}
		if len(names) != len(tc.want) {
			t.Errorf("%q left %v, want %v", tc.pattern, names, tc.want)
			continue
		}
		for i := range names {
			if names[i] != tc.want[i] {
				t.Errorf("%q left %v, want %v", tc.pattern, names, tc.want)
				break
			}
		}
	}
}

// A history-mode finding carries an "@sha12" suffix on its path. A suppression
// written against the working-tree path must still match it, exactly as it did
// before globs existed.
func TestSuppressionPathGlobMatchesHistoryPaths(t *testing.T) {
	in := []Finding{{RuleID: "r", File: "docs/guide.md@a1b2c3d4e5f6"}}
	for _, pattern := range []string{"docs/**", "**/*.md", "*.md"} {
		got := FilterSuppressed(in, &SuppressionList{Suppression: []Suppression{
			{ID: pattern, File: pattern},
		}})
		if len(got) != 0 {
			t.Errorf("a history-mode path was not matched by %q: %+v", pattern, got)
		}
	}
}

// A File with no wildcard keeps its exact-match meaning, so an existing
// suppression file behaves identically after globs were added. Note that this
// means `README.md` does not match `docs/README.md`: that was true before, and
// changing it would silently widen every existing suppression.
func TestSuppressionExactPathIsUnchanged(t *testing.T) {
	in := []Finding{
		{RuleID: "r", File: "README.md"},
		{RuleID: "r", File: "docs/README.md"},
		{RuleID: "r", File: "notes.md"},
	}
	got := FilterSuppressed(in, &SuppressionList{Suppression: []Suppression{
		{ID: "readme", File: "README.md"},
	}})
	if len(got) != 2 || got[0].File != "docs/README.md" || got[1].File != "notes.md" {
		t.Errorf("exact matching changed: %+v", got)
	}
}

// Multiple populated fields are an intersection, which is what makes a narrow
// suppression expressible: "env-password, but only under docs/". Both
// non-matching findings must survive — the one outside docs/, and the one from a
// different rule inside it.
func TestSuppressionFieldsIntersect(t *testing.T) {
	in := []Finding{
		{RuleID: "env-password", File: "docs/a.env"},
		{RuleID: "env-password", File: "src/a.env"},
		{RuleID: "env-token", File: "docs/a.env"},
	}
	got := FilterSuppressed(in, &SuppressionList{Suppression: []Suppression{
		{ID: "narrow", RuleID: "env-password", File: "docs/**"},
	}})
	want := []string{"src/a.env", "docs/a.env"}
	if len(got) != len(want) {
		t.Fatalf("got %d survivors, want %d: %+v", len(got), len(want), got)
	}
	for i, f := range got {
		if f.File != want[i] {
			t.Errorf("survivor %d = %s, want %s", i, f.File, want[i])
		}
	}
}

// An entry with nothing populated must not match everything. A malformed entry
// that silently suppressed the whole report would be worse than no entry.
func TestSuppressionEmptyEntrySuppressesNothing(t *testing.T) {
	in := []Finding{{RuleID: "r", File: "a.env", Value: "v"}}
	got := FilterSuppressed(in, &SuppressionList{Suppression: []Suppression{{ID: "empty"}}})
	if len(got) != 1 {
		t.Errorf("an empty suppression entry removed a finding: %+v", got)
	}
}

// A malformed glob must not match, and must not panic. Note that `***` is *not*
// malformed — three stars are three consecutive wildcards, which is a legal and
// unremarkable glob.
func TestSuppressionMalformedGlobMatchesNothing(t *testing.T) {
	in := []Finding{{RuleID: "r", File: "a.env"}}
	for _, bad := range []string{"[", "a[", "docs/[/x"} {
		got := FilterSuppressed(in, &SuppressionList{Suppression: []Suppression{{File: bad}}})
		if len(got) != 1 {
			t.Errorf("glob %q matched something: %+v", bad, got)
		}
	}
}
