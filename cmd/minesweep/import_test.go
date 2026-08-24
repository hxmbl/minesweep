package main

import (
	"os"
	"path/filepath"
	"testing"

	"minesweep/findings"
)

func TestParseGitleaksIgnoreLine(t *testing.T) {
	cases := []struct {
		line    string
		wantNil bool
		file    string
		lineNum int
		ruleID  string
	}{
		{"abc123def456:src/config.py:14", false, "src/config.py", 14, ""},
		{"abc123def456:src/config.py:aws-access-token:14", false, "src/config.py", 14, "aws-access-token"},
		{"# comment", true, "", 0, ""},
		{"", true, "", 0, ""},
		{"garbage-line", true, "", 0, ""},
		{"sha:path:notanumber", true, "", 0, ""},
		{"sha:path:rule:zero", true, "", 0, ""},
	}
	for _, c := range cases {
		got := parseGitleaksIgnoreLine(c.line)
		if c.wantNil {
			if got != nil {
				t.Errorf("parse(%q) = %+v, want nil", c.line, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("parse(%q) = nil, want entry", c.line)
			continue
		}
		if got.File != c.file || got.Line != c.lineNum || got.RuleID != c.ruleID {
			t.Errorf("parse(%q) = %+v, want file=%s line=%d rule=%q", c.line, got, c.file, c.lineNum, c.ruleID)
		}
	}
}

func TestRunImportIgnoresEndToEnd(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, ".gitleaksignore")
	content := `# migrated triage
2f6c98b0e955:configs/prod.go:12
9a1b2c3d4e5f:configs/dev.go:generic-api-key:30
not-a-valid-entry
`
	os.WriteFile(in, []byte(content), 0644)

	out := filepath.Join(dir, "suppress.json")
	if err := runImportIgnores(in, out); err != nil {
		t.Fatal(err)
	}

	list, err := findings.LoadSuppressions(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Suppression) != 2 {
		t.Fatalf("got %d suppressions, want 2: %+v", len(list.Suppression), list.Suppression)
	}
	first := list.Suppression[0]
	if first.File != "configs/prod.go" || first.Line != 12 || first.RuleID != "" {
		t.Errorf("classic layout mismatch: %+v", first)
	}
	second := list.Suppression[1]
	if second.RuleID != "generic-api-key" || second.Line != 30 {
		t.Errorf("fingerprint layout mismatch: %+v", second)
	}
}

func TestSuppressionLineScoping(t *testing.T) {
	fs := []findings.Finding{
		{RuleID: "r1", File: "a.go", Line: 10},
		{RuleID: "r1", File: "a.go", Line: 99},
		{RuleID: "r2", File: "b.go", Line: 10},
	}
	list := &findings.SuppressionList{
		Version: "1",
		Suppression: []findings.Suppression{
			{ID: "one", File: "a.go", Line: 10},
		},
	}
	out := findings.FilterSuppressed(fs, list)
	if len(out) != 2 {
		t.Fatalf("line-scoped suppression removed %d, want exactly 1 removed", len(fs)-len(out))
	}
	for _, f := range out {
		if f.File == "a.go" && f.Line == 10 {
			t.Error("suppressed finding survived")
		}
	}
}

func TestSuppressionCombinedFieldsAreAND(t *testing.T) {
	fs := []findings.Finding{
		{RuleID: "r1", File: "a.go", Line: 1},
		{RuleID: "r2", File: "a.go", Line: 1},
		{RuleID: "r1", File: "other.go", Line: 1},
	}
	list := &findings.SuppressionList{
		Version:     "1",
		Suppression: []findings.Suppression{{ID: "x", RuleID: "r1", File: "a.go"}},
	}
	out := findings.FilterSuppressed(fs, list)
	if len(out) != 2 {
		t.Fatalf("combined rule_id+file must require both; got %d remaining", len(out))
	}
}

func TestSuppressionSingleFieldSemanticsUnchanged(t *testing.T) {
	fs := []findings.Finding{
		{RuleID: "r1", File: "anywhere.go"},
	}
	cases := []findings.SuppressionList{
		{Version: "1", Suppression: []findings.Suppression{{ID: "a", RuleID: "r1"}}},
		{Version: "1", Suppression: []findings.Suppression{{ID: "b", File: "anywhere.go"}}},
		{Version: "1", Suppression: []findings.Suppression{{ID: "c", Pattern: "anywhere"}}},
	}
	for i := range cases {
		out := findings.FilterSuppressed(fs, &cases[i])
		if len(out) != 0 {
			t.Errorf("case %d: single-field suppression regressed", i)
		}
	}
}
