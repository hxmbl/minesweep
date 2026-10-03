package detectors

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRuleFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// #21: mergeRules only applied ACROSS sources, never WITHIN one directory, so a
// rules directory could not override a rule. Two files defining the same ID both
// stayed live and the scan reported whichever was evaluated first -- which kills
// the main reason to ship a rules directory, namely tuning a noisy rule down.
//
// Last file wins, and fs.ReadDir returns names sorted, so filename ordering
// expresses precedence.
func TestRuleOverrideWithinOneDirectory(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "10-base.yml",
		"rules:\n  - id: dup-rule\n    type: regex\n    name: BASE version\n    description: d\n"+
			"    severity: high\n    tags: [x]\n    patterns:\n      - regex: DUP_[A-Z]{4}\n        confidence: 0.90\n")
	writeRuleFile(t, dir, "20-override.yml",
		"rules:\n  - id: dup-rule\n    type: regex\n    name: OVERRIDE version\n    description: d\n"+
			"    severity: low\n    tags: [x]\n    patterns:\n      - regex: DUP_[A-Z]{4}\n        confidence: 0.10\n")

	rd, err := NewRegexDetector(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	for _, r := range rd.Rules() {
		if r.ID == "dup-rule" {
			n++
			if r.Name != "OVERRIDE version" {
				t.Errorf("dup-rule = %q, want the later file to win", r.Name)
			}
			if r.Severity != "low" {
				t.Errorf("dup-rule severity = %q, want low", r.Severity)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d live definitions of dup-rule, want 1", n)
	}
}

func TestDedupeByIDKeepsLastAndStableOrder(t *testing.T) {
	in := []Rule{
		{ID: "a", Name: "a1"}, {ID: "b", Name: "b1"}, {ID: "a", Name: "a2"}, {ID: "c", Name: "c1"},
	}
	out := dedupeByID(in)
	if len(out) != 3 {
		t.Fatalf("got %d rules, want 3: %+v", len(out), out)
	}
	want := []struct{ id, name string }{{"a", "a2"}, {"b", "b1"}, {"c", "c1"}}
	for i, w := range want {
		if out[i].ID != w.id || out[i].Name != w.name {
			t.Errorf("out[%d] = %s/%s, want %s/%s", i, out[i].ID, out[i].Name, w.id, w.name)
		}
	}
}

// #30: a typo'd or unknown key used to parse into a zero value, producing a rule
// that silently never fired -- confidnce: 0.9 became 0.0, below the confidence
// floor, with zero output and zero warnings. Severity was already validated
// loudly; keys are now held to the same standard.
//
// A directory of rule files warns and skips the offending file, matching how
// every other per-file problem there is handled. An explicit single --rules file
// is fatal, because that one file is the whole request.
func TestUnknownRuleKeyIsRejected(t *testing.T) {
	cases := []struct{ name, body string }{
		{
			name: "typo'd confidence",
			body: "rules:\n  - id: t\n    type: regex\n    name: T\n    description: d\n    severity: high\n    tags: [x]\n" +
				"    patterns:\n      - regex: X_[A-Z]{4}\n        confidnce: 0.9\n",
		},
		{
			name: "misspelled file_filter",
			body: "rules:\n  - id: t\n    type: regex\n    name: T\n    description: d\n    severity: high\n    tags: [x]\n" +
				"    filefilter: \"*.go\"\n    patterns:\n      - regex: X_[A-Z]{4}\n        confidence: 0.9\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRuleFile(t, dir, "r.yml", tc.body)

			rules, err := loadRules(dir, "regex")
			if err != nil {
				t.Fatalf("loadRules: %v", err)
			}
			for _, r := range rules {
				if r.ID == "t" {
					t.Errorf("a rule with %s was loaded; it would silently never fire: %+v", tc.name, r)
				}
			}

			single := filepath.Join(dir, "r.yml")
			if _, err := loadRulesFile(single, "regex"); err == nil {
				t.Errorf("an explicit --rules %s must be a hard error", single)
			}
		})
	}
}

// An out-of-range confidence is a mistake, not a value: 0.9 out of range would
// sit in the rule looking loaded and match nothing at scan time.
func TestOutOfRangeConfidenceDisablesThePattern(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, dir, "r.yml",
		"rules:\n  - id: t\n    type: regex\n    name: T\n    description: d\n    severity: high\n    tags: [x]\n"+
			"    patterns:\n      - regex: X_[A-Z]{4}\n        confidence: 9.0\n")
	rules, err := loadRules(dir, "regex")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.ID == "t" && len(r.Patterns) != 0 {
			t.Errorf("a rule with no usable pattern was kept: %+v", r)
		}
	}
	// The rule must not be loadable at all as an effective rule.
	rd, err := NewRegexDetector(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rd.Rules() {
		if r.ID == "t" {
			t.Errorf("rule with an out-of-range confidence is live: %+v", r)
		}
	}
}
