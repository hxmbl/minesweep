package detectors

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"minesweep/filesystem"
)

const sampleGitleaks = `
title = "team config"

[allowlist]
description = "global"
regexes = ['''EXAMPLE''']

[[rules]]
id = "aws-access-token"
description = "AWS access token"
regex = '''(AKIA|ASIA)[A-Z0-9]{16}'''
tags = ["aws", "token"]
keywords = ["akia"]

[[rules]]
id = "generic-api-key"
description = "Generic API key"
regex = '''(?i)(?:key|token)\s*[=:]\s*([a-z0-9]{16,})'''
secretGroup = 1
entropy = 3.0

[[rules]]
id = "ssh-private-key"
description = "Private key"
regex = '''-----BEGIN [A-Z ]*PRIVATE KEY-----'''

[[rules]]
id = "internal-slug"
description = "Internal identifier"
regex = '''internal_[a-z]{8}'''

[rules.allowlist]
paths = ['''(^|/)fixtures/''']
stopwords = ["sample", "dummy"]
condition = "OR"
`

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadGitleaksRulesTranslation(t *testing.T) {
	rules, err := LoadGitleaksRules([]byte(sampleGitleaks), "test.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(rules))
	}

	byID := map[string]Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}

	aws := byID["aws-access-token"]
	if aws.Severity != "high" || aws.Type != "regex" {
		t.Errorf("aws severity/type = %q/%q", aws.Severity, aws.Type)
	}
	if len(aws.Patterns) != 1 || aws.Patterns[0].CaptureGroup != 0 {
		t.Error("aws pattern mapping wrong")
	}
	hasProvenance := false
	for _, tag := range aws.Tags {
		if tag == "imported-gitleaks" {
			hasProvenance = true
		}
	}
	if !hasProvenance {
		t.Error("provenance tag missing")
	}

	generic := byID["generic-api-key"]
	if generic.Patterns[0].CaptureGroup != 1 {
		t.Errorf("secretGroup not mapped: %+v", generic.Patterns[0])
	}
	if generic.Patterns[0].MinEntropy != 3.0 {
		t.Errorf("entropy not mapped: %+v", generic.Patterns[0])
	}
	if generic.Severity != "medium" {
		t.Errorf("generic severity = %q", generic.Severity)
	}

	if byID["ssh-private-key"].Severity != "critical" {
		t.Errorf("private key should be critical")
	}
	if byID["internal-slug"].Severity != "medium" && byID["internal-slug"].Severity != "high" {
		t.Errorf("unrecognized id got implausible severity %q", byID["internal-slug"].Severity)
	}

	// Global allowlist attaches to rules without their own.
	if len(aws.Allowlist) != 1 {
		t.Errorf("global allowlist not attached to aws rule: %d blocks", len(aws.Allowlist))
	}
	// Per-rule allowlist keeps its own block alongside the global one.
	slug := byID["internal-slug"]
	if len(slug.Allowlist) != 2 {
		t.Fatalf("expected per-rule + global blocks, got %d", len(slug.Allowlist))
	}
	var hasStops, hasPaths bool
	for _, b := range slug.Allowlist {
		if len(b.stopwords) > 0 {
			hasStops = true
		}
		if len(b.pathRes) > 0 {
			hasPaths = true
		}
	}
	if !hasStops || !hasPaths {
		t.Errorf("block set lost categories: %+v", slug.Allowlist)
	}
}

func TestSeverityHeuristics(t *testing.T) {
	cases := map[string]string{
		"rsa-private-key":    "critical",
		"pkcs8-key":          "critical",
		"aws-access-token":   "high",
		"github-pat":         "high",
		"stripe-secret":      "high",
		"generic-api-key":    "medium",
		"generic-thing":      "medium",
		"totally-unknown-id": "high",
	}
	for id, want := range cases {
		if got := gitleaksSeverity(id); got != want {
			t.Errorf("gitleaksSeverity(%q) = %q, want %q", id, got, want)
		}
	}
}

func detectWithRule(t *testing.T, rule Rule, path, content string) int {
	t.Helper()
	rule.Type = "regex"
	for i := range rule.Patterns {
		if err := rule.Patterns[i].compile(); err != nil {
			t.Fatalf("pattern compile: %v", err)
		}
	}
	det := &RegexDetector{rules: []Rule{rule}}
	f := &filesystem.File{Path: path, Content: []byte(content), Size: int64(len(content)), Mode: 0644}
	return len(det.Detect(f))
}

func TestAllowlistEnforcementMatrix(t *testing.T) {
	base := Rule{
		ID: "t", Name: "T", Severity: "high",
		Patterns: []Pattern{{Regex: `(secret_[a-z0-9]+)`, Confidence: 0.9}},
	}
	content := "value = secret_abc123\n"

	compile := func(al *importedAllowlist) *Rule {
		r := base
		r.Allowlist = []*importedAllowlist{al}
		return &r
	}

	if n := detectWithRule(t, *compile(nil), "src/app.go", content); n == 0 {
		t.Fatal("baseline rule must match without allowlist")
	}

	// Path regex suppresses only matching paths.
	pathAL := compile(&importedAllowlist{pathRes: mustRes(`(^|/)fixtures/`)})
	if n := detectWithRule(t, *pathAL, "fixtures/a.go", content); n != 0 {
		t.Error("path allowlist should suppress in fixtures/")
	}
	if n := detectWithRule(t, *pathAL, "src/a.go", content); n == 0 {
		t.Error("path allowlist must not suppress elsewhere")
	}

	// Stopword on the secret value.
	stopAL := compile(&importedAllowlist{stopwords: []string{"abc123"}})
	if n := detectWithRule(t, *stopAL, "src/a.go", content); n != 0 {
		t.Error("stopword should suppress matching secret")
	}
	if n := detectWithRule(t, *compile(&importedAllowlist{stopwords: []string{"zzz"}}), "src/a.go", content); n == 0 {
		t.Error("non-matching stopword must not suppress")
	}

	// OR condition: any category hit suppresses.
	orAL := compile(&importedAllowlist{
		pathRes:   mustRes(`nomatch`),
		stopwords: []string{"abc123"},
	})
	if n := detectWithRule(t, *orAL, "src/a.go", content); n != 0 {
		t.Error("OR condition should suppress when any category matches")
	}

	// AND condition: all categories must hit; path misses so no suppression.
	andAL := compile(&importedAllowlist{
		pathRes:      mustRes(`nomatch`),
		stopwords:    []string{"abc123"},
		conditionAnd: true,
	})
	if n := detectWithRule(t, *andAL, "src/a.go", content); n == 0 {
		t.Error("AND condition requires every populated category to match")
	}

	andHit := compile(&importedAllowlist{
		pathRes:      mustRes(`^src/`),
		stopwords:    []string{"abc123"},
		conditionAnd: true,
	})
	if n := detectWithRule(t, *andHit, "src/a.go", content); n != 0 {
		t.Error("AND condition with all hits should suppress")
	}
}

func TestMinEntropyFiltering(t *testing.T) {
	high := Rule{
		ID: "e", Name: "E", Severity: "low",
		Patterns: []Pattern{{Regex: `[a-f0-9]{20,}`, Confidence: 0.9, MinEntropy: 3.5}},
	}
	lowEntropyLine := "hash = aaaaaaaaaaaaaaaaaaaa\n"
	highEntropyLine := "hash = f00dbabe5157c0ffee123456\n"

	if n := detectWithRule(t, high, "f.txt", lowEntropyLine); n != 0 {
		t.Error("low-entropy match must be filtered by min_entropy")
	}
	if n := detectWithRule(t, high, "f.txt", highEntropyLine); n == 0 {
		t.Error("high-entropy match must survive min_entropy")
	}
}

func TestLoadRulesDirPicksUpToml(t *testing.T) {
	dir := writeTemp(t, "leaks.toml", sampleGitleaks)
	det, err := NewRegexDetector(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range det.Rules() {
		if strings.HasPrefix(r.ID, "aws-access") {
			found = true
		}
	}
	if !found {
		t.Error("toml file in rules dir was not loaded")
	}
}

func mustRes(expr string) []*regexp.Regexp {
	return []*regexp.Regexp{regexp.MustCompile(expr)}
}

// Regression for the bounty finding: multiple [[rules.allowlists]] tables
// must be evaluated independently with their own conditions, never merged.
func TestMultiAllowlistTablesIndependent(t *testing.T) {
	rules, err := LoadGitleaksRules([]byte(`
[[rules]]
id = "x"
description = "x"
regex = '''secret_[a-z0-9]+'''

[[rules.allowlists]]
condition = "AND"
paths = ['''^src/''']
stopwords = ["nomatch"]

[[rules.allowlists]]
stopwords = ["zzzrealstop"]
`), "audit.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	rule := rules[0]
	if len(rule.Allowlist) != 2 {
		t.Fatalf("expected 2 independent blocks, got %d", len(rule.Allowlist))
	}

	detectAt := func(path, content string) int {
		rule.Type = "regex"
		for i := range rule.Patterns {
			if err := rule.Patterns[i].compile(); err != nil {
				t.Fatal(err)
			}
		}
		det := &RegexDetector{rules: []Rule{rule}}
		f := &filesystem.File{Path: path, Content: []byte(content), Size: int64(len(content)), Mode: 0644}
		return len(det.Detect(f))
	}

	// Case A: table1 AND unmet (stopword absent), table2 no match either.
	// Gitleaks keeps this finding; flattened merge wrongly suppressed it.
	if n := detectAt("src/a.go", "value = secret_abc123\n"); n == 0 {
		t.Error("case A must survive: neither independent table matches fully")
	}

	// Case B: table2 stopword present anywhere -> suppressed regardless of path.
	if n := detectAt("other/b.go", "value = secret_zzzrealstop42\n"); n != 0 {
		t.Error("case B must be suppressed by the second table's stopword")
	}

	// Case C: full AND satisfaction on table1 -> suppressed.
	if n := detectAt("src/c.go", "value = secret_nomatch99\n"); n != 0 {
		t.Error("case C must be suppressed: AND table fully satisfied")
	}
}

// #20: a gitleaks config found in the tree being scanned contributes its RULES
// but not its ALLOWLISTS. An allowlist only ever suppresses findings, so
// honouring one from the tree under inspection would let that tree silence its
// own secrets -- the same trust class as the max_file_size_mb hole.
//
// (The original note claimed the allowlist was broken when loaded. It is not:
// LoadGitleaksRules does honour it. The real defect was that nothing discovered
// the file at all, and that -r <file> was silently ignored, so a migrating user
// got neither rules nor allowlist without being told.)
func TestLoadGitleaksRulesDiscoveredIgnoresAllowlists(t *testing.T) {
	const cfg = `
title = "untrusted"

[allowlist]
paths = ['''^secrets/''']

[[rules]]
id = "demo-rule"
regex = '''DEMO_[A-Z0-9]{8}'''
secretGroup = 0
`
	rules, err := LoadGitleaksRules([]byte(cfg), ".gitleaks.toml", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected the rule to be loaded, got %d rules", len(rules))
	}
	if len(rules[0].Allowlist) != 0 {
		t.Errorf("discovered config carried %d allowlist block(s); an untrusted allowlist must be dropped",
			len(rules[0].Allowlist))
	}

	// The same config, explicitly named by the user, keeps its allowlist.
	trusted, err := LoadGitleaksRules([]byte(cfg), "mine.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted) != 1 || len(trusted[0].Allowlist) == 0 {
		t.Error("an explicitly named config must keep its allowlist")
	}
}

func TestFindGitleaksConfig(t *testing.T) {
	dir := t.TempDir()
	if got := FindGitleaksConfig(dir); got != "" {
		t.Errorf("no config present, got %q", got)
	}
	write := func(name string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("title = \"x\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// The search does not walk up: a config belonging to an enclosing project
	// must not be adopted when scanning one of its subdirectories.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindGitleaksConfig(sub); got != "" {
		t.Errorf("adopted a config from outside the scan root: %q", got)
	}
	// A config inside the scan root is found.
	inner := filepath.Join(sub, ".gitleaks.toml")
	if err := os.WriteFile(inner, []byte("title = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := FindGitleaksConfig(sub); got != inner {
		t.Errorf("FindGitleaksConfig(sub) = %q, want %q", got, inner)
	}
	if err := os.Remove(inner); err != nil {
		t.Fatal(err)
	}

	want := write(".gitleaks.toml")
	if got := FindGitleaksConfig(dir); got != want {
		t.Errorf("FindGitleaksConfig = %q, want %q", got, want)
	}
	// A directory named like the config is not a config.
	d := filepath.Join(dir, "gitleaks.toml")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindGitleaksConfig(dir); got != want {
		t.Errorf("a directory named gitleaks.toml was treated as the config: %q", got)
	}
}
