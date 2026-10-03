package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"minesweep/findings"
)

// #7: a directory the scanner cannot read held a live credential and the scan
// still exited 0 with files_skipped and files_failed both absent. A coverage gap
// must never be able to produce a clean-looking result.
func TestUnreadableDirectoryMakesScanIncomplete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 000 is still readable")
	}
	dir := t.TempDir()
	open := filepath.Join(dir, "open")
	blocked := filepath.Join(dir, "blocked")
	for _, d := range []string{open, blocked} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const secret = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01\n"
	for _, f := range []string{filepath.Join(open, "a.env"), filepath.Join(blocked, "b.env")} {
		if err := os.WriteFile(f, []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := e.Run(dir)
	if err != nil {
		t.Fatal(err)
	}

	if !rep.Incomplete {
		t.Error("scan reported complete despite an unreadable subtree")
	}
	if !containsReason(rep.IncompleteReasons, ReasonUnreadable) {
		t.Errorf("IncompleteReasons = %v, want it to include %q", rep.IncompleteReasons, ReasonUnreadable)
	}
	if rep.FilesFailed == 0 {
		t.Error("FilesFailed = 0 despite an unreadable directory")
	}
	// Only the readable file should have been scanned, and it should still have
	// been found: accounting for the gap must not suppress real findings.
	if len(rep.Findings) == 0 {
		t.Error("no findings from the readable half of the tree")
	}
	for _, f := range rep.Findings {
		if strings.Contains(f.File, "blocked") {
			t.Errorf("unexpected finding from the unreadable directory: %+v", f)
		}
	}
}

// #3: the per-file budget has to be reachable from the engine, or a single
// pathological file can materialise hundreds of thousands of findings before the
// global cap is ever consulted.
func TestFileBudgetIsReachableFromEngine(t *testing.T) {
	dir := t.TempDir()
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		sb.WriteString("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "big.env"), []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := New(Config{MaxFindings: 1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := e.Run(dir)
	if err != nil {
		t.Fatal(err)
	}

	if !rep.Incomplete {
		t.Error("scan reported complete although the finding cap dropped findings")
	}
	// The per-file budget is now armed and fires first, which is the whole point
	// of the fix: one pathological file is bounded before the global cap is ever
	// consulted. Either reason is a correct verdict; both must be present.
	if !containsReason(rep.IncompleteReasons, ReasonFileBudget) &&
		!containsReason(rep.IncompleteReasons, ReasonFindingCap) {
		t.Errorf("IncompleteReasons = %v, want %q or %q",
			rep.IncompleteReasons, ReasonFileBudget, ReasonFindingCap)
	}
	if len(rep.Findings) > 1 {
		t.Errorf("kept %d findings with MaxFindings=1", len(rep.Findings))
	}
	// FindingsDropped is deliberately not asserted to be positive: the budget
	// now prevents the findings from being created at all, rather than creating
	// 200,000 of them and trimming to 1 afterwards. Nothing is dropped because
	// nothing extra is ever built.
	if rep.FindingsDropped != 0 {
		t.Errorf("FindingsDropped = %d; findings should be bounded at the source now", rep.FindingsDropped)
	}
}

// #32: a symlink escaping the scan root hides content the scan was asked for, so
// it has to make the scan incomplete rather than counting as a scanned file.
func TestEscapingSymlinkMakesScanIncomplete(t *testing.T) {
	if _, err := os.Lstat("/"); err != nil {
		t.Skip("no filesystem")
	}
	root := t.TempDir()
	outside := t.TempDir()
	const secret = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01\n"
	if err := os.WriteFile(filepath.Join(outside, "secret.env"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape.env")
	if err := os.Symlink(filepath.Join(outside, "secret.env"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := e.Run(root)
	if err != nil {
		t.Fatal(err)
	}

	if !rep.Incomplete {
		t.Error("scan reported complete despite a symlink resolving outside the root")
	}
	if !containsReason(rep.IncompleteReasons, ReasonUnreadable) {
		t.Errorf("IncompleteReasons = %v, want it to include %q", rep.IncompleteReasons, ReasonUnreadable)
	}
	// The link must not be reported as having been scanned for its secret.
	for _, f := range rep.Findings {
		if strings.Contains(f.Value, "wJalrXUtnFEMI") {
			t.Errorf("secret outside the root was read through a symlink: %+v", f)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func containsReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}

// #5: filepath.WalkDir does not follow a symlinked root, so scanning a symlinked
// project directory found nothing, scored 0/100 and exited clean. --diff,
// --staged and --history already resolved symlinks, so the four modes disagreed
// about the same tree.
func TestSymlinkedScanRootIsActuallyScanned(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "realproject")
	wrapper := filepath.Join(base, "wrapper")
	for _, d := range []string{real, wrapper} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const secret = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01\n"
	if err := os.WriteFile(filepath.Join(real, ".env"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(wrapper, "project")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	scan := func(target string) *findings.RiskReport {
		t.Helper()
		e, err := New(Config{})
		if err != nil {
			t.Fatal(err)
		}
		rep, err := e.Run(target)
		if err != nil {
			t.Fatalf("run %s: %v", target, err)
		}
		return rep
	}

	viaLink := scan(link)
	direct := scan(real)

	if len(direct.Findings) == 0 {
		t.Fatal("scanning the real directory found nothing; the fixture is wrong")
	}
	if len(viaLink.Findings) != len(direct.Findings) {
		t.Errorf("scanning the symlink found %d findings, direct scan found %d",
			len(viaLink.Findings), len(direct.Findings))
	}
	if viaLink.RiskScore != findings.RiskScore(direct.RiskScore) || viaLink.RiskScore == 0 {
		t.Errorf("risk score via symlink = %v, direct scan = %v", viaLink.RiskScore, direct.RiskScore)
	}
	// A symlinked root that is fully scannable is not a coverage gap.
	if containsReason(viaLink.IncompleteReasons, ReasonUnreadable) {
		t.Errorf("IncompleteReasons = %v; scanning a resolvable symlinked root is not a gap", viaLink.IncompleteReasons)
	}

	// Paths in the report must be relative to the resolved root, not the link.
	for _, f := range viaLink.Findings {
		if strings.HasPrefix(f.File, "/") {
			t.Errorf("finding path is absolute: %q", f.File)
		}
	}
}

// #6: the two-hop escape, at the engine level: nothing outside the scan root may
// be read through a chain of in-root links.
func TestSymlinkChainEscapeIsNotReadByEngine(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, outside} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const secret = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01\n"
	if err := os.WriteFile(filepath.Join(outside, "secret.env"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.env"), filepath.Join(root, "b.env")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("b.env", filepath.Join(root, "a.env")); err != nil {
		t.Fatal(err)
	}

	e, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := e.Run(root)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range rep.Findings {
		if strings.Contains(f.Value, "wJalrXUtnFEMI") {
			t.Errorf("secret outside the scan root was read through a symlink chain: %+v", f)
		}
		if strings.Contains(f.SourceLine, "wJalrXUtnFEMI") {
			t.Errorf("evidence leaked the out-of-root secret: %q", f.SourceLine)
		}
	}
}

// #13: PolicyDir and RulesDir used to default to "policy" and "rules", resolved
// against the working directory. resolvePolicies preferred
// <cwd>/policy/default.yml over the embedded policy, so merely running the
// scanner from a checkout that happened to contain one applied that policy to a
// tree it had nothing to do with -- and a policy whose only rule was
// `tags: ["*"], action: allow` turned a blocked finding into a clean exit 0.
//
// mergeRules replaces built-in rules by ID, so an ambient ./rules could weaken a
// built-in rule just as easily as add one. Neither is picked up now unless the
// user names it.
func TestAmbientPolicyAndRulesDirsAreNotUsed(t *testing.T) {
	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, "policy", "default.yml"),
		"policies:\n  - tags: [\"*\"]\n    action: allow\n")
	writeFile(t, filepath.Join(cwd, "rules", "aws.yml"),
		"rules:\n  - id: aws-secret-key\n    type: regex\n    name: weakened\n    description: d\n"+
			"    severity: low\n    tags: [aws]\n    patterns:\n      - regex: NEVERMATCHES_[A-Z]+\n"+
			"        confidence: 0.1\n")

	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	e, err := New(Config{})
	if err != nil {
		t.Fatalf("ambient policy/rules dirs must not break engine construction: %v", err)
	}

	// The ambient policy would allow everything.
	for _, r := range e.Policies() {
		if len(r.Tags) == 1 && r.Tags[0] == "*" && r.Action == findings.ActionAllow {
			t.Errorf("ambient ./policy/default.yml was loaded: %+v", r)
		}
	}

	// The ambient rule file would have replaced the built-in aws-secret-key.
	for _, r := range e.regex.Rules() {
		if r.ID == "aws-secret-key" && r.Severity == "low" {
			t.Errorf("ambient ./rules overwrote the built-in aws-secret-key rule: %+v", r)
		}
	}

	// Sanity: the built-in rule really is present at its own severity.
	var found bool
	for _, r := range e.regex.Rules() {
		if r.ID == "aws-secret-key" {
			found = true
			if r.Severity != "critical" {
				t.Errorf("built-in aws-secret-key severity = %q, want critical", r.Severity)
			}
		}
	}
	if !found {
		t.Error("built-in aws-secret-key rule missing")
	}
}

// The ambient directories must still be usable when the user names them.
func TestNamedPolicyAndRulesDirsAreHonoured(t *testing.T) {
	cwd := t.TempDir()
	writeFile(t, filepath.Join(cwd, "policy", "default.yml"),
		"policies:\n  - tags: [\"*\"]\n    action: allow\n")
	writeFile(t, filepath.Join(cwd, "rules", "custom.yml"),
		"rules:\n  - id: my-explicit-rule\n    type: regex\n    name: Explicit\n    description: d\n"+
			"    severity: critical\n    tags: [t]\n    patterns:\n      - regex: EXPLICIT_[A-Z]{4}\n"+
			"        confidence: 0.9\n")

	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	e, err := New(Config{PolicyDir: "policy", RulesDir: "rules"})
	if err != nil {
		t.Fatal(err)
	}
	var allowed, explicit bool
	for _, r := range e.Policies() {
		if len(r.Tags) == 1 && r.Tags[0] == "*" && r.Action == findings.ActionAllow {
			allowed = true
		}
	}
	for _, r := range e.regex.Rules() {
		if r.ID == "my-explicit-rule" {
			explicit = true
		}
	}
	if !allowed {
		t.Error("an explicitly named --policy-dir was not honoured")
	}
	if !explicit {
		t.Error("an explicitly named --rules dir was not honoured")
	}
}
