package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	// The file's own budget bounds what is ever built, so the cap only has to
	// choose among a bounded candidate set rather than trim 200,000 findings.
	// FindingsDropped is therefore expected to be non-zero here: 1000 were
	// produced (perFileFindingBudget) and 1 was kept.
	if rep.FindingsDropped <= 0 {
		t.Error("expected the cap to drop the findings the per-file budget allowed")
	}
	if rep.FindingsDropped >= 100000 {
		t.Errorf("FindingsDropped = %d; the per-file budget did not bound production", rep.FindingsDropped)
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

// #11: which findings survive --max-findings must not depend on worker
// scheduling. Two things made it depend on scheduling: the trim broke ties on
// input order (detectParallel's result-channel completion order), and the
// per-file budget was derived from the global remaining, which several workers
// could each read as the full cap before any of them reported.
//
// The same tree scanned with --workers 1 and --workers 32 produced two different
// sets, which also invalidates a baseline recorded from a different run.
func TestMaxFindingsSelectionIsIndependentOfWorkerCount(t *testing.T) {
	dir := t.TempDir()
	// 40 files x 25 identical-shaped secrets each: far more than the cap, so the
	// cap has to choose.
	line := "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY%02d\n"
	for f := 0; f < 40; f++ {
		var sb strings.Builder
		for i := 0; i < 25; i++ {
			fmt.Fprintf(&sb, line, i)
		}
		writeFile(t, filepath.Join(dir, fmt.Sprintf("f%02d.env", f)), sb.String())
	}

	survey := func(workers int) []string {
		t.Helper()
		e, err := New(Config{MaxFindings: 25, Workers: workers})
		if err != nil {
			t.Fatal(err)
		}
		rep, err := e.Run(dir)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(rep.Findings))
		for _, f := range rep.Findings {
			out = append(out, f.File+":"+strconv.Itoa(f.Line)+":"+f.RuleID)
		}
		return out
	}

	base := survey(1)
	if len(base) != 25 {
		t.Fatalf("expected the cap to keep 25 findings, kept %d", len(base))
	}
	for _, workers := range []int{2, 4, 8, 16} {
		got := survey(workers)
		if len(got) != len(base) {
			t.Errorf("workers=%d kept %d findings, want %d", workers, len(got), len(base))
			continue
		}
		for i := range got {
			if got[i] != base[i] {
				t.Errorf("workers=%d selected %q where workers=1 selected %q", workers, got[i], base[i])
			}
		}
	}
}

// #12: a baseline has to describe what was reported. Recording the pre-filter
// set was two bugs at once: a run capped at 10 findings wrote all 300 to the
// baseline, and suppressed findings were baselined too, so deleting the
// suppression file did not bring them back.
func TestBaselineRecordsOnlyWhatWasReported(t *testing.T) {
	dir := t.TempDir()
	line := "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY%02d\n"
	var sb strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&sb, line, i)
	}
	writeFile(t, filepath.Join(dir, "big.env"), sb.String())

	baseline := filepath.Join(dir, "baseline.json")
	e, err := New(Config{MaxFindings: 10, BaselineFile: baseline, UpdateBaseline: true, Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := e.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 10 {
		t.Fatalf("expected 10 reported findings, got %d", len(rep.Findings))
	}

	b, err := findings.LoadBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Findings) != 10 {
		t.Errorf("baseline recorded %d findings, want the 10 that were reported", len(b.Findings))
	}

	// Raising the cap must surface what the truncated run never reported.
	e2, err := New(Config{BaselineFile: baseline, Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	rep2, err := e2.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Findings) == 0 {
		t.Error("the baseline recorded findings that were never reported, hiding them permanently")
	}
}

// A suppression is a local, uncommitted decision, usually made to get a build
// past a known finding. Baselining a suppressed finding means deleting the
// suppression file no longer brings it back.
func TestSuppressedFindingsAreNotBaselined(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "a.env"), "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01\n")
	writeFile(t, filepath.Join(dir, "b.env"), "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY99\n")
	supp := filepath.Join(dir, "suppress.json")
	writeFile(t, supp, `{"version":"1","suppressions":[{"file":"b.env"}]}`)
	baseline := filepath.Join(dir, "baseline.json")

	e, err := New(Config{MinSeverity: "low", SuppressFile: supp, BaselineFile: baseline, UpdateBaseline: true})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := e.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if strings.Contains(f.File, "b.env") {
			t.Errorf("b.env should have been suppressed: %+v", f)
		}
	}

	b, err := findings.LoadBaseline(baseline)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range b.Findings {
		if strings.HasPrefix(entry, "b.env") {
			t.Errorf("a suppressed finding was baselined: %q", entry)
		}
	}

	// Removing the suppression must bring it back.
	if err := os.Remove(supp); err != nil {
		t.Fatal(err)
	}
	e2, err := New(Config{MinSeverity: "low", BaselineFile: baseline})
	if err != nil {
		t.Fatal(err)
	}
	rep2, err := e2.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range rep2.Findings {
		if strings.Contains(f.File, "b.env") {
			found = true
		}
	}
	if !found {
		t.Error("b.env did not come back after the suppression file was removed")
	}
}
