package engine

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"minesweep/findings"
)

// buildFindingTree writes n files each containing m AWS keys, which is enough
// distinct findings to push any small cap and to spread them across workers.
func buildFindingTree(t *testing.T, n, m int) string {
	t.Helper()
	dir := t.TempDir()
	sub := filepath.Join(dir, "d")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		var b strings.Builder
		for j := 0; j < m; j++ {
			fmt.Fprintf(&b, "AWS_ACCESS_KEY_ID=AKIA%016X\n", i*m+j)
		}
		if err := os.WriteFile(filepath.Join(sub, fmt.Sprintf("f%03d.env", i)), []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// C6: three identical runs of one tree over the finding cap produced three
// different result sets. trimToConfidenceCap broke ties on input order, and the
// input order was the order in which workers finished.
func TestScanOverCapIsDeterministic(t *testing.T) {
	dir := buildFindingTree(t, 40, 50)

	digests := map[string][]string{}
	for _, workers := range []int{1, 2, 4, 8, 16} {
		for run := 0; run < 3; run++ {
			eng, err := New(Config{MaxFindings: 500, Workers: workers, FailOn: "low"})
			if err != nil {
				t.Fatal(err)
			}
			rep, err := eng.Run(dir)
			if err != nil {
				t.Fatal(err)
			}
			digests[digest(t, rep.Findings)] = append(
				digests[digest(t, rep.Findings)], fmt.Sprintf("workers=%d run=%d", workers, run))
		}
	}
	if len(digests) != 1 {
		for d, runs := range digests {
			t.Errorf("digest %s from %v", d[:12], runs)
		}
		t.Fatalf("%d distinct results from 15 identical scans of the same tree", len(digests))
	}
}

// The retained set must be the same *set*, not just the same count, so a
// baseline written under one worker count matches under another.
func TestRetainedSetIsWorkerCountIndependent(t *testing.T) {
	dir := buildFindingTree(t, 20, 40)
	var reference map[string]bool
	for _, workers := range []int{1, 3, 8, 16} {
		eng, err := New(Config{MaxFindings: 200, Workers: workers})
		if err != nil {
			t.Fatal(err)
		}
		rep, err := eng.Run(dir)
		if err != nil {
			t.Fatal(err)
		}
		set := map[string]bool{}
		for _, f := range rep.Findings {
			set[fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.RuleID)] = true
		}
		if reference == nil {
			reference = set
			continue
		}
		if len(set) != len(reference) {
			t.Fatalf("workers=%d kept %d findings, workers=1 kept %d", workers, len(set), len(reference))
		}
		for k := range reference {
			if !set[k] {
				t.Fatalf("workers=%d dropped %s which workers=1 kept", workers, k)
			}
		}
	}
}

// sortFindings must be a total order. Two findings agreeing on location, rule,
// value and confidence but differing elsewhere were previously ordered
// arbitrarily, and that arbitrariness leaked worker scheduling into output.
func TestSortFindingsIsATotalOrder(t *testing.T) {
	mk := func(tag string) findingFixture {
		return findingFixture{File: "a.env", Line: 3, Column: 1, RuleID: "r", Value: "v",
			Confidence: 0.5, Type: tag, Reason: "why", Severity: 3}
	}
	a := []findingFixture{mk("alpha"), mk("beta"), mk("gamma")}
	b := []findingFixture{mk("gamma"), mk("alpha"), mk("beta")}

	sortFixtures(a)
	sortFixtures(b)
	for i := range a {
		if a[i].Type != b[i].Type {
			t.Fatalf("order is not deterministic: %v vs %v", a, b)
		}
	}
}

// C5: the incompleteness notice must account for what was actually lost.
// Report-only FindingsDropped counted the final trim alone; per-file discards
// happened before the trim saw them, so a scan that dropped 1500 findings
// reported 550.
func TestPerFileDiscardsAreCounted(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 2_000; i++ {
		fmt.Fprintf(&b, "AWS_ACCESS_KEY_ID=AKIA%016X\n", i)
	}
	if err := os.WriteFile(filepath.Join(dir, "one.txt"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	unlimited, err := New(Config{MaxFindings: -1, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	full, err := unlimited.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	total := len(full.Findings)

	capped, err := New(Config{MaxFindings: 600, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := capped.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 600 {
		t.Fatalf("kept %d findings, want the cap of 600", len(rep.Findings))
	}
	// One file only, so the whole cap is its share. Every finding the file
	// *materialised* must be either kept or accounted for; matches a detector
	// never reached cannot be counted, which is why the figure is documented
	// and rendered as a lower bound.
	accounted := len(rep.Findings) + rep.FindingsDropped + rep.FindingsDiscarded
	if accounted > total {
		t.Errorf("accounting invented findings: kept=%d dropped=%d discarded=%d = %d, but only %d exist",
			len(rep.Findings), rep.FindingsDropped, rep.FindingsDiscarded, accounted, total)
	}
	if accounted == 0 || accounted >= total {
		t.Errorf("accounting is not a useful lower bound: kept=%d dropped=%d discarded=%d, total=%d",
			len(rep.Findings), rep.FindingsDropped, rep.FindingsDiscarded, total)
	}
	if !rep.Incomplete {
		t.Error("a truncated scan must not report itself complete")
	}
	if !containsReason(rep.IncompleteReasons, ReasonFileBudget) {
		t.Errorf("per-file budget exhaustion not recorded: %v", rep.IncompleteReasons)
	}
}

// With no budget truncation the accounting must be exact: nothing is lost, so
// nothing may be reported as lost.
func TestUntruncatedScanAccountsNothingAsLost(t *testing.T) {
	dir := buildFindingTree(t, 5, 10)
	eng, err := New(Config{MaxFindings: -1, Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Incomplete {
		t.Errorf("an untruncated scan reported incomplete: %v", rep.IncompleteReasons)
	}
	if rep.FindingsDropped != 0 || rep.FindingsDiscarded != 0 {
		t.Errorf("untruncated scan reported losses: dropped=%d discarded=%d",
			rep.FindingsDropped, rep.FindingsDiscarded)
	}
	if rep.FindingsSuppressed != 0 {
		t.Errorf("untruncated scan reported suppressions: %d", rep.FindingsSuppressed)
	}
}

// No file may ever be skipped outright because of the finding budget. Under the
// old shared pool, files reached after the pool ran dry were dropped without
// being opened, which is a coverage gap no report described.
func TestNoFileIsSkippedByTheBudget(t *testing.T) {
	dir := buildFindingTree(t, 40, 50)
	eng, err := New(Config{MaxFindings: 200, Workers: 8})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FilesScanned != 40 {
		t.Fatalf("scanned %d of 40 files; the budget must never skip a file", rep.FilesScanned)
	}
	if len(rep.Findings) > 200 {
		t.Fatalf("kept %d findings, over the cap of 200", len(rep.Findings))
	}
	if !rep.Incomplete {
		t.Error("a truncated scan must not report itself complete")
	}
}

// Every file in the tree must be opened, whatever the budget.
func TestBudgetNeverSkipsFilesAtAnyWorkerCount(t *testing.T) {
	dir := buildFindingTree(t, 12, 60)
	for _, workers := range []int{1, 2, 8, 16} {
		for _, cap := range []int{1, 10, 100, 1000} {
			eng, err := New(Config{MaxFindings: cap, Workers: workers})
			if err != nil {
				t.Fatal(err)
			}
			rep, err := eng.Run(dir)
			if err != nil {
				t.Fatal(err)
			}
			if rep.FilesScanned != 12 {
				t.Fatalf("cap=%d workers=%d: scanned %d of 12 files", cap, workers, rep.FilesScanned)
			}
			if len(rep.Findings) > cap {
				t.Fatalf("cap=%d workers=%d: kept %d findings", cap, workers, len(rep.Findings))
			}
		}
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

// A pathological single file must be bounded by its own budget rather than
// materialising everything it can match.
func TestSingleFileIsBoundedByBudget(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 20_000; i++ {
		fmt.Fprintf(&b, "AWS_ACCESS_KEY_ID=AKIA%016X\n", i)
	}
	if err := os.WriteFile(filepath.Join(dir, "one.txt"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	eng, err := New(Config{MaxFindings: 100, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 100 {
		t.Fatalf("kept %d findings, want 100", len(rep.Findings))
	}
	if rep.FindingsDiscarded == 0 {
		t.Error("per-file discards were not counted")
	}
}

func digest(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum)
}

// findingFixture mirrors the comparable surface of findings.Finding so the
// total-order property can be asserted without importing detectors.
type findingFixture = findings.Finding

func sortFixtures(fs []findingFixture) { sortFindings(fs) }
