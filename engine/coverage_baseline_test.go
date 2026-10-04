package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// C7: --update-baseline wrote hashes for findings that were never reported.
// filterBaseline ran before the trim and before suppression and handed the whole
// slice to the baseline writer, so --update-baseline --max-findings 5 reported
// 5 findings, wrote 400 hashes, and every later run reported the tree clean.
func TestUpdateBaselineRecordsOnlyReportedFindings(t *testing.T) {
	dir := buildFindingTree(t, 4, 100)
	baseline := filepath.Join(dir, "b.json")

	// Untruncated: every finding is reported, so all of them are recorded.
	eng, err := New(Config{MaxFindings: -1, UpdateBaseline: true, BaselineFile: baseline})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries := baselineCount(t, baseline)
	if entries != len(rep.Findings) {
		t.Fatalf("baseline holds %d entries for %d reported findings", entries, len(rep.Findings))
	}

	// Truncated: the baseline must not be written at all, because a partial
	// baseline permanently blesses findings nobody triaged.
	partial := filepath.Join(dir, "partial.json")
	capped, err := New(Config{MaxFindings: 10, UpdateBaseline: true, BaselineFile: partial, Workers: 4})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capped.Run(dir); err == nil {
		t.Fatal("expected an error when updating a baseline from an incomplete scan")
	} else if !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("error should name the cause, got: %v", err)
	}
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatal("a baseline was written from an incomplete scan")
	}
}

// A finding removed by the suppression file must not enter the baseline: with
// the suppression file deleted afterwards, the finding has to come back.
func TestSuppressedFindingsAreNotBaselined(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.env"), []byte(awsKey), 0o600); err != nil {
		t.Fatal(err)
	}
	suppress := filepath.Join(dir, "s.json")
	if err := os.WriteFile(suppress, []byte(`{"version":"1","suppressions":[{"id":"x","pattern":".*"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(dir, "b.json")

	eng, err := New(Config{MaxFindings: -1, UpdateBaseline: true, BaselineFile: baseline, SuppressFile: suppress})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) != 0 {
		t.Fatalf("expected everything suppressed, got %d findings", len(rep.Findings))
	}
	if n := baselineCount(t, baseline); n != 0 {
		t.Fatalf("baseline holds %d suppressed findings", n)
	}

	// Remove the suppression: the finding must return.
	if err := os.Remove(suppress); err != nil {
		t.Fatal(err)
	}
	eng2, err := New(Config{MaxFindings: -1, BaselineFile: baseline})
	if err != nil {
		t.Fatal(err)
	}
	rep2, err := eng2.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Findings) == 0 {
		t.Fatal("the finding did not come back after the suppression was removed")
	}
}

// C9: an unreadable directory used to vanish with no accounting at all and the
// scan still exited 0. It must be counted and must mark the scan incomplete.
func TestUnreadableDirectoryIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "secret.env"), []byte(awsKey), 0o600); err != nil {
		t.Fatal(err)
	}
	// Lock the directory *after* populating it.
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	if err := os.WriteFile(filepath.Join(dir, "open.txt"), []byte("harmless\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	eng, err := New(Config{MaxFindings: -1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FilesFailed == 0 {
		t.Error("an unreadable directory was not counted as a failure")
	}
	if len(rep.UnreadablePaths) == 0 {
		t.Error("no unreadable path was named in the report")
	}
	if !rep.Incomplete {
		t.Error("an unreadable directory must mark the scan incomplete")
	}
	if !containsReason(rep.IncompleteReasons, ReasonUnreadable) {
		t.Errorf("reason not recorded: %v", rep.IncompleteReasons)
	}
	// The same directory is reported twice by the walker (entry error plus
	// failed read); it must be counted once.
	if rep.FilesFailed != 1 {
		t.Errorf("FilesFailed = %d, want 1 (the walker reports the path twice)", rep.FilesFailed)
	}
	for _, p := range rep.UnreadablePaths {
		if filepath.IsAbs(p) {
			t.Errorf("unreadable path should be root-relative, got %q", p)
		}
	}
}

// An unreadable *file* is the same class of gap.
func TestUnreadableFileIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read anything")
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "locked.env")
	if err := os.WriteFile(f, []byte(awsKey), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f, 0o600) })

	eng, err := New(Config{MaxFindings: -1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FilesFailed == 0 {
		t.Error("an unreadable file was not counted")
	}
	if !rep.Incomplete {
		t.Error("an unreadable file must mark the scan incomplete")
	}
}

// A clean, fully-readable scan must not claim incompleteness.
func TestReadableTreeIsComplete(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := New(Config{MaxFindings: -1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Incomplete || rep.FilesFailed != 0 || len(rep.UnreadablePaths) != 0 {
		t.Errorf("readable tree reported incomplete=%v failed=%d paths=%v",
			rep.Incomplete, rep.FilesFailed, rep.UnreadablePaths)
	}
}

func baselineCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Findings map[string]string `json:"findings"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	return len(b.Findings)
}

var _ = fmt.Sprintf
