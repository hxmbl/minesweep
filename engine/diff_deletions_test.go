package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// A file deleted on the branch used to appear in the --diff file list, fail the
// content fetch at HEAD, and be reported as a path that "could not be read" —
// an incomplete scan, exit 2. Any PR that deleted a file failed the gate with a
// coverage warning that was pure fiction: there was nothing there to inspect.
func TestDiffScanIgnoresDeletedFiles(t *testing.T) {
	dir := initRepo(t)

	// A file that exists at the base commit and is deleted on the branch.
	victim := filepath.Join(dir, "removed.env")
	if err := os.WriteFile(victim, []byte(awsKey), 0o600); err != nil {
		t.Fatal(err)
	}
	scopedGit(t, dir, "add", "-A")
	scopedGit(t, dir, "commit", "-qm", "add secret")

	base := scopedGitOut(t, dir, "rev-parse", "HEAD")

	if err := os.Remove(victim); err != nil {
		t.Fatal(err)
	}
	scopedGit(t, dir, "add", "-A")
	scopedGit(t, dir, "commit", "-qm", "remove it")

	eng, err := New(Config{MaxFindings: -1, DiffMode: true, DiffBase: base})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Incomplete {
		t.Fatalf("deleting a file must not make the scan incomplete: %v", rep.IncompleteReasons)
	}
	if rep.FilesFailed != 0 {
		t.Errorf("FilesFailed = %d; a deleted file has nothing to read", rep.FilesFailed)
	}
	for _, p := range rep.UnreadablePaths {
		t.Errorf("deleted path reported as unreadable: %s", p)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("a deleted file must not produce findings, got %d", len(rep.Findings))
	}
}

// A rename keeps its content, so it must still be scanned. Rename detection is
// on by default, and without R in the diff filter the file was skipped whole —
// a secret surviving a `git mv` passed the gate.
func TestDiffScanCatchesRenamedFile(t *testing.T) {
	dir := initRepo(t)
	original := filepath.Join(dir, "config.env")
	if err := os.WriteFile(original, []byte(awsKey), 0o600); err != nil {
		t.Fatal(err)
	}
	scopedGit(t, dir, "add", "-A")
	scopedGit(t, dir, "commit", "-qm", "add secret")

	base := scopedGitOut(t, dir, "rev-parse", "HEAD")

	if err := os.Rename(original, filepath.Join(dir, "renamed.env")); err != nil {
		t.Fatal(err)
	}
	scopedGit(t, dir, "add", "-A")
	scopedGit(t, dir, "commit", "-qm", "rename it")

	eng, err := New(Config{MaxFindings: -1, DiffMode: true, DiffBase: base})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range rep.Findings {
		if f.RuleID == "aws-access-key-id" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a renamed secret was not reported; found %d findings", len(rep.Findings))
	}
}

// A modified file is of course still scanned.
func TestDiffScanStillCatchesModifiedFiles(t *testing.T) {
	dir := initRepo(t)
	base := scopedGitOut(t, dir, "rev-parse", "HEAD")

	f := filepath.Join(dir, "app.env")
	if err := os.WriteFile(f, []byte(awsKey), 0o600); err != nil {
		t.Fatal(err)
	}
	scopedGit(t, dir, "add", "-A")
	scopedGit(t, dir, "commit", "-qm", "add secret")

	eng, err := New(Config{MaxFindings: -1, DiffMode: true, DiffBase: base})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("a modified secret was not reported")
	}
	if rep.Incomplete {
		t.Errorf("unexpected incompleteness: %v", rep.IncompleteReasons)
	}
}

func scopedGitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out := runGit(t, dir, args...)
	if out == "" {
		t.Fatalf("git %v produced no output", args)
	}
	return out
}
