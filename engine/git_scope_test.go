package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func initRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", ".")
	if err := os.WriteFile(filepath.Join(dir, "base.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-qm", "init")
	return dir
}

// scopedGit runs a git command in dir with a fixed identity, for the staged and
// history scope tests.
func scopedGit(t *testing.T, dir string, args ...string) { //nolint:unused // used by the scoping tests below
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// C10: a single-file target used to bypass --staged/--diff/--history entirely
// and silently scan the working tree. With the index holding a secret the
// working tree no longer had, `minesweep --staged ./f` reported nothing and
// exited 0.
func TestStagedSingleFileReadsTheIndex(t *testing.T) {
	dir := initRepo(t)
	secret := filepath.Join(dir, "c.env")
	if err := os.WriteFile(secret, []byte(awsKey), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "c.env")
	// Clean the working tree without touching the index.
	if err := os.WriteFile(secret, []byte("clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, target := range []string{dir, secret} {
		eng, err := New(Config{MaxFindings: -1, StagedOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		rep, err := eng.Run(target)
		if err != nil {
			t.Fatalf("target %s: %v", target, err)
		}
		var found bool
		for _, f := range rep.Findings {
			if f.RuleID == "aws-access-key-id" {
				found = true
			}
		}
		if !found {
			t.Errorf("target %s: the staged secret was not reported; the working tree was scanned instead", target)
		}
	}
}

// A single-file target must not drag in the rest of the repository.
func TestStagedSingleFileIsScopedToThatFile(t *testing.T) {
	dir := initRepo(t)
	for _, name := range []string{"a.env", "b.env"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(awsKey), 0o600); err != nil {
			t.Fatal(err)
		}
		gitRun(t, dir, "add", name)
	}
	eng, err := New(Config{MaxFindings: -1, StagedOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(filepath.Join(dir, "a.env"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if filepath.Base(f.File) == "b.env" {
			t.Fatal("scanning a.env also reported b.env")
		}
	}
	if len(rep.Findings) == 0 {
		t.Fatal("nothing was reported")
	}
}

// History mode on a single file must attribute to commits rather than reading
// the working tree.
func TestHistorySingleFileIsScoped(t *testing.T) {
	dir := initRepo(t)
	f := filepath.Join(dir, "old.env")
	if err := os.WriteFile(f, []byte(awsKey), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "old.env")
	gitRun(t, dir, "commit", "-qm", "add secret")
	if err := os.WriteFile(f, []byte("clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.env")
	if err := os.WriteFile(other, []byte(awsKey), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "other.env")
	gitRun(t, dir, "commit", "-qm", "add other")

	eng, err := New(Config{MaxFindings: -1, HistoryMode: true})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("history scan of a single file found nothing")
	}
	for _, got := range rep.Findings {
		if !strings.Contains(got.File, "old.env") {
			t.Fatalf("history scan of old.env also reported %s", got.File)
		}
		if got.Commit == "" {
			t.Error("history finding has no commit attribution; the working tree was scanned")
		}
	}
}
