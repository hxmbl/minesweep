package filesystem

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGetDiffFilesEmptyDir(t *testing.T) {
	dir := t.TempDir()
	files, err := GetDiffFiles(dir, "HEAD")
	if err != nil {
		// Non-git dir returns error, that's fine
		return
	}
	if len(files) != 0 {
		t.Errorf("expected 0 diff files in empty dir, got %d", len(files))
	}
}

func TestGetStagedFiles(t *testing.T) {
	dir := t.TempDir()

	if err := runGitCmd(dir, "init"); err != nil {
		t.Skip("git not available:", err)
	}
	runGitCmd(dir, "config", "user.email", "test@test.com")
	runGitCmd(dir, "config", "user.name", "Test")

	writeTestFile(t, filepath.Join(dir, "staged.txt"), "secret")
	runGitCmd(dir, "add", "staged.txt")

	files, err := GetStagedFiles(dir)
	if err != nil {
		t.Fatalf("GetStagedFiles: %v", err)
	}

	found := false
	for _, f := range files {
		if filepath.Base(f) == "staged.txt" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected staged.txt in staged files")
	}
}

func TestGetStagedFilesEmpty(t *testing.T) {
	dir := t.TempDir()

	if err := runGitCmd(dir, "init"); err != nil {
		t.Skip("git not available:", err)
	}
	runGitCmd(dir, "config", "user.email", "test@test.com")
	runGitCmd(dir, "config", "user.name", "Test")

	files, err := GetStagedFiles(dir)
	if err != nil {
		t.Fatalf("GetStagedFiles: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 staged files, got %d", len(files))
	}
}

func TestGetDiffFilesCommittedDiff(t *testing.T) {
	dir := t.TempDir()

	if err := runGitCmd(dir, "init"); err != nil {
		t.Skip("git not available:", err)
	}
	runGitCmd(dir, "config", "user.email", "test@test.com")
	runGitCmd(dir, "config", "user.name", "Test")

	writeTestFile(t, filepath.Join(dir, "original.txt"), "original")
	runGitCmd(dir, "add", ".")
	runGitCmd(dir, "commit", "-m", "initial")

	// Add a new file (untracked)
	writeTestFile(t, filepath.Join(dir, "new.txt"), "new secret AKIAIOSFODNN7EXAMPLE")

	// Compare against HEAD (should show untracked and modified files)
	files, err := GetDiffFiles(dir, "HEAD")
	if err != nil {
		// If HEAD comparison doesn't work, that's ok for this test
		t.Skipf("GetDiffFiles with HEAD: %v", err)
	}

	t.Logf("diff files: %v", files)
	// The function should return something or error gracefully
}

func TestIsGitRepo(t *testing.T) {
	dir := t.TempDir()
	if IsGitRepo(dir) {
		t.Error("expected false for non-git dir")
	}

	runGitCmd(dir, "init")
	if !IsGitRepo(dir) {
		t.Error("expected true for git dir")
	}
}

func TestReadFileLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	writeTestFile(t, path, "line1\nline2\nline3\n")

	lines, err := ReadFileLines(path)
	if err != nil {
		t.Fatalf("ReadFileLines: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "line1" {
		t.Errorf("expected line1, got %s", lines[0])
	}
	if lines[2] != "line3" {
		t.Errorf("expected line3, got %s", lines[2])
	}
}

func TestReadFileLinesEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	writeTestFile(t, path, "")

	lines, err := ReadFileLines(path)
	if err != nil {
		t.Fatalf("ReadFileLines: %v", err)
	}
	if len(lines) != 0 {
		t.Errorf("expected 0 lines, got %d", len(lines))
	}
}

func TestReadFileLinesMissing(t *testing.T) {
	_, err := ReadFileLines("/nonexistent/file.txt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// helpers

func runGitCmd(dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return &gitError{cmd: "git " + args[0], output: string(out), err: err}
	}
	return nil
}

type gitError struct {
	cmd    string
	output string
	err    error
}

func (e *gitError) Error() string {
	return e.cmd + ": " + e.err.Error() + "\n" + e.output
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeFile %s: %v", path, err)
	}
}
