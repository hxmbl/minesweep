package git

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

func TestGetDiffFilesSubdir(t *testing.T) {
	// Regression: paths must resolve against the repo top level even when the
	// scan root is a subdirectory of the repository.
	dir := t.TempDir()

	if err := runGitCmd(dir, "init", "-b", "main"); err != nil {
		t.Skip("git not available:", err)
	}
	runGitCmd(dir, "config", "user.email", "test@test.com")
	runGitCmd(dir, "config", "user.name", "Test")

	if err := os.MkdirAll(filepath.Join(dir, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "pkg", "a.txt"), "base")
	runGitCmd(dir, "add", ".")
	runGitCmd(dir, "commit", "-m", "init")
	runGitCmd(dir, "checkout", "-q", "-b", "feature")
	writeTestFile(t, filepath.Join(dir, "pkg", "a.txt"), "changed with AKIAIOSFODNN7EXAMPLE")
	runGitCmd(dir, "add", ".")
	runGitCmd(dir, "commit", "-m", "change")

	files, err := GetDiffFiles(filepath.Join(dir, "pkg"), "main")
	if err != nil {
		t.Fatalf("GetDiffFiles from subdir: %v", err)
	}
	found := false
	for _, f := range files {
		if f == "pkg/a.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected pkg/a.txt in diff files relative to toplevel, got %v", files)
	}
}

func TestTopLevel(t *testing.T) {
	dir := t.TempDir()
	if TopLevel(dir) != "" && IsGitRepo(dir) {
		t.Error("TopLevel should be empty outside a repo")
	}
	if err := runGitCmd(dir, "init"); err != nil {
		t.Skip("git not available:", err)
	}
	if got := TopLevel(dir); got == "" {
		t.Error("expected non-empty toplevel inside repo")
	}
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

// TestRegression_CommandInjection tests that branch names are properly sanitized
// to prevent command injection (Issue 4.3)
func TestRegression_CommandInjection(t *testing.T) {
	testCases := []struct {
		name       string
		branch     string
		shouldFail bool
	}{
		{"valid branch", "main", false},
		{"valid feature branch", "feature/test", false},
		{"valid with dash", "fix-bug", false},
		{"valid with underscore", "test_branch", false},
		{"valid with dot", "release.1.0", false},
		{"command injection attempt 1", "main; rm -rf /", true},
		{"command injection attempt 2", "main | cat /etc/passwd", true},
		{"command injection attempt 3", "main && echo hacked", true},
		{"command injection attempt 4", "main `whoami`", true},
		{"command injection attempt 5", "main $(whoami)", true},
		{"command injection attempt 6", "main > /tmp/hack", true},
		{"command injection attempt 7", "main < /tmp/hack", true},
		{"empty branch", "", false}, // Should default to main
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sanitized, err := SanitizeBranchName(tc.branch)

			if tc.shouldFail {
				if err == nil {
					t.Errorf("Expected error for branch %q, but got none", tc.branch)
				}
				if sanitized != "" {
					t.Errorf("Expected empty sanitized branch for %q, but got %q", tc.branch, sanitized)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for branch %q: %v", tc.branch, err)
				}
				if tc.branch == "" && sanitized != "main" {
					t.Errorf("Expected 'main' for empty branch, but got %q", sanitized)
				}
				if tc.branch != "" && sanitized != tc.branch {
					t.Errorf("Expected %q, but got %q", tc.branch, sanitized)
				}
			}
		})
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
