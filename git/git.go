// Package git provides git-related operations for MineSweep
package git

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// sanitizeBranchName validates and sanitizes a git branch name to prevent command injection
func SanitizeBranchName(name string) (string, error) {
	// Git branch names can contain: a-z, A-Z, 0-9, -, _, ., /
	// They cannot contain: spaces, ;, |, &, $, `, >, <, etc.
	validBranchPattern := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9\-_.\/]*$`)
	if name == "" {
		return "main", nil
	}
	if !validBranchPattern.MatchString(name) {
		return "", fmt.Errorf("branch name contains invalid characters")
	}
	// Additional check: ensure no shell metacharacters
	for _, char := range name {
		if char == ';' || char == '|' || char == '&' || char == '$' || char == '`' ||
			char == '>' || char == '<' || char == '(' || char == ')' || char == '\n' {
			return "", fmt.Errorf("branch name contains shell metacharacters")
		}
	}
	return name, nil
}

// TopLevel returns the absolute path of the repository working tree root
// containing path (or "" if not a git repo).
func TopLevel(path string) string {
	cmd := exec.Command("git", "rev-parse", "--show-toplevel")
	cmd.Dir = path
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// GetDiffFiles returns the list of files changed between baseBranch and HEAD,
// relative to the repository top-level directory.
func GetDiffFiles(root string, baseBranch string) ([]string, error) {
	if baseBranch == "" {
		baseBranch = "main"
	}

	// Sanitize branch name to prevent command injection
	sanitizedBranch, err := SanitizeBranchName(baseBranch)
	if err != nil {
		return nil, fmt.Errorf("invalid branch name: %w", err)
	}

	// git prints paths relative to the repo root regardless of cwd, so run
	// from the top level to make the returned paths unambiguous.
	top := TopLevel(root)
	if top == "" {
		return nil, fmt.Errorf("not a git repository: %s", root)
	}

	// `git diff <branch>...HEAD` exits 0 with EMPTY output when the base
	// branch does not exist, silently scanning nothing; that default must be
	// distinguishable from a real empty diff.
	probe := exec.Command("git", "rev-parse", "--verify", "--quiet", sanitizedBranch+"^{commit}") //nolint:gosec // branch name sanitized by SanitizeBranchName
	probe.Dir = top
	baseExists := probe.Run() == nil

	var out []byte
	if baseExists {
		cmd := exec.Command("git", "diff", "--name-only", sanitizedBranch+"...HEAD") //nolint:gosec // branch name sanitized by SanitizeBranchName
		cmd.Dir = top
		out, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git diff --name-only %q: %w", sanitizedBranch, err)
		}
	} else {
		// No base branch exists (single-commit checkout, unborn main):
		// diff from the empty tree so the whole HEAD is scanned as
		// "changed". The empty-tree object hash is a git constant.
		const emptyTree = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
		cmd := exec.Command("git", "diff", "--name-only", emptyTree, "HEAD")
		cmd.Dir = top
		out, err = cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git diff --name-only %q: %w", sanitizedBranch, err)
		}
	}

	return parseFileList(string(out)), nil
}

// GetStagedFiles returns the list of staged files, relative to the repository
// top-level directory.
func GetStagedFiles(root string) ([]string, error) {
	top := TopLevel(root)
	if top == "" {
		return nil, fmt.Errorf("not a git repository: %s", root)
	}

	cmd := exec.Command("git", "diff", "--cached", "--name-only", "--diff-filter=ACM")
	cmd.Dir = top
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --cached --name-only: %w", err)
	}

	return parseFileList(string(out)), nil
}

// GetIndexContent returns the staged content of the named path from the git
// index. This is what a pre-commit scan must read: the working tree may hold
// edits that are not part of the commit.
func GetIndexContent(root, path string) ([]byte, error) {
	return GetFileContent(root, path, "")
}

// GetFileContent returns the content of path as recorded at rev, where rev is
// "" for the index (":path"), "HEAD", or a branch/tag. Used by diff/staged
// scans so they examine exactly what would be committed instead of whatever
// sits in the working tree.
func GetFileContent(root, path, rev string) ([]byte, error) {
	top := TopLevel(root)
	if top == "" {
		return nil, fmt.Errorf("not a git repository: %s", root)
	}
	p := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if p == "" || p == "." || filepath.IsAbs(path) ||
		p == ".." || strings.HasPrefix(p, "../") {
		return nil, fmt.Errorf("refusing index path outside the repository: %q", path)
	}
	show := rev + ":" + p
	cmd := exec.Command("git", "show", show) //nolint:gosec // path and rev validated above; rev is a fixed internal value
	cmd.Dir = top
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git show %s: %w", show, err)
	}
	return out, nil
}

func parseFileList(out string) []string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var files []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, filepath.ToSlash(filepath.Clean(line)))
		}
	}
	return files
}

// IsGitRepo checks if a path is a git repository
func IsGitRepo(path string) bool {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	cmd.Dir = path
	return cmd.Run() == nil
}

// ReadFileLines reads a file and returns its lines
func ReadFileLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)
	if len(content) == 0 {
		return nil, nil
	}
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	return lines, nil
}
