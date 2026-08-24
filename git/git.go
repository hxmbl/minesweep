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

	cmd := exec.Command("git", "diff", "--name-only", sanitizedBranch+"...HEAD") //nolint:gosec // branch name sanitized by SanitizeBranchName
	cmd.Dir = top
	out, err := cmd.Output()
	if err != nil {
		cmd = exec.Command("git", "diff", "--name-only", sanitizedBranch) //nolint:gosec // branch name sanitized by SanitizeBranchName
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

	cmd := exec.Command("git", "diff", "--cached", "--name-only")
	cmd.Dir = top
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --cached --name-only: %w", err)
	}

	return parseFileList(string(out)), nil
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
