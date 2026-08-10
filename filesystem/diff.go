package filesystem

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// sanitizeBranchName validates and sanitizes a git branch name to prevent command injection
func sanitizeBranchName(name string) (string, error) {
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

func GetDiffFiles(root string, baseBranch string) ([]string, error) {
	if baseBranch == "" {
		baseBranch = "main"
	}

	// Sanitize branch name to prevent command injection
	sanitizedBranch, err := sanitizeBranchName(baseBranch)
	if err != nil {
		return nil, fmt.Errorf("invalid branch name: %w", err)
	}

	cmd := exec.Command("git", "diff", "--name-only", sanitizedBranch+"...HEAD")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		cmd = exec.Command("git", "diff", "--name-only", sanitizedBranch)
		cmd.Dir = root
		out, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var files []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

func GetStagedFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--name-only")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var files []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
		}
	}
	return files, nil
}

func IsGitRepo(path string) bool {
	cmd := exec.Command("git", "rev-parse", "--git-dir")
	cmd.Dir = path
	return cmd.Run() == nil
}

func ReadFileLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(data)
	if len(content) == 0 {
		return nil, nil
	}
	lines := strings.Split(strings.TrimRight(content, "\n"), "\n")
	return lines, nil
}
