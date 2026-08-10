package filesystem

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"minesweep/git"
)

// GetDiffFiles is a wrapper around git.GetDiffFiles for backward compatibility
func GetDiffFiles(root string, baseBranch string) ([]string, error) {
	return git.GetDiffFiles(root, baseBranch)
}

// GetStagedFiles is a wrapper around git.GetStagedFiles for backward compatibility
func GetStagedFiles(root string) ([]string, error) {
	return git.GetStagedFiles(root)
}

// IsGitRepo is a wrapper around git.IsGitRepo for backward compatibility
func IsGitRepo(path string) bool {
	return git.IsGitRepo(path)
}

// ReadFileLines reads a file and returns its lines
func ReadFileLines(path string) ([]string, error) {
	return git.ReadFileLines(path)
}

// sanitizeBranchName is kept for backward compatibility but delegates to git package
func sanitizeBranchName(name string) (string, error) {
	return git.SanitizeBranchName(name)
}
