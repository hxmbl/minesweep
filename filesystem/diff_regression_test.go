package filesystem

import (
	"testing"
)

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
			sanitized, err := sanitizeBranchName(tc.branch)

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

// TestRegression_PathTraversal tests that symlinks pointing outside root are handled safely
// (Issue 4.1)
func TestRegression_PathTraversal(t *testing.T) {
	testCases := []struct {
		name     string
		path     string
		root     string
		expected bool
	}{
		{"safe path", "/safe/root/file.txt", "/safe/root", true},
		{"relative safe path", "file.txt", "/safe/root", true},
		{"parent directory", "../etc/passwd", "/safe/root", false},
		{"multiple parent directories", "../../../etc/passwd", "/safe/root", false},
		{"absolute path outside root", "/etc/passwd", "/safe/root", false},
		{"sibling directory", "../sibling/file.txt", "/safe/root", false},
		{"same directory", "./file.txt", "/safe/root", true},
		{"subdirectory", "subdir/file.txt", "/safe/root", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isSafePath(tc.path, tc.root)
			if result != tc.expected {
				t.Errorf("isSafePath(%q, %q) = %v, expected %v", tc.path, tc.root, result, tc.expected)
			}
		})
	}
}
