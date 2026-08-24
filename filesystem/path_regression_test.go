package filesystem

import (
	"testing"
)

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
