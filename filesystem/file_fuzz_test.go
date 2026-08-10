// +build gofuzz

package filesystem

import (
	"path/filepath"
)

// FuzzPathTraversal fuzzes path traversal detection
func FuzzPathTraversal(f *testing.F) {
	// Seed corpus with various path patterns
	f.Add([]byte("safe/path"))
	f.Add([]byte("../etc/passwd"))
	f.Add([]byte("../../../etc/passwd"))
	f.Add([]byte("/etc/passwd"))
	f.Add([]byte("path/../other"))
	f.Add([]byte(""))
	f.Add([]byte("."))
	f.Add([]byte(".."))
	f.Add([]byte("/"))
	f.Add([]byte("//"))
	f.Add([]byte("path//to//file"))

	f.Fuzz(func(t *testing.T, data []byte) {
		path := string(data)
		root := "/safe/root"
		
		// This should not panic
		safe := isSafePath(path, root)
		_ = safe
	})
}

// FuzzSanitizeBranchName fuzzes branch name sanitization
func FuzzSanitizeBranchName(f *testing.F) {
	// Seed corpus
	f.Add([]byte("main"))
	f.Add([]byte("feature/branch"))
	f.Add([]byte("fix-bug"))
	f.Add([]byte("test_branch"))
	f.Add([]byte("branch.with.dots"))
	f.Add([]byte("branch; rm -rf /"))
	f.Add([]byte("branch | cat /etc/passwd"))
	f.Add([]byte("branch && echo hacked"))
	f.Add([]byte("branch `whoami`"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		name := string(data)
		// This should not panic
		sanitized, err := sanitizeBranchName(name)
		_ = sanitized
		_ = err
	})
}

// FuzzNewFileWithRoot fuzzes file creation with path traversal protection
func FuzzNewFileWithRoot(f *testing.F) {
	// Seed corpus - these won't actually create files, just test the path logic
	f.Add([]byte("test.txt"))
	f.Add([]byte("/tmp/test.txt"))
	f.Add([]byte("../test.txt"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		path := string(data)
		root := "/safe/root"
		
		// We can't actually create files in fuzzing, but we can test the logic
		// by checking if the path would be safe
		if path != "" {
			safe := isSafePath(path, root)
			_ = safe
		}
	})
}
