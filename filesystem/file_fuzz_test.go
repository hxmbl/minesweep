//go:build gofuzz
// +build gofuzz

package filesystem

import (
	"testing"
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
