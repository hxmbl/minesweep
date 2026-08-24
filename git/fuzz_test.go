package git

import (
	"testing"
)

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
		sanitized, err := SanitizeBranchName(name)
		_ = sanitized
		_ = err
	})
}
