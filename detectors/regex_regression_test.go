import (
	"os"
)
package detectors

import (
	"strings"
	"testing"
	"time"

	"minesweep/filesystem"
)

// TestRegression_ReDoS tests that dangerous regex patterns are rejected
// (Issue 4.4)
func TestRegression_ReDoS(t *testing.T) {
	testCases := []struct {
		name    string
		pattern string
		shouldFail bool
	}{
		{"safe pattern", `[a-z]+`, false},
		{"safe pattern with quantifier", `[a-z]{5,10}`, false},
		{"safe pattern with star", `[a-z]*`, false},
		{"ReDoS pattern 1", `(a+)+$`, true},
		{"ReDoS pattern 2", `(a*)*a`, true},
		{"ReDoS pattern 3", `(a+){1,}`, true},
		{"ReDoS pattern 4", `(a*)+`, true},
		{"ReDoS pattern 5", `a++`, true},
		{"ReDoS pattern 6", `a**`, true},
		{"ReDoS pattern 7", `a*+`, true},
		{"ReDoS pattern 8", `a+*`, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pattern := Pattern{
				Regex:      tc.pattern,
				Confidence: 0.5,
			}
			
			err := pattern.compile()
			
			if tc.shouldFail {
				if err == nil {
					t.Errorf("Expected error for pattern %q, but got none", tc.pattern)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for pattern %q: %v", tc.pattern, err)
				}
			}
		})
	}
}

// TestRegression_ReDoS_Timeout tests that regex matching doesn't hang
// (Issue 4.4)
func TestRegression_ReDoS_Timeout(t *testing.T) {
	// Create a detector with a safe pattern
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Skip("Skipping test, could not load rules")
	}

	// Create a file with content that would cause ReDoS with a bad pattern
	// But our safe patterns should handle it quickly
	content := []byte(strings.Repeat("a", 10000))
	file := &filesystem.File{
		Path:    "test.txt",
		Content: content,
		Size:    int64(len(content)),
		Mode:    0644,
	}

	// This should complete quickly, not hang
	done := make(chan bool, 1)
	go func() {
		_ = d.Detect(file)
		done <- true
	}()

	select {
	case <-done:
		// Success - completed without hanging
	case <-time.After(1 * time.Second):
		t.Fatal("Regex matching timed out - possible ReDoS vulnerability")
	}
}

// TestRegression_ResourceExhaustion tests that resource limits are respected
// (Issues 4.5, 4.6)
func TestRegression_ResourceExhaustion(t *testing.T) {
	// Test with a large file that exceeds max file size
	// This should be skipped by the walker
	
	// Create a temporary large file
	tmpFile, err := os.CreateTemp("", "minesweep-large-test")
	if err != nil {
		t.Skip("Skipping test, could not create temp file")
	}
	defer os.Remove(tmpFile.Name())
	
	// Write 100MB of data (larger than default 50MB limit)
	largeContent := make([]byte, 100*1024*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}
	if _, err := tmpFile.Write(largeContent); err != nil {
		t.Skip("Skipping test, could not write large file")
	}
	if err := tmpFile.Close(); err != nil {
		t.Skip("Skipping test, could not close file")
	}
	
	// Try to scan with a walker that has default max file size
	files, err := WalkWithOptions("/tmp", WalkOption{
		MaxFileSize: DefaultMaxFileSize,
		SkipExtensions: []string{".go", ".txt"}, // Skip most files
	})
	if err != nil {
		t.Skip("Skipping test, walk failed")
	}
	
	// The large file should not be in the results
	for _, f := range files {
		if f.Path == tmpFile.Name() {
			t.Error("Large file was not skipped by max file size limit")
		}
	}
}
