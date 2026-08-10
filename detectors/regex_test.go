package detectors

import (
	"strings"
	"testing"

	"minesweep/filesystem"
)

// BenchmarkRegexDetector benchmarks the regex detector performance
func BenchmarkRegexDetector(b *testing.B) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		b.Fatalf("Failed to create regex detector: %v", err)
	}

	// Create test content with a secret
	content := []byte(strings.Repeat("safe content\n", 1000) + "AKIAIOSFODNN7EXAMPLE\n" + strings.Repeat("more safe content\n", 1000))
	file := &filesystem.File{
		Path:    "test.txt",
		Content: content,
		Size:    int64(len(content)),
		Mode:    0644,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(file)
	}
}

// BenchmarkRegexDetectorLargeFile benchmarks with a large file
func BenchmarkRegexDetectorLargeFile(b *testing.B) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		b.Fatalf("Failed to create regex detector: %v", err)
	}

	// Create a large file (1MB)
	content := []byte(strings.Repeat("safe content\n", 100000))
	file := &filesystem.File{
		Path:    "large.txt",
		Content: content,
		Size:    int64(len(content)),
		Mode:    0644,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(file)
	}
}

// BenchmarkRegexDetectorManySecrets benchmarks with many secrets in the file
func BenchmarkRegexDetectorManySecrets(b *testing.B) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		b.Fatalf("Failed to create regex detector: %v", err)
	}

	// Create content with many secrets
	var secrets []string
	for i := 0; i < 100; i++ {
		secrets = append(secrets, "AKIAIOSFODNN7EXAMPLE")
	}
	content := []byte(strings.Join(secrets, "\n"))
	file := &filesystem.File{
		Path:    "many_secrets.txt",
		Content: content,
		Size:    int64(len(content)),
		Mode:    0644,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(file)
	}
}

// BenchmarkEntropyDetector benchmarks the entropy detector
func BenchmarkEntropyDetector(b *testing.B) {
	d := NewEntropyDetector()

	// Create test content
	content := []byte(strings.Repeat("safe content\n", 1000))
	file := &filesystem.File{
		Path:    "test.txt",
		Content: content,
		Size:    int64(len(content)),
		Mode:    0644,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(file)
	}
}

// BenchmarkDatabaseDetector benchmarks the database detector
func BenchmarkDatabaseDetector(b *testing.B) {
	d := NewDatabaseDetector()

	// Create test content with a database URL
	content := []byte("postgresql://user:password@localhost:5432/database\n" + strings.Repeat("safe content\n", 1000))
	file := &filesystem.File{
		Path:    "test.txt",
		Content: content,
		Size:    int64(len(content)),
		Mode:    0644,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(file)
	}
}

// BenchmarkOAuthDetector benchmarks the OAuth detector
func BenchmarkOAuthDetector(b *testing.B) {
	d := NewOAuthDetector()

	// Create test content with a JWT token
	content := []byte("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n" + strings.Repeat("safe content\n", 1000))
	file := &filesystem.File{
		Path:    "test.txt",
		Content: content,
		Size:    int64(len(content)),
		Mode:    0644,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Detect(file)
	}
}
