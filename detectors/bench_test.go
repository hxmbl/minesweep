package detectors

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"minesweep/filesystem"
)

func benchContent() []byte {
	var b strings.Builder
	line := 0
	for b.Len() < 400*1024 {
		switch line % 10 {
		case 0:
			fmt.Fprintf(&b, "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
		case 1:
			fmt.Fprintf(&b, "password: \"super-secret-password-%d\"\n", line)
		case 2:
			fmt.Fprintf(&b, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n")
		case 3:
			fmt.Fprintf(&b, "postgres://admin:p4ssw0rd@db.example.com:5432/prod?sslmode=require\n")
		case 4:
			fmt.Fprintf(&b, "xK9mP2vL8nQ4wR7tY6uI5oP3aS1dF0gH2jK4lZ9xC8vB7nM6\n")
		case 5:
			fmt.Fprintf(&b, "const greeting = \"hello world\"; // ordinary code line %d\n", line)
		case 6:
			fmt.Fprintf(&b, "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgc3RyaW5nIQ==\n")
		case 7:
			fmt.Fprintf(&b, "github_token = ghp_abcdefghijklmnopqrstuvwxyz1234567890\n")
		case 8:
			fmt.Fprintf(&b, "# just a comment line with some padding text %d\n", line)
		default:
			fmt.Fprintf(&b, "export function compute(input) { return input * 42; }\n")
		}
		line++
	}
	return []byte(b.String())
}

func benchFile(tb testing.TB, content []byte) *filesystem.File {
	tb.Helper()
	return &filesystem.File{
		Path:     "bench.txt",
		Content:  content,
		Mode:     0644,
		Size:     int64(len(content)),
		IsBinary: false,
	}
}

func BenchmarkMixedContentRegex(b *testing.B) {
	content := benchContent()
	det, err := NewRegexDetector(filepath.Join("..", "rules"))
	if err != nil {
		b.Fatal(err)
	}
	file := benchFile(b, content)
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if r := det.Detect(file); len(r) == 0 {
			b.Fatal("expected findings")
		}
	}
}

func BenchmarkMixedContentEntropy(b *testing.B) {
	content := benchContent()
	det := NewEntropyDetector()
	file := benchFile(b, content)
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(file)
	}
}

func BenchmarkMixedContentBase64(b *testing.B) {
	content := benchContent()
	rx, err := NewRegexDetector(filepath.Join("..", "rules"))
	if err != nil {
		b.Fatal(err)
	}
	det := NewBase64DetectorWithRegex(rx)
	file := benchFile(b, content)
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(file)
	}
}

func BenchmarkMixedContentDatabase(b *testing.B) {
	content := benchContent()
	det := NewDatabaseDetector()
	file := benchFile(b, content)
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(file)
	}
}

func BenchmarkMixedContentOAuth(b *testing.B) {
	content := benchContent()
	det := NewOAuthDetector()
	file := benchFile(b, content)
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = det.Detect(file)
	}
}

func BenchmarkShannonEntropy(b *testing.B) {
	s := "xK9mP2vL8nQ4wR7tY6uI5oP3aS1dF0gH2jK4lZ9xC8vB7nM6qW1eR4"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = shannonEntropy(s)
	}
}
