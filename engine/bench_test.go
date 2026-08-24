package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// BenchmarkEndToEnd builds a temp tree and scans it through the full engine,
// exercising walk + read + detect + finalize.
func BenchmarkEndToEnd(b *testing.B) {
	content := benchContent()
	root := b.TempDir()
	for i := 0; i < 20; i++ {
		dir := filepath.Join(root, fmt.Sprintf("pkg%02d", i))
		if err := os.MkdirAll(dir, 0755); err != nil {
			b.Fatal(err)
		}
		for j := 0; j < 10; j++ {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file%d.go", j)), content, 0644); err != nil {
				b.Fatal(err)
			}
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng, err := New(Config{Workers: 4})
		if err != nil {
			b.Fatal(err)
		}
		rep, err := eng.Run(root)
		if err != nil {
			b.Fatal(err)
		}
		if len(rep.Findings) == 0 {
			b.Fatal("expected findings")
		}
	}
}
