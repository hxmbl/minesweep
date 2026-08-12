package detectors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"minesweep/filesystem"
)

func TestRegexDetectorNoFalsePositives(t *testing.T) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}

	safeFiles := map[string]string{
		"empty.go":               "",
		"hello_world.go":         "package main\n\nfunc main() {\n\tprintln(\"hello\")\n}\n",
		"just_README.md":         "# My Project\n\nThis is a safe project.\n",
		"plain_text.txt":         "The quick brown fox jumps over the lazy dog.\n",
		"numbers.txt":            "12345 67890 1112131415 1617181920\n",
		"urls.txt":               "https://example.com/page?q=search&limit=10\n",
		"html_page.html":         "<html><body><h1>Hello</h1><p>World</p></body></html>\n",
		"css_styles.css":         "body { margin: 0; padding: 0; background: #fff; }\n",
		"sql_query.sql":          "SELECT id, name, email FROM users WHERE active = 1;\n",
		"json_data.json":         `{"users":[{"id":1,"name":"John"}],"total":100}` + "\n",
		"yaml_config.yml":        "server:\n  port: 8080\n  host: localhost\n",
	}

	for name, content := range safeFiles {
		t.Run(name, func(t *testing.T) {
			file := &filesystem.File{
				Path:    name,
				Content: []byte(content),
			}
			fResults := d.Detect(file)
			if len(fResults) > 0 {
				for _, f := range fResults {
					t.Logf("  false positive: %s (%.0f%%)", f.Type, f.Confidence*100)
				}
				t.Fatalf("expected 0 findings for safe file %q, got %d", name, len(fResults))
			}
		})
	}
}

func TestRegexDetectorEdgeCases(t *testing.T) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}

	tests := []struct {
		name    string
		content string
		wantMin int
	}{
		{
			name:    "fake JWT with invalid header",
			content: `eyJmb28iOiAiYmFyIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.ZnV6enkK`,
			wantMin: 1,
		},
		{
			name:    "JWT in URL query params",
			content: `https://api.example.com/auth?access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqPnd9Z1X1jK2FzR0pJIXO6Q64g0lGg`,
			wantMin: 2,
		},
		{
			name: "AWS key in code example",
			content: `# Example configuration
# AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
# aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`,
			wantMin: 1,
		},
		{
			name:    "password in URL",
			content: `password=postgres://user:pass@localhost:5432/mydb`,
			wantMin: 1,
		},
		{
			name:    "private key in PEM file",
			content: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0gM\n-----END RSA PRIVATE KEY-----\n",
			wantMin: 2,
		},
		{
			name:    "Slack token",
			content: `slack_token=xoxb-123456789012-1234567890123-abc123def456ghi789jkl`,
			wantMin: 1,
		},
		{
			name:    "GitHub PAT",
			content: `GITHUB_TOKEN=ghp_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz0`,
			wantMin: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := &filesystem.File{
				Path:    "test.txt",
				Content: []byte(tt.content),
			}
			fResults := d.Detect(file)
			if len(fResults) < tt.wantMin {
				t.Errorf("expected at least %d findings, got %d", tt.wantMin, len(fResults))
				for _, f := range fResults {
					t.Logf("  found: %s (%.0f%%)", f.Type, f.Confidence*100)
				}
			}
		})
	}
}

func TestRegexDetectorLargeInput(t *testing.T) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}

	largeContent := strings.Repeat("hello world this is a safe file\n", 10000) + "AKIAIOSFODNN7EXAMPLE\n"
	file := &filesystem.File{
		Path:    "large.txt",
		Content: []byte(largeContent),
	}
	fResults := d.Detect(file)
	if len(fResults) == 0 {
		t.Fatal("expected to find AWS key even in large file")
	}
}

func TestFileTypeDetectorBinary(t *testing.T) {
	d := NewFileTypeDetector()

	tests := []struct {
		name     string
		file     *filesystem.File
		wantFind int
	}{
		{
			name: "ELF binary",
			file: &filesystem.File{
				Path:     "executable",
				Content:  []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0},
				IsBinary: true,
				Mode:     0755,
			},
			wantFind: 2,
		},
		{
			name: "text file",
			file: &filesystem.File{
				Path:     "readme.md",
				Content:  []byte("# hello"),
				IsBinary: false,
				Mode:     0644,
			},
			wantFind: 0,
		},
		{
			name: "executable text script",
			file: &filesystem.File{
				Path:     "script.sh",
				Content:  []byte("#!/bin/bash\necho hi\n"),
				IsBinary: false,
				Mode:     0755,
			},
			wantFind: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fResults := d.Detect(tt.file)
			if len(fResults) != tt.wantFind {
				t.Errorf("expected %d findings, got %d", tt.wantFind, len(fResults))
				for _, f := range fResults {
					t.Logf("  found: %s", f.Type)
				}
			}
		})
	}
}

func TestSymlinkDetectorBroken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}

	dir := t.TempDir()
	link := filepath.Join(dir, "broken-link")
	err := os.Symlink("nonexistent-target", link)
	if err != nil {
		t.Skip("symlinks not supported:", err)
	}

	f, err := filesystem.NewFile(link)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}

	d := NewSymlinkDetector()
	fResults := d.Detect(f)
	if len(fResults) == 0 {
		t.Fatal("expected findings for broken symlink")
	}
}

func TestSymlinkDetectorRegularFile(t *testing.T) {
	d := NewSymlinkDetector()
	f := &filesystem.File{
		Path:      "regular.txt",
		IsSymlink: false,
	}
	fResults := d.Detect(f)
	if len(fResults) != 0 {
		t.Fatal("expected 0 findings for regular file")
	}
}

// ─── Brutal regex detector tests ──────────────────────────────────────

func TestRegexDetectorEmptyFile(t *testing.T) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	file := &filesystem.File{
		Path:    "empty.txt",
		Content: []byte{},
	}
	fResults := d.Detect(file)
	if len(fResults) != 0 {
		t.Fatalf("expected 0 findings for empty file, got %d", len(fResults))
	}
}

func TestRegexDetectorBinaryContent(t *testing.T) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	binContent := make([]byte, 256)
	for i := range binContent {
		binContent[i] = byte(i)
	}
	file := &filesystem.File{
		Path:    "binary.bin",
		Content: binContent,
	}
	fResults := d.Detect(file)
	// Must not panic; binary content is valid regex input
	t.Logf("binary content produced %d findings (expected graceful handling)", len(fResults))
}

func TestRegexDetectorUnicodeContent(t *testing.T) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	content := `# ☕ java config
DB_PASSWORD=☕☕☕☕☕☕☕☕☕☕
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
# 你好世界
SECRET=秘密
`
	file := &filesystem.File{
		Path:    "unicode.txt",
		Content: []byte(content),
	}
	fResults := d.Detect(file)
	found := false
	for _, f := range fResults {
		if f.Type == "AWS Access Key ID" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected to find AWS key in unicode content")
	}
}

func TestRegexDetectorVeryLongLines(t *testing.T) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	longPrefix := strings.Repeat("A", 100000)
	content := longPrefix + " PASSWORD=secret123\n"
	file := &filesystem.File{
		Path:    "long.txt",
		Content: []byte(content),
	}
	fResults := d.Detect(file)
	if len(fResults) == 0 {
		t.Fatal("expected findings in file with very long line")
	}
}

func TestRegexDetectorSecretsAtPositions(t *testing.T) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}

	t.Run("secret_at_end_of_large", func(t *testing.T) {
		content := strings.Repeat("safe line\n", 5000) + "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
		file := &filesystem.File{
			Path:    "large.txt",
			Content: []byte(content),
		}
		fResults := d.Detect(file)
		found := false
		for _, f := range fResults {
			if f.Type == "AWS Access Key ID" {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("expected to find secret at end of large file")
		}
	})

	t.Run("multiple_secrets_scattered", func(t *testing.T) {
		var lines []string
		for i := 0; i < 100; i++ {
			lines = append(lines, fmt.Sprintf("line%d = safe\n", i))
		}
		lines[0] = "GITHUB_TOKEN=ghp_abc123def456ghi789jkl012mno345pqr678stu901vwx234yz0\n"
		lines[50] = "slack_token=xoxb-123456789012-1234567890123-abc123def456ghi789jkl\n"
		lines[99] = "-----BEGIN RSA PRIVATE KEY-----\n"
		content := strings.Join(lines, "")

		file := &filesystem.File{
			Path:    "scattered.txt",
			Content: []byte(content),
		}
		fResults := d.Detect(file)
		if len(fResults) < 3 {
			t.Fatalf("expected at least 3 findings for scattered secrets, got %d", len(fResults))
		}
	})

	t.Run("secret_on_every_line", func(t *testing.T) {
		var lines []string
		for i := 0; i < 100; i++ {
			lines = append(lines, fmt.Sprintf("PASSWORD=secret%03d\n", i))
		}
		content := strings.Join(lines, "")
		file := &filesystem.File{
			Path:    "all_secrets.txt",
			Content: []byte(content),
		}
		fResults := d.Detect(file)
		if len(fResults) < 100 {
			t.Fatalf("expected 100+ findings for 100 secret lines (8+ chars each), got %d", len(fResults))
		}
	})
}

func TestRegexDetectorSecretsInComments(t *testing.T) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}

	content := `// TODO: remove this before commit
// AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
// password = super-secret-12345
// slack token: xoxb-123456789012-1234567890123-abc123def456ghi789jkl
//
// func main() {
//     db.connect("postgres://user:pass@localhost/db")
// }
`
	file := &filesystem.File{
		Path:    "commented.go",
		Content: []byte(content),
	}
	fResults := d.Detect(file)
	if len(fResults) == 0 {
		t.Fatal("expected findings for secrets hidden in comments")
	}
}

// ─── Brutal file type detector tests ─────────────────────────────────

func TestFileTypeDetectorAllCombinations(t *testing.T) {
	d := NewFileTypeDetector()

	type combo struct {
		name     string
		binary   bool
		exec     bool
		symlink  bool
		wantFind int
	}
	allCombos := []combo{
		{"plain_text", false, false, false, 0},
		{"executable_only", false, true, false, 1},
		{"binary_only", true, false, false, 1},
		{"binary_and_executable", true, true, false, 2},
		// FileTypeDetector only checks binary and executable bits
		{"symlink_only", false, false, true, 0},
		{"symlink_and_binary", true, false, true, 1},
		{"symlink_and_executable", false, true, true, 1},
		{"all_flags", true, true, true, 2},
	}
	for _, c := range allCombos {
		t.Run(c.name, func(t *testing.T) {
			file := &filesystem.File{
				Path:      "test",
				IsBinary:  c.binary,
				IsSymlink: c.symlink,
			}
			if c.exec {
				file.Mode = 0755
			}
			fResults := d.Detect(file)
			if len(fResults) != c.wantFind {
				t.Errorf("expected %d findings for (%s), got %d", c.wantFind, c.name, len(fResults))
			}
		})
	}
}

// ─── Brutal symlink detector tests ──────────────────────────────────

func TestSymlinkDetectorEmptyTarget(t *testing.T) {
	d := NewSymlinkDetector()
	f := &filesystem.File{
		Path:          "link",
		IsSymlink:     true,
		SymlinkTarget: "",
	}
	fResults := d.Detect(f)
	if len(fResults) != 1 {
		t.Fatal("expected 1 finding for symlink with empty target")
	}
}

func TestSymlinkDetectorNormalFileVariousPaths(t *testing.T) {
	d := NewSymlinkDetector()
	paths := []string{
		"/etc/passwd",
		"/",
		"C:\\Windows\\system32",
		"",
		"../relative/link",
		"./././././link",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			f := &filesystem.File{
				Path:      p,
				IsSymlink: false,
			}
			fResults := d.Detect(f)
			if len(fResults) != 0 {
				t.Errorf("expected 0 findings for non-symlink path %q, got %d", p, len(fResults))
			}
		})
	}
}

func TestLoadRulesFilterByType(t *testing.T) {
	d, err := NewRegexDetector("../rules")
	if err != nil {
		t.Fatalf("NewRegexDetector: %v", err)
	}
	if len(d.rules) == 0 {
		t.Fatal("expected at least 1 regex rule")
	}
	for _, r := range d.rules {
		if r.Type != "regex" {
			t.Errorf("expected rule %q to have type 'regex', got %q", r.ID, r.Type)
		}
	}
}
