package filesystem

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestIsBinaryMagicBytes(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"ELF", []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}, true},
		{"PE/MZ", []byte{'M', 'Z', 0, 0, 0, 0, 0, 0}, true},
		{"PDF", []byte{'%', 'P', 'D', 'F', '1', '.', '4'}, true},
		{"PNG", []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, true},
		{"ZIP", []byte{'P', 'K', 0x03, 0x04, 0, 0, 0, 0}, true},
		{"GZIP", []byte{0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0}, true},
		{"BZ2", []byte{0x42, 0x5a, 0x68, 0x39}, true},
		{"XZ", []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}, true},
		{"MachO-32be", []byte{0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0}, true},
		{"MachO-64be", []byte{0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 0}, true},
		{"MachO-32le", []byte{0xce, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}, true},
		{"MachO-64le", []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBinary(tt.data); got != tt.want {
				t.Errorf("IsBinary(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsBinaryNullByte(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"single null middle", []byte("hello\x00world"), true},
		{"single null start", []byte{0x00, 'h', 'e', 'l', 'l', 'o'}, true},
		{"single null end", []byte("hello\x00"), true},
		{"only nulls", []byte{0x00, 0x00, 0x00}, true},
		{"no nulls", []byte("hello world\n"), false},
		{"empty", []byte{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBinary(tt.data); got != tt.want {
				t.Errorf("IsBinary(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsBinaryControlChars(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		want   bool
		reason string
	}{
		{"more than 10% control", bytesWithControlChars(100, 15), true, "15% control chars"},
		{"less than 10% control", bytesWithControlChars(100, 5), false, "5% control chars"},
		{"tab newline cr are ok", []byte("\t\n\r\t\n\rhello world"), false, "whitespace only"},
		{"exactly at threshold", bytesWithControlChars(100, 10), false, "10% threshold not exceeded"},
		{"one above threshold", bytesWithControlChars(100, 11), true, "11% exceeds 10%"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBinary(tt.data); got != tt.want {
				t.Errorf("IsBinary(%s) = %v, want %v", tt.reason, got, tt.want)
			}
		})
	}
}

func bytesWithControlChars(total, control int) []byte {
	b := make([]byte, total)
	for i := 0; i < control; i++ {
		b[i] = 0x01 // control char
	}
	for i := control; i < total; i++ {
		b[i] = 'x'
	}
	return b
}

func TestIsBinaryTextFormats(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"plain ASCII", []byte("package main\n\nfunc main() {}\n"), false},
		{"markdown", []byte("# Title\n\nSome *text* with `code`\n"), false},
		{"JSON", []byte(`{"key": "value", "nested": {"a": 1}}`), false},
		{"YAML", []byte("key: value\nlist:\n  - item1\n  - item2\n"), false},
		{"HTML with tags", []byte("<html><body><p>Hello</p></body></html>\n"), false},
		{"Go source", []byte("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"hello\")\n}\n"), false},
		{"Python source", []byte("def hello():\n    print(\"world\")\n\nif __name__ == \"__main__\":\n    hello()\n"), false},
		{"shell script", []byte("#!/bin/bash\n\necho \"Hello World\"\nfor i in 1 2 3; do\n  echo $i\ndone\n"), false},
		{"CSV", []byte("name,age,email\nJohn,30,john@example.com\nJane,25,jane@example.com\n"), false},
		{"XML", []byte("<?xml version=\"1.0\"?>\n<root><item id=\"1\">value</item></root>\n"), false},
		{"SQL", []byte("SELECT * FROM users WHERE id = 1;\nINSERT INTO logs VALUES ('test');\n"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBinary(tt.data); got != tt.want {
				t.Errorf("IsBinary(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsBinaryMixedContent(t *testing.T) {
	largeText := strings.Repeat("hello world this is text content\n", 1000)
	if IsBinary([]byte(largeText)) {
		t.Fatal("large text should not be binary")
	}

	pngInText := append([]byte("this file has a PNG signature at the end: \n"), []byte{0x89, 'P', 'N', 'G'}...)
	if IsBinary(pngInText) {
		t.Fatal("text with trailing magic bytes should not be binary")
	}
}

func TestIsUTF8(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"ASCII", []byte("hello world"), true},
		{"UTF-8 2byte", []byte("caf\xc3\xa9"), true},
		{"UTF-8 3byte", []byte("\xe2\x82\xac"), true},
		{"UTF-8 4byte", []byte("\xf0\x9f\x92\xa9"), true},
		{"invalid 2byte", []byte{0xc0, 0x00}, false},
		{"invalid 3byte", []byte{0xe0, 0x00, 0x00}, false},
		{"invalid 4byte", []byte{0xf0, 0x00, 0x00, 0x00}, false},
		{"starts with 0xFF", []byte{0xFF, 0xFE}, false},
		{"empty", []byte{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUTF8(tt.data); got != tt.want {
				t.Errorf("IsUTF8(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestHasBOM(t *testing.T) {
	tests := []struct {
		name  string
		data  []byte
		enc   string
		found bool
	}{
		{"UTF-8 BOM", []byte{0xEF, 0xBB, 0xBF, 'h', 'e', 'l', 'l', 'o'}, "utf-8", true},
		{"UTF-16 LE BOM", []byte{0xFF, 0xFE, 'h', 0x00, 'i', 0x00}, "utf-16-le", true},
		{"UTF-16 BE BOM", []byte{0xFE, 0xFF, 0x00, 'h', 0x00, 'i'}, "utf-16-be", true},
		{"no BOM", []byte("hello"), "", false},
		{"empty", []byte{}, "", false},
		{"partial BOM", []byte{0xEF, 0xBB}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, found := HasBOM(tt.data)
			if found != tt.found || enc != tt.enc {
				t.Errorf("HasBOM = (%q, %v), want (%q, %v)", enc, found, tt.enc, tt.found)
			}
		})
	}
}

func TestIsTextFile(t *testing.T) {
	tests := []struct {
		ext  string
		want bool
	}{
		{".go", true}, {".rs", true}, {".py", true}, {".js", true}, {".ts", true},
		{".md", true}, {".txt", true}, {".yaml", true}, {".json", true},
		{".png", false}, {".exe", false}, {".zip", false}, {".mp4", false},
		{".unknown", false}, {"", false},
	}
	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			if got := IsTextFile(tt.ext); got != tt.want {
				t.Errorf("IsTextFile(%q) = %v, want %v", tt.ext, got, tt.want)
			}
		})
	}
}

func TestIsBinaryFile(t *testing.T) {
	tests := []struct {
		ext  string
		want bool
	}{
		{".png", true}, {".exe", true}, {".zip", true}, {".mp4", true},
		{".go", false}, {".txt", false}, {".md", false},
		{".unknown", false}, {"", false},
	}
	for _, tt := range tests {
		t.Run(tt.ext, func(t *testing.T) {
			if got := IsBinaryFile(tt.ext); got != tt.want {
				t.Errorf("IsBinaryFile(%q) = %v, want %v", tt.ext, got, tt.want)
			}
		})
	}
}

func TestNewFileSymlink(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original.txt")
	link := filepath.Join(dir, "link.txt")

	os.WriteFile(original, []byte("real content\n"), 0644)

	err := os.Symlink("original.txt", link)
	if err != nil {
		t.Skip("symlinks not supported:", err)
	}

	f, err := NewFile(link)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if err := f.LoadContent(); err != nil {
		t.Fatalf("LoadContent: %v", err)
	}
	if !f.IsSymlink {
		t.Fatal("expected symlink flag")
	}
	if f.SymlinkTarget == "" {
		t.Fatal("expected symlink target")
	}
	if string(f.Content) != "real content\n" {
		t.Fatalf("expected to read through symlink, got %q", string(f.Content))
	}
}

func TestNewFileExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "script.sh")
	os.WriteFile(path, []byte("#!/bin/bash\necho hi\n"), 0755)

	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if !f.IsExecutable() {
		t.Fatal("expected executable flag")
	}
	if f.IsBinary {
		t.Fatal("shell script is not binary")
	}
}

func TestNewFileUTF16(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "utf16.txt")

	utf16le := []byte{0xFF, 0xFE, 'h', 0x00, 'e', 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00}
	os.WriteFile(path, utf16le, 0644)

	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if err := f.LoadContent(); err != nil {
		t.Fatalf("LoadContent: %v", err)
	}
	if !f.IsBinary {
		t.Fatal("UTF-16 file should be detected as binary (null bytes)")
	}
}

func TestIgnorePatternGitignoreStyle(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		path     string
		ignored  bool
	}{
		{"simple glob", []string{"*.log"}, "debug.log", true},
		{"not matching", []string{"*.log"}, "main.go", false},
		{"comment", []string{"# this is a comment", "*.log"}, "debug.log", true},
		{"blank line", []string{"", "*.log"}, "debug.log", true},
		{"negation", []string{"*.log", "!important.log"}, "important.log", false},
		{"negation override", []string{"*.log", "!important.log"}, "debug.log", true},
		{"directory", []string{"build/"}, "build/output.o", true},
		{"subdirectory", []string{"build/"}, "src/build/file.o", true},
		{"vendor without star", []string{"vendor/"}, "vendor/pkg/file.go", true},
		{"vendor star single level", []string{"vendor/*"}, "vendor/pkg", true},
		{"vendor star no deep", []string{"vendor/*"}, "vendor/pkg/file.go", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := NewIgnorePattern(tt.patterns)
			if got := ip.Ignored(tt.path); got != tt.ignored {
				t.Errorf("Ignored(%q) = %v, want %v", tt.path, got, tt.ignored)
			}
		})
	}
}

func TestLoadMinesweepIgnore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".minesweepignore")
	content := "# MineSweep ignore file\n*.log\nbuild/\n!important.log\n"
	os.WriteFile(path, []byte(content), 0644)

	ip, err := LoadMinesweepIgnore(path)
	if err != nil {
		t.Fatalf("LoadMinesweepIgnore: %v", err)
	}
	if !ip.Ignored("debug.log") {
		t.Fatal("*.log should be ignored")
	}
	if !ip.Ignored("build/output.o") {
		t.Fatal("build/ should be ignored")
	}
	if ip.Ignored("important.log") {
		t.Fatal("!important.log should NOT be ignored")
	}
}

func TestLoadMissingMinesweepIgnore(t *testing.T) {
	ip, err := LoadMinesweepIgnore("/nonexistent/.minesweepignore")
	if err != nil {
		t.Fatalf("LoadMinesweepIgnore for missing file: %v", err)
	}
	if ip.Ignored("anything") {
		t.Fatal("empty ignore should not ignore anything")
	}
}

func TestWalkWithIgnoreFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("keep"), 0644)
	os.WriteFile(filepath.Join(dir, "debug.log"), []byte("log"), 0644)
	os.WriteFile(filepath.Join(dir, "build.o"), []byte("obj"), 0644)

	ignoreContent := "*.log\n"
	os.WriteFile(filepath.Join(dir, ".minesweepignore"), []byte(ignoreContent), 0644)

	files, err := Walk(dir, nil, "")
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 files (skipping .log and .o via extension), got %d", len(files))
	}
	_ = files
}

func TestWalkSkipsVenvDotGit(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("main"), 0644)
	os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0755)
	os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("config"), 0644)
	os.MkdirAll(filepath.Join(dir, "node_modules", "pkg"), 0755)
	os.WriteFile(filepath.Join(dir, "node_modules", "pkg", "index.js"), []byte("module"), 0644)

	files, err := Walk(dir, nil, "")
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file (main.go), got %d", len(files))
	}
}

func TestNewFileBrokenSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "broken-link")
	err := os.Symlink("/nonexistent-target-xyz", link)
	if err != nil {
		t.Skip("symlinks not supported:", err)
	}

	f, err := NewFile(link)
	if err != nil {
		t.Fatalf("NewFile(broken symlink): %v", err)
	}
	if !f.IsSymlink {
		t.Fatal("expected symlink flag")
	}
	if !strings.Contains(f.SymlinkTarget, "broken") {
		t.Fatalf("expected broken symlink marker, got %q", f.SymlinkTarget)
	}
}

func TestWalkMaxFileSize(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "small.txt"), []byte("small"), 0644)
	large := make([]byte, 100)
	os.WriteFile(filepath.Join(dir, "large.txt"), large, 0644)

	files, err := WalkWithOptions(dir, WalkOption{MaxFileSize: 50})
	if err != nil {
		t.Fatalf("WalkWithOptions: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file (small.txt only), got %d", len(files))
	}
	if files[0].Path != filepath.Join(dir, "small.txt") {
		t.Fatalf("expected small.txt, got %s", files[0].Path)
	}
}

// ─── Brutal IsBinary tests ──────────────────────────────────────────────

func TestIsBinaryThresholdExact(t *testing.T) {
	t.Run("just_under_10pc", func(t *testing.T) {
		data := bytesWithControlChars(1000, 100)
		if IsBinary(data) {
			t.Fatal("exactly 10% control chars should not be binary")
		}
	})
	t.Run("just_over_10pc", func(t *testing.T) {
		data := bytesWithControlChars(1000, 101)
		if !IsBinary(data) {
			t.Fatal("10.1% control chars should be binary")
		}
	})
	t.Run("all_whitespace", func(t *testing.T) {
		data := []byte("\t\n\r   \t\n\r\t\n\r")
		if IsBinary(data) {
			t.Fatal("only whitespace control chars should not be binary")
		}
	})
	t.Run("control_at_end", func(t *testing.T) {
		data := append([]byte(strings.Repeat("x", 89)), 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01)
		if !IsBinary(data) {
			t.Fatal("11% control chars should be binary")
		}
	})
	t.Run("single_byte", func(t *testing.T) {
		if IsBinary([]byte("x")) {
			t.Fatal("single ASCII byte should not be binary")
		}
		if !IsBinary([]byte{0x00}) {
			t.Fatal("single null byte should be binary")
		}
	})
}

func TestIsBinaryVeryLargeText(t *testing.T) {
	data := make([]byte, 2<<20) // 2MB
	for i := range data {
		data[i] = byte('a' + i%26)
	}
	data[len(data)-1] = '\n'
	if IsBinary(data) {
		t.Fatal("2MB of ASCII text should not be binary")
	}
}

func TestIsBinaryMagicNotAtStart(t *testing.T) {
	data := []byte("This file has ELF magic in the middle: \x7fELF")
	if IsBinary(data) {
		t.Fatal("text with ELF magic in middle should not be binary")
	}
	data2 := []byte("PK\x03\x04")
	if !IsBinary(data2) {
		t.Fatal("ZIP magic at start should be binary")
	}
}

func TestIsBinaryAllPrintable(t *testing.T) {
	data := make([]byte, 95)
	for i := 0; i < 95; i++ {
		data[i] = byte(0x20 + i)
	}
	if IsBinary(data) {
		t.Fatal("all printable ASCII should not be binary")
	}
}

func TestIsBinaryMagicOnByteBoundary(t *testing.T) {
	t.Run("partial_magic_too_short", func(t *testing.T) {
		if IsBinary([]byte{0x7f}) {
			t.Fatal("single ELF byte should not match ELF magic")
		}
	})
	t.Run("magic_then_text", func(t *testing.T) {
		if !IsBinary([]byte{0x7f, 'E', 'L', 'F', 'h', 'e', 'l', 'l', 'o'}) {
			t.Fatal("ELF magic prefix should win over text content")
		}
	})
}

func TestIsBinaryEmptyAndNil(t *testing.T) {
	if IsBinary(nil) {
		t.Fatal("nil should not be binary")
	}
	if IsBinary([]byte{}) {
		t.Fatal("empty slice should not be binary")
	}
}

// ─── Brutal NewFile tests ──────────────────────────────────────────────

func TestNewFileEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	os.WriteFile(path, []byte{}, 0644)

	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile(empty): %v", err)
	}
	if len(f.Content) != 0 {
		t.Fatalf("expected empty content, got %d bytes", len(f.Content))
	}
	if f.Size != 0 {
		t.Fatalf("expected size 0, got %d", f.Size)
	}
}

func TestNewFilePermissionDenied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	os.WriteFile(path, []byte("data"), 0000)

	_, err := NewFile(path)
	if err == nil {
		// This might succeed if running as root; test is informational
		t.Log("NewFile succeeded on 0000 file (running as root?)")
	}
}

func TestNewFileSymlinkChain(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	link1 := filepath.Join(dir, "link1")
	link2 := filepath.Join(dir, "link2")

	os.WriteFile(target, []byte("chain content\n"), 0644)
	err := os.Symlink("target.txt", link1)
	if err != nil {
		t.Skip("symlinks not supported:", err)
	}
	err = os.Symlink("link1", link2)
	if err != nil {
		t.Skip("chained symlinks not supported:", err)
	}

	f, err := NewFile(link2)
	if err != nil {
		t.Fatalf("NewFile(chain): %v", err)
	}
	if err := f.LoadContent(); err != nil {
		t.Fatalf("LoadContent: %v", err)
	}
	if !f.IsSymlink {
		t.Fatal("expected symlink flag")
	}
	if string(f.Content) != "chain content\n" {
		t.Fatalf("expected to read through chain, got %q", string(f.Content))
	}
}

func TestNewFileSymlinkSelfLoop(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "self")
	err := os.Symlink("self", link)
	if err != nil {
		t.Skip("symlinks not supported:", err)
	}

	_, err = NewFile(link)
	// Should handle gracefully: either return a valid File or an error
	if err == nil {
		t.Log("NewFile handled self-loop symlink gracefully (returned non-nil)")
	}
}

func TestNewFileSymlinkCrossLoop(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	err := os.Symlink("b", a)
	if err != nil {
		t.Skip("symlinks not supported:", err)
	}
	err = os.Symlink("a", b)
	if err != nil {
		t.Skip("cross symlinks not supported:", err)
	}

	_, err = NewFile(a)
	if err == nil {
		t.Log("NewFile handled cross-loop symlink gracefully (returned non-nil)")
	}
}

func TestNewFileVeryLongPath(t *testing.T) {
	dir := t.TempDir()
	longName := strings.Repeat("a", 200) + ".txt"
	path := filepath.Join(dir, longName)
	os.WriteFile(path, []byte("deep path"), 0644)

	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile(long path): %v", err)
	}
	if err := f.LoadContent(); err != nil {
		t.Fatalf("LoadContent: %v", err)
	}
	if string(f.Content) != "deep path" {
		t.Fatalf("expected content 'deep path', got %q", string(f.Content))
	}
}

func TestNewFileSpecialCharacters(t *testing.T) {
	dir := t.TempDir()
	name := "file with spaces and (parens) & symbols!.txt"
	path := filepath.Join(dir, name)
	os.WriteFile(path, []byte("special"), 0644)

	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile(special name): %v", err)
	}
	if f.Path != path {
		t.Fatalf("expected path %q, got %q", path, f.Path)
	}
}

func TestNewFileNoExtension(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Makefile")
	os.WriteFile(path, []byte("all:\n\techo hi\n"), 0644)

	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile(no ext): %v", err)
	}
	if f.IsBinary {
		t.Fatal("Makefile should not be binary")
	}
}

func TestNewFileHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	os.WriteFile(path, []byte{0x00, 0x01, 0x02, 0x03}, 0644)

	f, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if err := f.LoadContent(); err != nil {
		t.Fatalf("LoadContent: %v", err)
	}
	if f.Hash == "" {
		t.Fatal("expected non-empty hash")
	}
}

// ─── Brutal Walk tests ───────────────────────────────────────────────

func TestWalkEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	files, err := Walk(dir, nil, "")
	if err != nil {
		t.Fatalf("Walk(empty): %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected 0 files in empty dir, got %d", len(files))
	}
}

func TestWalkOnlyDirectories(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "a", "b", "c"), 0755)
	os.MkdirAll(filepath.Join(dir, "x", "y"), 0755)

	files, err := Walk(dir, nil, "")
	if err != nil {
		t.Fatalf("Walk(only dirs): %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected 0 files in dir-only tree, got %d", len(files))
	}
}

func TestWalkAllIgnored(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "build.o"), []byte("obj"), 0644)
	os.WriteFile(filepath.Join(dir, "output.bin"), []byte("bin"), 0644)
	os.WriteFile(filepath.Join(dir, "lib.dll"), []byte("dll"), 0644)

	files, err := Walk(dir, nil, "")
	if err != nil {
		t.Fatalf("Walk(all ignored): %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected 0 files (all extensions blocked), got %d", len(files))
	}
}

func TestWalkPermissionDeniedSubdir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "readable.txt"), []byte("visible"), 0644)
	sub := filepath.Join(dir, "secret")
	os.MkdirAll(sub, 0755)
	os.WriteFile(filepath.Join(sub, "hidden.txt"), []byte("hidden"), 0644)
	os.Chmod(sub, 0000)
	defer os.Chmod(sub, 0755)

	files, err := Walk(dir, nil, "")
	if err != nil {
		t.Fatalf("Walk(denied subdir): %v", err)
	}
	foundHidden := false
	for _, f := range files {
		if strings.Contains(f.Path, "hidden.txt") {
			foundHidden = true
		}
	}
	if foundHidden {
		t.Fatal("should not have read files in permission-denied subdir")
	}
	if len(files) == 0 {
		t.Fatal("should have found readable.txt even with denied subdir")
	}
}

func TestWalkUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unreadable.txt")
	os.WriteFile(path, []byte("can't read me"), 0000)
	os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("fine"), 0644)

	files, err := Walk(dir, nil, "")
	if err != nil {
		t.Fatalf("Walk(unreadable): %v", err)
	}
	foundNormal := false
	for _, f := range files {
		if strings.HasSuffix(f.Path, "normal.txt") {
			foundNormal = true
		}
	}
	if !foundNormal {
		t.Fatal("normal.txt should have been found despite unreadable file")
	}
	_ = path
}

func TestWalkDeepNesting(t *testing.T) {
	dir := t.TempDir()
	current := dir
	tryDepth := 200
	for i := 0; i < tryDepth; i++ {
		current = filepath.Join(current, fmt.Sprintf("d%d", i))
		if err := os.Mkdir(current, 0755); err != nil {
			t.Skipf("mkdir at depth %d: %v", i, err)
		}
	}
	deepFile := filepath.Join(current, "deep.txt")
	if err := os.WriteFile(deepFile, []byte("deep"), 0644); err != nil {
		t.Skipf("write deep file: %v", err)
	}
	os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root"), 0644)

	files, err := Walk(dir, nil, "")
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files (root.txt + deep.txt at depth %d), got %d", tryDepth, len(files))
	}
}

func TestWalkMaxFileSizeBoundary(t *testing.T) {
	dir := t.TempDir()
	// Exactly boundary size
	exact := make([]byte, 100)
	os.WriteFile(filepath.Join(dir, "exact.txt"), exact, 0644)
	// One byte over
	over := make([]byte, 101)
	os.WriteFile(filepath.Join(dir, "over.txt"), over, 0644)
	// Way under
	os.WriteFile(filepath.Join(dir, "small.txt"), []byte("x"), 0644)

	files, err := WalkWithOptions(dir, WalkOption{MaxFileSize: 100})
	if err != nil {
		t.Fatalf("WalkWithOptions: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files (exact=100 + small=1), got %d: %v", len(files), files)
	}
}

func TestWalkHiddenDirsVariousDepths(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0755)
	os.WriteFile(filepath.Join(dir, ".git", "config"), []byte("git config"), 0644)
	os.WriteFile(filepath.Join(dir, ".git", "objects", "abc123"), []byte("obj"), 0644)

	os.MkdirAll(filepath.Join(dir, "src", ".git", "hooks"), 0755)
	os.WriteFile(filepath.Join(dir, "src", ".git", "hooks", "pre-commit"), []byte("hook"), 0644)

	os.WriteFile(filepath.Join(dir, "src", "main.go"), []byte("main"), 0644)

	files, err := Walk(dir, nil, "")
	if err != nil {
		t.Fatalf("Walk(.git at depth): %v", err)
	}
	for _, f := range files {
		if strings.Contains(f.Path, ".git") {
			t.Fatalf("found file inside .git: %s", f.Path)
		}
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 file (src/main.go), got %d", len(files))
	}
}

// ─── Brutal IgnorePattern tests ──────────────────────────────────────

func TestIgnorePatternSpecialGlobChars(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		path     string
		ignored  bool
	}{
		{"glob_star", []string{"*.log"}, "test.log", true},
		{"glob_question", []string{"test.???"}, "test.log", true},
		{"glob_range", []string{"[abc]*.go"}, "a_main.go", true},
		{"glob_range_no_match", []string{"[abc]*.go"}, "x_main.go", false},
		{"glob_double_star", []string{"a/**/b"}, "a/x/y/b", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := NewIgnorePattern(tt.patterns)
			if got := ip.Ignored(tt.path); got != tt.ignored {
				t.Errorf("Ignored(%q) = %v, want %v (patterns=%v)", tt.path, got, tt.ignored, tt.patterns)
			}
		})
	}
}

func TestIgnorePatternOnlyNegations(t *testing.T) {
	ip := NewIgnorePattern([]string{"!important.log"})
	if ip.Ignored("important.log") {
		t.Fatal("only negation with no prior pattern should not ignore")
	}
	if ip.Ignored("other.log") {
		t.Fatal("only negation should not ignore non-matching files")
	}
}

func TestIgnorePatternAllComments(t *testing.T) {
	ip := NewIgnorePattern([]string{"# comment", "  # indented", "#another"})
	if ip.Ignored("anything") {
		t.Fatal("all comments should result in empty ignore set")
	}
}

func TestIgnorePatternOverlappingDirFile(t *testing.T) {
	ip := NewIgnorePattern([]string{"build/", "!build/output.o", "*.log", "!debug.log"})
	if !ip.Ignored("build/other.o") {
		t.Fatal("build/ should ignore files under build/")
	}
	if ip.Ignored("build/output.o") {
		t.Fatal("!build/output.o should un-ignore build/output.o")
	}
	if !ip.Ignored("error.log") {
		t.Fatal("*.log should ignore error.log")
	}
	if ip.Ignored("debug.log") {
		t.Fatal("!debug.log should un-ignore debug.log")
	}
}

func TestIgnorePatternManyPatterns(t *testing.T) {
	patterns := make([]string, 100)
	for i := 0; i < 50; i++ {
		patterns[i] = fmt.Sprintf("*.%d", i)
	}
	patterns[50] = "!important.99"
	for i := 51; i < 100; i++ {
		patterns[i] = fmt.Sprintf("dir%d/", i-50)
	}
	ip := NewIgnorePattern(patterns)
	if !ip.Ignored("test.42") {
		t.Fatal("should match pattern *.42 among 100 patterns")
	}
	if ip.Ignored("important.99") {
		t.Fatal("!important.99 should override *.99")
	}
	if !ip.Ignored("dir5/somefile.go") {
		t.Fatal("dir5/ should match at any depth")
	}
}

func TestIgnorePatternTrailingWhitespace(t *testing.T) {
	ip := NewIgnorePattern([]string{"*.log ", "  "})
	if !ip.Ignored("test.log") {
		t.Fatal("pattern with trailing space should still match after trim")
	}
}

// ─── Brutal concurrent tests ────────────────────────────────────────

func TestNewFileConcurrent(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i := 0; i < 50; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%d.txt", i))
		os.WriteFile(p, []byte(fmt.Sprintf("content %d", i)), 0644)
		paths = append(paths, p)
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			f, err := NewFile(paths[idx])
			if err != nil {
				t.Errorf("NewFile concurrent: %v", err)
				return
			}
			if err := f.LoadContent(); err != nil {
				t.Errorf("LoadContent concurrent: %v", err)
				return
			}
			if len(f.Content) == 0 {
				t.Error("NewFile concurrent: empty content")
			}
		}(i)
	}
	wg.Wait()
}

func TestIgnorePatternConcurrent(t *testing.T) {
	ip := NewIgnorePattern([]string{"*.log", "build/", "!important.log", "vendor/*", "*.o", "node_modules/"})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cases := map[string]bool{
				"debug.log":          true,
				"build/output.o":     true,
				"important.log":      false,
				"vendor/pkg":         true,
				"vendor/pkg/file.go": false,
				"main.go":            false,
				"src/main.go":        false,
			}
			for path, want := range cases {
				if got := ip.Ignored(path); got != want {
					t.Errorf("concurrent Ignored(%q) = %v, want %v", path, got, want)
				}
			}
		}()
	}
	wg.Wait()
}

func TestHashConsistency(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	os.WriteFile(path, []byte("the quick brown fox jumps over the lazy dog"), 0644)

	f1, _ := NewFile(path)
	f2, _ := NewFile(path)
	_ = f1.LoadContent()
	_ = f2.LoadContent()
	if f1.Hash != f2.Hash {
		t.Fatal("same file should produce same hash")
	}

	path2 := filepath.Join(dir, "test2.txt")
	os.WriteFile(path2, []byte("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"), 0644)
	f3, _ := NewFile(path2)
	_ = f3.LoadContent()
	if f1.Hash == f3.Hash {
		t.Fatal("different content should produce different hash")
	}
}
