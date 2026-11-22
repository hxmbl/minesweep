package filesystem

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsTestDirConventionalNames pins the set of conventional test-directory
// names recognised by isTestDir, including case/whitespace tolerance and the
// negative cases (testdata is a fixture dir, not a test dir).
func TestIsTestDirConventionalNames(t *testing.T) {
	cases := []struct {
		seg  string
		want bool
	}{
		{"test", true},
		{"tests", true},
		{"testing", true},
		{"__tests__", true},
		{"spec", true},
		{"specs", true},
		{"testsrc", true},
		{"Tests", true},
		{"  tests  ", true},
		{"__TESTS__", true},
		{"src", false},
		{"internal", false},
		{"testdata", false},
		{"", false},
		{"testing123", false},
		{"mytests", false},
	}
	for _, c := range cases {
		if got := isTestDir(c.seg); got != c.want {
			t.Errorf("isTestDir(%q) = %v, want %v", c.seg, got, c.want)
		}
	}
}

// TestIsTestFileNamingConventions guards the pre-existing naming-based
// detection so the directory change does not regress it.
func TestIsTestFileNamingConventions(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"foo_test.go", true},
		{"foo_spec.ts", true},
		{"test_foo.py", true},
		{"spec_bar.rb", true},
		{"foo.test.js", true},
		{"foo.spec.tsx", true},
		{"test_data.json", false},
		{"prod.go", false},
	}
	for _, c := range cases {
		path := filepath.FromSlash(c.path)
		if got := isTestFile(path); got != c.want {
			t.Errorf("isTestFile(%q) = %v, want %v", path, got, c.want)
		}
	}
}

// TestWalkSkipsTestDirectories verifies end-to-end that files beneath a
// conventional test directory are skipped by default and counted as SkippedTest,
// while sibling production files are kept.
func TestWalkSkipsTestDirectories(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tests", "secret.go"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "keep.go"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	var st WalkStats
	files, err := WalkWithOptions(root, WalkOption{Stats: &st})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("kept=%d, want 1", len(files))
	}
	if st.SkippedTest != 1 {
		t.Errorf("SkippedTest=%d, want 1 (stats=%+v)", st.SkippedTest, st)
	}
}

// TestWalkAncestorNamedLikeTestDir ensures a scan root located beneath an
// ancestor named like a test directory is not wholesale skipped: only
// directories inside the root count.
func TestWalkAncestorNamedLikeTestDir(t *testing.T) {
	outer := filepath.Join(t.TempDir(), "tests")
	root := filepath.Join(outer, "actual", "project")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "real.go"), []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	innerTests := filepath.Join(root, "tests")
	if err := os.MkdirAll(innerTests, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(innerTests, "helper.go"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	var st WalkStats
	files, err := WalkWithOptions(root, WalkOption{Stats: &st})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		for _, f := range files {
			t.Logf("kept: %s", f.Path)
		}
		t.Fatalf("kept=%d, want 1 (ancestor named tests must not skip all)", len(files))
	}
	if st.SkippedTest != 1 {
		t.Errorf("SkippedTest=%d, want 1 (stats=%+v)", st.SkippedTest, st)
	}
}
