package filesystem

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// #9: DiscoverIgnore concatenated every ancestor's lines into a single rule set
// evaluated against the scan-root-relative path. Git anchors each pattern to the
// directory that declared it, so flattening re-anchored an ancestor's "/x/" onto
// the scan root and silently dropped files the user never asked to ignore.
//
//	root/.minesweepignore            -> /secrets/
//	scanning root/services/api       -> services/api/secrets/db.env  (MUST scan)
func TestAncestorAnchoredPatternKeepsItsOwnAnchor(t *testing.T) {
	repo := t.TempDir()
	target := filepath.Join(repo, "services", "api")
	if err := os.MkdirAll(filepath.Join(target, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "secrets", "db.env"), canarySecret)
	writeFile(t, filepath.Join(target, "keep", "keep.env"), canarySecret)
	writeFile(t, filepath.Join(repo, ".minesweepignore"), "/secrets/\n")
	makeGitRepo(t, repo)

	set, err := DiscoverIgnore(target)
	if err != nil {
		t.Fatal(err)
	}
	if set.Ignored("secrets/db.env") {
		t.Error("an ancestor's anchored /secrets/ dropped a path it does not cover")
	}
	if set.Ignored("keep/keep.env") {
		t.Error("keep/keep.env was ignored")
	}
}

// The other direction: an ancestor's non-anchored pattern still applies to
// everything beneath it, exactly as git would.
func TestAncestorNonAnchoredPatternStillApplies(t *testing.T) {
	repo := t.TempDir()
	target := filepath.Join(repo, "services", "api")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "db.env"), canarySecret)
	writeFile(t, filepath.Join(repo, ".minesweepignore"), "db.env\n")
	makeGitRepo(t, repo)

	set, err := DiscoverIgnore(target)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Ignored("db.env") {
		t.Error("an ancestor's non-anchored pattern stopped applying to the scan root")
	}
}

// An ancestor may itself be excluded by a pattern from a further ancestor, and a
// nearer declaration must still win over it.
func TestNearestAncestorDeclarationWins(t *testing.T) {
	repo := t.TempDir()
	target := filepath.Join(repo, "services", "api")
	if err := os.MkdirAll(filepath.Join(target, "build"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(target, "build", "x.env"), canarySecret)
	// Repo root excludes everything under services; services/ re-includes build.
	writeFile(t, filepath.Join(repo, ".minesweepignore"), "services/\n")
	writeFile(t, filepath.Join(repo, "services", ".minesweepignore"), "!build/\n")
	makeGitRepo(t, repo)

	set, err := DiscoverIgnore(target)
	if err != nil {
		t.Fatal(err)
	}
	if set.Ignored("build/x.env") {
		t.Error("the nearer negation did not re-include build/")
	}
}

func TestRootRelativePrefix(t *testing.T) {
	cases := []struct {
		root, dir, want string
	}{
		{"/a/b/c", "/a/b/c", ""},
		{"/a/b/c", "/a/b", ".."},
		{"/a/b/c", "/a", "../.."},
		{"/a/b/c", "/", "../../.."},
		{"/a/b/c", "/a/b/c/d", ""},
	}
	for _, c := range cases {
		if got := rootRelativePrefix(c.root, c.dir); got != c.want {
			t.Errorf("rootRelativePrefix(%q, %q) = %q, want %q", c.root, c.dir, got, c.want)
		}
	}
}

// #10: isTestFile trimmed the last extension and then looked for a ".test" or
// ".spec" suffix, so the segment branch only ever fired for "<stem>.test.<ext>".
// Worse, it fired for data formats too: prod.test.tfvars and secrets.test.json
// are Terraform environment and data files that routinely carry live
// credentials, and they were dropped by default as "test files".
func TestIsTestFile(t *testing.T) {
	skipped := []string{
		// _test / _spec are the file's own convention: any extension.
		"foo_test.go",
		"foo_test.py",
		"real_test.go",
		"foo_spec.rb",
		"foo_spec.go",
		// .test/.spec for a known source extension.
		"foo.test.js",
		"foo.spec.ts",
		"Foo.test.jsx",
		"widget.spec.tsx",
		"handler.test.go",
		"widget_test.go",
	}
	scanned := []string{
		// Data and config formats: a ".test" segment is part of the name, not a
		// test marker. These carry real credentials.
		"prod.test.tfvars",
		"secrets.test.json",
		"config.test.yaml",
		"env.test.ini",
		"creds.test.toml",
		// Bare ".test"/".spec" with no following extension never matched before
		// and still must not.
		"foo.test",
		"foo.spec",
		// Ordinary names.
		"real_test2.go",
		"contest.ts",
		"latest.env",
		".env",
	}
	for _, name := range skipped {
		if !isTestFile(name) {
			t.Errorf("isTestFile(%q) = false, want true", name)
		}
	}
	for _, name := range scanned {
		if isTestFile(name) {
			t.Errorf("isTestFile(%q) = true, want false", name)
		}
	}
}

// The end-to-end consequence: a credential in a *.test.tfvars file must be found
// without --include-test-files, and one in a *.test.js file must not.
func TestTestFileHeuristicEndToEnd(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "prod.test.tfvars"), canarySecret)
	writeFile(t, filepath.Join(dir, "module.test.js"), canarySecret)

	stats := &WalkStats{}
	files, err := WalkWithOptions(dir, WalkOption{Stats: stats, NoIgnore: true})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f.Path))
	}
	if !contains(names, "prod.test.tfvars") {
		t.Errorf("prod.test.tfvars was not walked (walked: %v)", names)
	}
	if contains(names, "module.test.js") {
		t.Errorf("module.test.js was walked but is a test module (walked: %v)", names)
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// makeGitRepo bounds ignoreSearchDirs at the repo top level, which is what makes
// an ancestor ignore file participate at all.
func makeGitRepo(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	for _, args := range [][]string{
		{"init", "-q", "."},
		{"config", "user.email", "test@example.invalid"},
		{"config", "user.name", "test"},
	} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v (%s)", args, err, out)
		}
	}
}
