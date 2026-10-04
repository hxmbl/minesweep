package engine

import (
	fx "minesweep/internal/fixtures"
	"os"
	"path/filepath"
	"testing"

	"minesweep/findings"
)

var awsKey = "AWS_ACCESS_KEY_ID=" + fx.AWSAccessKeyID() + "\n"

// C4: os.Stat follows symlinks but filepath.WalkDir Lstats the root, so a
// symlinked scan root was delivered to the walk function as a single
// non-directory entry. Scanning it reported one info-level "Symlink" finding,
// exit 0, and none of the tree.
func TestScanThroughSymlinkedRootFindsSecrets(t *testing.T) {
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "cfg.env"), []byte(awsKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "clean.txt"), []byte("nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	base := t.TempDir()
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	for _, root := range []string{real, link, link + string(filepath.Separator)} {
		eng, err := New(Config{MaxFindings: -1, FailOn: "low"})
		if err != nil {
			t.Fatal(err)
		}
		rep, err := eng.Run(root)
		if err != nil {
			t.Fatalf("root %s: %v", root, err)
		}
		if rep.FilesScanned < 2 {
			t.Fatalf("root %s: scanned %d files, expected the whole tree", root, rep.FilesScanned)
		}
		var found bool
		for _, f := range rep.Findings {
			if f.RuleID == "aws-access-key-id" {
				found = true
			}
		}
		if !found {
			t.Fatalf("root %s: the AWS key was not reported", root)
		}
	}
}

// A symlinked root must produce the same reported paths as the real one, or
// baselines recorded from one form will not match the other.
func TestSymlinkedRootReportsStablePaths(t *testing.T) {
	real := t.TempDir()
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "sub", "cfg.env"), []byte(awsKey), 0o600); err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	pathsOf := func(root string) []string {
		eng, err := New(Config{MaxFindings: -1})
		if err != nil {
			t.Fatal(err)
		}
		rep, err := eng.Run(root)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, f := range rep.Findings {
			out = append(out, f.File)
		}
		return out
	}
	a, b := pathsOf(real), pathsOf(link)
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("finding sets differ: real=%v link=%v", a, b)
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("path %d differs: real=%q link=%q", i, a[i], b[i])
		}
		if filepath.IsAbs(a[i]) {
			t.Fatalf("reported path is absolute: %q", a[i])
		}
	}
}

// The suppression switch must be reachable and must actually suppress.
func TestDisableInlineSuppressionIsHonoured(t *testing.T) {
	dir := t.TempDir()
	body := "# minesweep: ignore\n" + awsKey
	if err := os.WriteFile(filepath.Join(dir, "a.env"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	suppressed, err := New(Config{MaxFindings: -1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := suppressed.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		if f.RuleID == "aws-access-key-id" {
			t.Fatal("the inline suppression was not honoured by default")
		}
	}
	if rep.FindingsSuppressed == 0 {
		t.Error("a suppressed finding was not counted in the report")
	}

	// The same tree with suppression disabled must report the key.
	enabled, err := New(Config{MaxFindings: -1, DisableInlineSuppression: true})
	if err != nil {
		t.Fatal(err)
	}
	rep2, err := enabled.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range rep2.Findings {
		if f.RuleID == "aws-access-key-id" {
			found = true
		}
	}
	if !found {
		t.Fatal("--no-inline-suppressions did not surface the suppressed finding")
	}
}

// Binary content must never reach a finding's evidence, in any report format.
func TestBinaryEvidenceIsNeverRawBytes(t *testing.T) {
	dir := t.TempDir()
	body := append([]byte("SQLite format 3\x00"), []byte(awsKey)...)
	if err := os.WriteFile(filepath.Join(dir, "app.db"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := New(Config{MaxFindings: -1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("expected at least the binary-file finding")
	}
	for _, f := range rep.Findings {
		for _, field := range []string{f.SourceLine, f.Context} {
			if field == findings.BinaryEvidence(int(len(body))) {
				continue
			}
			if containsAny(field, "AKIA", "SQLite format") {
				t.Fatalf("raw binary bytes leaked into %s of %s: %q", f.RuleID, f.File, field)
			}
		}
	}
}

// Evidence must stay bounded even for a file with no newline at all.
func TestEvidenceLinesAreBounded(t *testing.T) {
	dir := t.TempDir()
	line := append([]byte("AWS_ACCESS_KEY_ID="+fx.AWSAccessKeyID()+" "), make([]byte, 200_000)...)
	if err := os.WriteFile(filepath.Join(dir, "one.txt"), line, 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := New(Config{MaxFindings: -1})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Findings) == 0 {
		t.Fatal("expected a finding")
	}
	for _, f := range rep.Findings {
		if len(f.SourceLine) > 4*maxEvidenceLineBytes {
			t.Fatalf("SourceLine is %d bytes; evidence is not bounded", len(f.SourceLine))
		}
		if len(f.Context) > 8*maxEvidenceLineBytes {
			t.Fatalf("Context is %d bytes; evidence is not bounded", len(f.Context))
		}
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
