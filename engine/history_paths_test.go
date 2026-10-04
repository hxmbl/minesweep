package engine

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"minesweep/findings"
)

// git's object listing names each object exactly once. A secret committed at
// two paths — copied, moved, or written twice with identical content — was
// therefore reported under a single name, and the other location was silently
// absent. A user who cleaned up the file the report named would leave the
// credential in the tree believing it was gone, and the next history scan would
// have nothing new to say, because the one path it looked at had been fixed.
func TestHistoryReportsEveryPathOfASharedBlob(t *testing.T) {
	dir := initRepo(t)
	commitFile(t, dir, "top.env", awsKey, "add top")
	commitFile(t, dir, "sub/inner.env", awsKey, "add inner")

	got := strings.Join(historyPaths(t, dir), ",")
	if got != "sub/inner.env,top.env" {
		t.Fatalf("history reported %q, want %q — a shared blob hides one of its locations", got, "sub/inner.env,top.env")
	}
}

// Expansion must not become a way around the requested scope. withinDir alone
// is not enough for a single-file target: root is that file's directory, so
// every sibling is inside it.
func TestHistoryExpansionRespectsScope(t *testing.T) {
	dir := initRepo(t)
	commitFile(t, dir, "top.env", awsKey, "add top")
	commitFile(t, dir, "sub/inner.env", awsKey, "add inner")

	for _, tc := range []struct{ target, want string }{
		{dir, "sub/inner.env,top.env"},
		{filepath.Join(dir, "sub"), "sub/inner.env"},
		{filepath.Join(dir, "sub", "inner.env"), "sub/inner.env"},
	} {
		got := strings.Join(historyPaths(t, tc.target), ",")
		if got != tc.want {
			t.Errorf("target %s: reported %q, want %q", tc.target, got, tc.want)
		}
	}
}

// The filter is a statement about paths, so it must be applied to paths. The
// one name git happens to give a blob is not evidence about the others: a secret
// shared between config.env and vendor/logo.png was missed entirely whenever
// the filtered name was the one git picked.
func TestHistoryFilteredNameDoesNotHideASharedSecret(t *testing.T) {
	dir := initRepo(t)
	commitFile(t, dir, "config.env", awsKey, "add config")
	commitFile(t, dir, "vendor/logo.png", awsKey, "add png")

	rep := runHistory(t, dir)
	paths := map[string]bool{}
	for _, f := range rep.Findings {
		paths[historyBase(f.File)] = true
	}
	if !paths["config.env"] {
		t.Fatalf("the secret was not reported at its scannable path; got %v", paths)
	}
	if paths["vendor/logo.png"] {
		t.Fatalf("a filtered path was reported: %v", paths)
	}
	if !containsSkipped(rep.SkippedBy, "logo.png") {
		t.Errorf("the filtered location was not accounted for as skipped: %v", rep.SkippedBy)
	}
}

// A distinct secret that lives only at a filtered path stays unreported, and
// says so.
func TestHistoryFilteredPathWithItsOwnSecretIsNotReported(t *testing.T) {
	dir := initRepo(t)
	commitFile(t, dir, "config.env", awsKey, "add config")
	commitFile(t, dir, "logo.png",
		"GITHUB_TOKEN=\x67hp_abcdefghijklmnopqrstuvwxyz0123456789\n", "add png")

	rep := runHistory(t, dir)
	for _, f := range rep.Findings {
		if strings.HasSuffix(historyBase(f.File), ".png") {
			t.Fatalf("a filtered path was reported: %s", f.File)
		}
		if strings.Contains(f.RuleID, "github") {
			t.Fatalf("a secret that exists only at a filtered path was reported: %s", f.File)
		}
	}
	if len(rep.Findings) == 0 {
		t.Fatal("the unfiltered secret was not reported either")
	}
}

// Every occurrence carries a commit, so a reader knows where each copy lived.
func TestHistoryExpandedPathsAreAttributed(t *testing.T) {
	dir := initRepo(t)
	commitFile(t, dir, "a.env", awsKey, "add a")
	commitFile(t, dir, "b.env", awsKey, "add b")

	rep := runHistory(t, dir)
	seen := map[string]map[string]bool{}
	for _, f := range rep.Findings {
		if f.Commit == "" {
			t.Fatalf("%s has no commit attribution", f.File)
		}
		base := historyBase(f.File)
		if seen[base] == nil {
			seen[base] = map[string]bool{}
		}
		seen[base][f.Commit] = true
	}
	if len(seen) < 2 {
		t.Fatalf("expected findings at both paths, got %v", seen)
	}
}

func runHistory(t *testing.T, target string) *findings.RiskReport {
	t.Helper()
	eng, err := New(Config{MaxFindings: -1, HistoryMode: true})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(target)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func historyPaths(t *testing.T, target string) []string {
	t.Helper()
	seen := map[string]bool{}
	for _, f := range runHistory(t, target).Findings {
		seen[historyBase(f.File)] = true
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func commitFile(t *testing.T, dir, rel, content, msg string) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	scopedGit(t, dir, "add", "-A")
	scopedGit(t, dir, "commit", "-qm", msg)
}

func historyBase(display string) string {
	if i := strings.LastIndexByte(display, '@'); i > 0 {
		return display[:i]
	}
	return display
}

func containsSkipped(lines []string, want string) bool {
	for _, l := range lines {
		if strings.Contains(l, want) {
			return true
		}
	}
	return false
}
