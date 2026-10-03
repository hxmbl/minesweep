package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// #3: ClaimFinding treated 0 as both "unlimited" and "exhausted", so the
// decrement that spent the last unit immediately re-armed "unlimited". The
// budget could never be exhausted and FindingBudgetHit was unreachable, so
// ReasonFileBudget was dead code.
func TestClaimFindingBudgetIsActuallyEnforced(t *testing.T) {
	f := &File{}
	f.SetFindingBudget(3)

	for i := 1; i <= 3; i++ {
		if !f.ClaimFinding() {
			t.Fatalf("claim %d of a budget of 3 was denied", i)
		}
		if f.FindingBudgetHit {
			t.Fatalf("budget reported exhausted after %d of 3 claims", i)
		}
	}
	if f.FindingBudget != 0 {
		t.Fatalf("remaining budget = %d, want 0", f.FindingBudget)
	}
	// The regression: claim 4 must be denied, and stay denied.
	for i := 4; i <= 8; i++ {
		if f.ClaimFinding() {
			t.Fatalf("claim %d was allowed after a budget of 3 was spent", i)
		}
	}
	if !f.FindingBudgetHit {
		t.Fatal("FindingBudgetHit was never set once the budget was spent")
	}
	if remaining, armed := f.RemainingFindingBudget(); !armed || remaining != 0 {
		t.Errorf("RemainingFindingBudget() = %d,%v want 0,true", remaining, armed)
	}
}

func TestClaimFindingUnlimitedWhenNotArmed(t *testing.T) {
	f := &File{}
	for i := 0; i < 1000; i++ {
		if !f.ClaimFinding() {
			t.Fatalf("claim %d denied with no budget set", i)
		}
	}
	if f.FindingBudgetHit {
		t.Error("FindingBudgetHit set with no budget armed")
	}
	if _, armed := f.RemainingFindingBudget(); armed {
		t.Error("RemainingFindingBudget reported armed with no budget set")
	}
}

// Re-arming must clear the exhausted state, otherwise a File reused for a second
// scan would stay permanently closed.
func TestSetFindingBudgetRearms(t *testing.T) {
	f := &File{}
	f.SetFindingBudget(1)
	f.ClaimFinding()
	if f.ClaimFinding() {
		t.Fatal("second claim should have been denied")
	}
	f.SetFindingBudget(2)
	if !f.ClaimFinding() {
		t.Fatal("re-armed budget denied a claim")
	}
	if f.FindingBudgetHit {
		t.Error("FindingBudgetHit survived re-arming")
	}
}

// A non-positive budget means unlimited, not "already spent". base64.go used to
// copy the raw remaining count into the decoded file, so an exhausted budget
// became unlimited for everything found inside the encoded payload.
func TestSetFindingBudgetNonPositiveIsUnlimited(t *testing.T) {
	for _, n := range []int{0, -1} {
		f := &File{}
		f.SetFindingBudget(1)
		f.ClaimFinding()
		f.SetFindingBudget(n)
		for i := 0; i < 5; i++ {
			if !f.ClaimFinding() {
				t.Fatalf("SetFindingBudget(%d) left the budget closed", n)
			}
		}
	}
}

// ClaimFinding is called once per match. The engine runs detectors for one file
// on a single goroutine, but File is an exported type and the base64 detector
// re-enters Detect on a derived File, so the counter has to be safe on its own.
func TestClaimFindingIsConcurrencySafe(t *testing.T) {
	f := &File{}
	const budget = 100
	f.SetFindingBudget(budget)

	var wg sync.WaitGroup
	var mu sync.Mutex
	granted := 0
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := 0
			for j := 0; j < 50; j++ {
				if f.ClaimFinding() {
					local++
				}
			}
			mu.Lock()
			granted += local
			mu.Unlock()
		}()
	}
	wg.Wait()

	if granted != budget {
		t.Errorf("granted %d claims for a budget of %d", granted, budget)
	}
	if !f.FindingBudgetHit {
		t.Error("FindingBudgetHit not set after concurrent exhaustion")
	}
}

// #33: "starts with .." is not "outside the root". A real file named "..env" was
// treated as escaping, so a symlink to it was marked unsafe and the file was
// dropped as a VCS-internal path in --diff/--staged/--history.
func TestEscapesRoot(t *testing.T) {
	sep := string(filepath.Separator)
	for _, rel := range []string{"..", ".." + sep, ".." + sep + "etc", ".." + sep + "a" + sep + "b"} {
		if !escapesRoot(rel) {
			t.Errorf("escapesRoot(%q) = false, want true", rel)
		}
	}
	for _, rel := range []string{
		".",
		"..env",
		"..envrc",
		"a/..env",
		"a/b/..config",
		"...",
		"foo..bar",
		"sub/..data/x",
	} {
		if escapesRoot(rel) {
			t.Errorf("escapesRoot(%q) = true, want false", rel)
		}
	}
}

// A symlink to an in-root file whose name starts with two dots must be safe.
func TestIsSafePathAcceptsDotDotPrefixedNameInRoot(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "..env")
	if err := os.WriteFile(real, []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if !isSafePath(link, dir) {
		t.Error("isSafePath rejected an in-root symlink to a file named ..env")
	}
}

// #7: WalkOption.OnError was invoked at three places in the walker but never set
// by any caller, so an unreadable subtree produced no accounting at all.
func TestWalkReportsUnreadableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 000 is still readable")
	}
	dir := t.TempDir()
	open := filepath.Join(dir, "open")
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })

	stats := &WalkStats{}
	var mu sync.Mutex
	var failed []string
	_, err := WalkWithOptions(dir, WalkOption{
		Stats: stats,
		OnError: func(path string, err error) {
			mu.Lock()
			failed = append(failed, path)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(failed) != 1 {
		t.Errorf("OnError called %d times (%v), want exactly 1", len(failed), failed)
	}
	if got := stats.ByReason[SkipReasonUnreadable]; got != 1 {
		t.Errorf("unreadable skip count = %d, want 1 (all: %v)", got, stats.ByReason)
	}
	// WalkDir reports an unopenable directory twice: once as an entry it cannot
	// descend into and once as an error. Each path must be accounted once.
	if stats.Total() != 1 {
		t.Errorf("total skips = %d, want 1 (all: %v)", stats.Total(), stats.ByReason)
	}
}

// #32: SkipReasonVCS was declared and printable but the prune never noted it, and
// WalkStats.SkippedSymlink was summed into Total but never incremented anywhere.
func TestWalkAccountsVCSPrunesAndUnsafeSymlinks(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git", "objects")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "leak.env"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real.env"), []byte("y = 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.env")
	if err := os.WriteFile(outside, []byte("z = 3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "escape.env")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	stats := &WalkStats{}
	var gaps []string
	var mu sync.Mutex
	_, err := WalkWithOptions(dir, WalkOption{
		Stats: stats,
		OnError: func(path string, err error) {
			mu.Lock()
			gaps = append(gaps, path)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if stats.ByReason[SkipReasonVCS] != 1 {
		t.Errorf("vcs-internals skip count = %d, want 1 (all: %v)",
			stats.ByReason[SkipReasonVCS], stats.ByReason)
	}
	if stats.ByReason[SkipReasonSymlink] != 1 {
		t.Errorf("symlink skip count = %d, want 1 (all: %v)",
			stats.ByReason[SkipReasonSymlink], stats.ByReason)
	}
	if stats.SkippedSymlink != 1 {
		t.Errorf("SkippedSymlink = %d, want 1", stats.SkippedSymlink)
	}
	// A link that resolves outside the root hides content the scan was asked
	// for, so it has to be a gap the engine can see, not just a statistic.
	if len(gaps) != 1 || gaps[0] != link {
		t.Errorf("OnError gaps = %v, want [%s]", gaps, link)
	}
}

// The VCS note reaches the report, so it must not publish an absolute local path.
func TestWalkVCSNoteIsRelative(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	stats := &WalkStats{}
	if _, err := WalkWithOptions(dir, WalkOption{Stats: stats}); err != nil {
		t.Fatal(err)
	}
	examples := stats.Examples[SkipReasonVCS]
	if len(examples) == 0 {
		t.Fatal("no vcs-internals example recorded")
	}
	if filepath.IsAbs(examples[0]) {
		t.Errorf("vcs-internals example is an absolute path: %q", examples[0])
	}
	if examples[0] != ".git" {
		t.Errorf("vcs-internals example = %q, want %q", examples[0], ".git")
	}
}

// A broken symlink has nothing to inspect, so it is counted but is not a gap.
func TestWalkBrokenSymlinkIsCountedButNotAGap(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "broken.env")
	if err := os.Symlink(filepath.Join(dir, "does-not-exist"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	stats := &WalkStats{}
	var gaps int
	_, err := WalkWithOptions(dir, WalkOption{
		Stats:   stats,
		OnError: func(string, error) { gaps++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.ByReason[SkipReasonSymlink] != 1 {
		t.Errorf("broken symlink not counted: %v", stats.ByReason)
	}
	if gaps != 0 {
		t.Errorf("broken symlink reported as a coverage gap (%d)", gaps)
	}
}

// #17: an empty skip_extensions entry panicked, and Go's panic exit code is 2 --
// the same code this tool uses to mean "incomplete scan". A mistyped config entry
// therefore looked like a deliberate verdict.
func TestEmptySkipExtensionIsAnErrorNotAPanic(t *testing.T) {
	_, err := newFilterSet(WalkOption{SkipExtensions: []string{""}})
	if err == nil {
		t.Fatal("an empty skip_extensions entry must be reported")
	}
	if !strings.Contains(err.Error(), "skip_extensions") {
		t.Errorf("error = %v, want it to name skip_extensions", err)
	}
}

// #34: a bare "env" never matched, because filepath.Ext always returns a
// dot-prefixed suffix, so the entry was a silent no-op. ".DS_Store?" in the
// defaults was the same mistake: a glob compared with ==.
func TestSkipExtensionsAcceptMissingLeadingDot(t *testing.T) {
	fs, err := newFilterSet(WalkOption{SkipExtensions: []string{"env", ".png"}})
	if err != nil {
		t.Fatal(err)
	}
	if !fs.skipExtSet[".env"] {
		t.Errorf("skipExtSet = %v, want .env normalised", fs.skipExtSet)
	}
	if !fs.skipExtSet[".png"] {
		t.Errorf("skipExtSet = %v, want .png present", fs.skipExtSet)
	}
	if reason, skip := fs.reasonExcludingSkipDir("thing.env"); !skip || reason != SkipReasonExt {
		t.Errorf("thing.env: skip=%v reason=%q, want it skipped as an extension", skip, reason)
	}
}
