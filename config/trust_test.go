package config

import (
	"os"
	"path/filepath"
	"testing"
)

// withTrustFile points the trust store at a temporary file for the duration of
// the test. Without this every test would read and write the real user config.
func withTrustFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trust")
	t.Setenv(TrustFileEnv, path)
	return path
}

func TestTrustFileMissingIsEmptyNotAnError(t *testing.T) {
	path := withTrustFile(t)
	store, err := LoadTrust()
	if err != nil {
		t.Fatalf("a missing trust file must not be an error: %v", err)
	}
	if len(store.Entries) != 0 || store.TrustAll {
		t.Errorf("missing file should be an empty store, got %+v", store)
	}
	if trusted, _ := store.Trusts("/anything"); trusted {
		t.Error("nothing is trusted when the file does not exist")
	}
	_ = path
}

func TestAddTrustRoundTrips(t *testing.T) {
	withTrustFile(t)
	dir := filepath.Join(t.TempDir(), "repo")

	if trusted, _ := IsTrustedWithReason(dir); trusted {
		t.Fatal("a fresh directory must not be trusted")
	}
	if err := AddTrust(dir); err != nil {
		t.Fatal(err)
	}
	trusted, reason := IsTrustedWithReason(dir)
	if !trusted {
		t.Fatalf("%s should be trusted after AddTrust", dir)
	}
	if reason == "" {
		t.Error("a trusted directory must say why, so the user can tell the fix took effect")
	}

	// Idempotent: re-running `minesweep trust .` must not duplicate the entry.
	if err := AddTrust(dir); err != nil {
		t.Fatal(err)
	}
	store, err := LoadTrust()
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Entries) != 1 {
		t.Errorf("AddTrust is not idempotent: %v", store.Entries)
	}

	// A relative path must resolve to the same entry, since the command takes
	// whatever the user typed.
	if err := AddTrust("."); err != nil {
		t.Fatal(err)
	}
	store, _ = LoadTrust()
	if len(store.Entries) != 2 {
		t.Errorf("cwd and %s are different directories and both should be listed: %v", dir, store.Entries)
	}
}

func TestRemoveTrust(t *testing.T) {
	withTrustFile(t)
	dir := t.TempDir()
	if err := AddTrust(dir); err != nil {
		t.Fatal(err)
	}
	if err := RemoveTrust(dir); err != nil {
		t.Fatal(err)
	}
	if trusted, _ := IsTrustedWithReason(dir); trusted {
		t.Error("RemoveTrust did not take effect")
	}
	if err := RemoveTrust(dir); err == nil {
		t.Error("removing something that is not trusted should say so, not silently succeed")
	}
}

// A sibling directory that happens to share a prefix must not be trusted. This
// is the whole reason the comparison is exact rather than a string prefix test:
// /work/myrepo-other is not /work/myrepo.
func TestTrustIsNotAPrefixMatch(t *testing.T) {
	withTrustFile(t)
	base := t.TempDir()
	target := filepath.Join(base, "repo")
	sibling := filepath.Join(base, "repo-other")
	if err := AddTrust(target); err != nil {
		t.Fatal(err)
	}
	if trusted, _ := IsTrustedWithReason(sibling); trusted {
		t.Errorf("%s must not be trusted because %s is", sibling, target)
	}
}

// Blanket trust is the equivalent of --config on every run, so it has to be
// written deliberately — but it must work when it is.
func TestTrustAllEntry(t *testing.T) {
	path := withTrustFile(t)
	if err := os.WriteFile(path, []byte("# comment\n\n*\n"+filepath.Join(t.TempDir(), "x")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadTrust()
	if err != nil {
		t.Fatal(err)
	}
	if !store.TrustAll {
		t.Error("`*` must set TrustAll")
	}
	if trusted, _ := store.Trusts(filepath.Join(t.TempDir(), "never-listed")); !trusted {
		t.Error("blanket trust must trust an unlisted directory")
	}
	// Blanket trust must not discard the explicit entries on rewrite.
	if err := AddTrust(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	store, _ = LoadTrust()
	if !store.TrustAll || len(store.Entries) == 0 {
		t.Errorf("rewriting lost state: %+v", store)
	}
}

// The file names the directories a user has decided to trust. It is written
// 0600 in a 0700 directory for that reason.
func TestTrustFilePermissions(t *testing.T) {
	withTrustFile(t)
	if err := AddTrust(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	store, _ := LoadTrust()
	info, err := os.Stat(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("trust file mode = %o, want 600", perm)
	}
}

// Comments and blank lines are ignored so the file can explain itself.
func TestTrustFileIgnoresCommentsAndBlanks(t *testing.T) {
	path := withTrustFile(t)
	dir := t.TempDir()
	body := "# a comment\n\n   \n" + dir + "  \n\n# trailing comment\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadTrust()
	if err != nil {
		t.Fatal(err)
	}
	if len(store.Entries) != 1 {
		t.Fatalf("entries = %v, want exactly one", store.Entries)
	}
	if trusted, _ := store.Trusts(dir); !trusted {
		t.Errorf("trailing whitespace broke the match for %s", dir)
	}
}
