package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// C2: a two-hop symlink chain must not escape the scan root.
//
// Validating only filepath.Join(dir(link), readlink(link)) is a lexical check
// on the FIRST hop. `a -> b` passes because b is inside the root, and
// `b -> /outside/secret` escapes on the second hop, which os.Open then
// follows. With that pair present, scanning the root read the out-of-root file
// and reported its credentials.
func TestSymlinkChainCannotEscapeRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "creds.env")
	if err := os.WriteFile(secret, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// hop -> outside (the real escape)
	hop := filepath.Join(root, "hop")
	if err := os.Symlink(secret, hop); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	// innocent -> hop (first hop is inside the root, so a lexical check passes)
	innocent := filepath.Join(root, "innocent")
	if err := os.Symlink(hop, innocent); err != nil {
		t.Fatal(err)
	}

	f, err := NewFileWithRoot(innocent, root)
	if err != nil {
		t.Fatal(err)
	}
	if f.symlinkState == symlinkOK {
		t.Fatalf("two-hop chain resolved to an out-of-root target was admitted as safe (target=%q)", f.SymlinkTarget)
	}
	data, err := f.GetContent()
	if err != nil {
		t.Fatalf("unexpected read error: %v", err)
	}
	if strings.Contains(string(data), "AKIA") {
		t.Fatal("content of a file outside the scan root was read through a symlink chain")
	}
}

// A symlink whose whole chain stays inside the root must still be followed:
// the containment check must not degrade into refusing every symlink.
func TestSymlinkChainInsideRootIsFollowed(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real.env")
	if err := os.WriteFile(real, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "hop")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	entry := filepath.Join(root, "innocent")
	if err := os.Symlink("hop", entry); err != nil {
		t.Fatal(err)
	}

	f, err := NewFileWithRoot(entry, root)
	if err != nil {
		t.Fatal(err)
	}
	if f.symlinkState != symlinkOK {
		t.Fatalf("in-root chain rejected: state=%v target=%q", f.symlinkState, f.SymlinkTarget)
	}
	data, err := f.GetContent()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "AKIA") {
		t.Fatal("in-root symlink chain was not followed")
	}
}

// A direct one-hop escape stays blocked (the regression this replaced).
func TestSymlinkDirectEscapeBlocked(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.env")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	f, err := NewFileWithRoot(link, root)
	if err != nil {
		t.Fatal(err)
	}
	if f.symlinkState != symlinkUnsafe {
		t.Fatalf("direct escape admitted: state=%v target=%q", f.symlinkState, f.SymlinkTarget)
	}
}

// A symlink cycle must be reported, not left in symlinkOK: os.IsNotExist does
// not match ELOOP, so the previous existence probe let cycles through with no
// marker at all.
func TestSymlinkLoopMarked(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	f, err := NewFileWithRoot(a, root)
	if err != nil {
		t.Fatal(err)
	}
	if f.symlinkState == symlinkOK {
		t.Fatalf("symlink cycle admitted as safe: target=%q", f.SymlinkTarget)
	}
}

// A symlink to a directory has no content; adopting the directory's size made
// every later read fail with EISDIR and be counted as an unreadable file.
func TestSymlinkToDirectoryHasNoContent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "sub"), link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	f, err := NewFileWithRoot(link, root)
	if err != nil {
		t.Fatal(err)
	}
	if f.Size != 0 {
		t.Fatalf("symlink to a directory inherited size %d", f.Size)
	}
	if _, err := f.GetContent(); err != nil {
		t.Fatalf("symlink to a directory should read as empty, got error: %v", err)
	}
}

// isSafePath must not reject an in-root file whose name merely begins with
// "..": a bare HasPrefix(rel, "..") test classified "..env" as outside the root.
func TestIsSafePathAllowsDotDotPrefixedNames(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "..env"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !isSafePath(filepath.Join(root, "..env"), root) {
		t.Fatal(`in-root file named "..env" was classified as outside the root`)
	}
	if !isSafePath(filepath.Join(root, "sub", "..env"), root) {
		t.Fatal(`in-root nested file named "..env" was classified as outside the root`)
	}
	if isSafePath(filepath.Join(root, "..", "escape"), root) {
		t.Fatal("genuine escape accepted")
	}
}

// A scan root reached through a symlink must accept its own files. Both sides
// of the comparison are canonicalised for exactly this reason.
func TestIsSafePathCanonicalisesRoot(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	if !isSafePath(filepath.Join(real, "a.env"), link) {
		t.Fatal("a file inside a symlinked scan root was rejected as outside it")
	}
}
