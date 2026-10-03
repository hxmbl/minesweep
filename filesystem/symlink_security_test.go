package filesystem

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const canarySecret = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01\n"

// #6: isSafePath validated only the lexical first hop while the kernel follows
// the whole chain, so a two-hop link inside the root read a file outside it.
//
//	root/b.env -> ../outside/secret.env
//	root/a.env -> b.env
func TestSymlinkChainCannotEscapeScanRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.env"), []byte(canarySecret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.env"), filepath.Join(root, "b.env")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("b.env", filepath.Join(root, "a.env")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"a.env", "b.env"} {
		f, err := NewFileWithRoot(filepath.Join(root, name), root)
		if err != nil {
			t.Fatalf("NewFileWithRoot(%s): %v", name, err)
		}
		if !f.IsSymlink {
			t.Fatalf("%s: expected a symlink", name)
		}
		if f.symlinkState != symlinkUnsafe {
			t.Errorf("%s: state = %v, want unsafe; the chain resolved outside the root", name, f.symlinkState)
		}
		if _, err := f.GetContent(); err != nil {
			t.Errorf("%s: GetContent on an unsafe link should be empty, not an error: %v", name, err)
		}
		if len(f.Content) != 0 {
			t.Errorf("%s: content was read through an escaping link: %q", name, f.Content)
		}
	}
}

// The single-hop case was already correct and must stay correct.
func TestSingleHopSymlinkEscapeIsBlocked(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.env"), []byte(canarySecret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.env"), filepath.Join(root, "a.env")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	f, err := NewFileWithRoot(filepath.Join(root, "a.env"), root)
	if err != nil {
		t.Fatal(err)
	}
	if f.symlinkState != symlinkUnsafe {
		t.Errorf("state = %v, want unsafe", f.symlinkState)
	}
}

// ...and an in-root link must still be followed, or the guard is just a filter.
func TestInRootSymlinkIsStillFollowed(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "real.env"), []byte(canarySecret), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.env", filepath.Join(root, "link.env")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	f, err := NewFileWithRoot(filepath.Join(root, "link.env"), root)
	if err != nil {
		t.Fatal(err)
	}
	if f.symlinkState != symlinkOK {
		t.Fatalf("state = %v, want ok", f.symlinkState)
	}
	content, err := f.GetContent()
	if err != nil {
		t.Fatalf("GetContent: %v", err)
	}
	if !strings.Contains(string(content), "wJalrXUtnFEMI") {
		t.Error("in-root symlink was not followed")
	}
}

// A loop reports ELOOP, not ENOENT, so os.IsNotExist missed it and the link was
// left marked as a perfectly good symlink with no marker at all.
func TestSymlinkLoopIsMarkedNotHealthy(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("b.env", filepath.Join(root, "a.env")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink("a.env", filepath.Join(root, "b.env")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.env", "b.env"} {
		f, err := NewFileWithRoot(filepath.Join(root, name), root)
		if err != nil {
			t.Fatalf("NewFileWithRoot(%s): %v", name, err)
		}
		if f.symlinkState == symlinkOK {
			t.Errorf("%s: a link loop was marked healthy", name)
		}
		if len(f.SymlinkTarget) == 0 {
			t.Errorf("%s: no marker recorded", name)
		}
	}
}

// A symlink to a directory must not be mistaken for a regular file: the
// directory's size was being reported as the link's size.
func TestSymlinkToDirectoryIsNotSizedLikeAFile(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("x", 5000)
	if err := os.WriteFile(filepath.Join(sub, "big.env"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "dirlink")
	if err := os.Symlink(sub, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	f, err := NewFileWithRoot(link, root)
	if err != nil {
		t.Fatal(err)
	}
	if f.Size == int64(len(big)) {
		t.Error("a symlink to a directory reported the size of a file inside it")
	}
	// Content must be empty: a directory cannot be read as a file.
	if _, err := f.GetContent(); err == nil && len(f.Content) != 0 {
		t.Errorf("read %d bytes from a symlink to a directory", len(f.Content))
	}
}

// isSafePath resolves both sides, so /tmp/x and /private/tmp/x (the same
// directory on macOS) do not disagree.
func TestIsSafePathResolvesBothSides(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "file.env")
	if err := os.WriteFile(real, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if !isSafePath(link, dir) {
		t.Error("isSafePath rejected a link to an in-root file reached through a symlinked dir")
	}
	if isSafePath(filepath.Join(dir, "..", "elsewhere"), dir) {
		t.Error("isSafePath accepted a path outside the root")
	}
}
