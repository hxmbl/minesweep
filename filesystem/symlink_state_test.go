package filesystem

import (
	"os"
	"path/filepath"
	"testing"
)

// A symlink target whose path merely CONTAINS a marker substring like
// "(broken)" or "(unsafe)" must not be treated as an actually-broken link.
func TestSymlinkTargetWithMarkerSubstring(t *testing.T) {
	root := t.TempDir()
	tricky := filepath.Join(root, "dir (unsafe) really (broken)")
	if err := os.MkdirAll(tricky, 0755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(tricky, "data.txt")
	if err := os.WriteFile(secret, []byte("real content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(secret, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	f, err := NewFileWithRoot(filepath.Join(root, "link"), root)
	if err != nil {
		t.Fatal(err)
	}
	content, err := f.GetContent()
	if err != nil {
		t.Fatalf("symlink into dir with marker-like name should still resolve: %v", err)
	}
	if string(content) != "real content\n" {
		t.Errorf("unexpected content %q", content)
	}
}

func TestSymlinkOutsideRootHasNoContent(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "secret.txt")
	os.WriteFile(target, []byte("top secret\n"), 0644)

	root := t.TempDir()
	if err := os.Symlink(target, filepath.Join(root, "leak")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	f, err := NewFileWithRoot(filepath.Join(root, "leak"), root)
	if err != nil {
		t.Fatal(err)
	}
	content, err := f.GetContent()
	if err != nil {
		t.Fatal(err)
	}
	if len(content) != 0 {
		t.Errorf("unsafe symlink must yield empty content, got %q", content)
	}
}
