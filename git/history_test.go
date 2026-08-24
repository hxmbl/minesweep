package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Alice", "GIT_AUTHOR_EMAIL=alice@example.com",
			"GIT_COMMITTER_NAME=Alice", "GIT_COMMITTER_EMAIL=alice@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "--initial-branch=main", ".")
	t.Cleanup(func() {})
	return dir
}

func commitFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Alice", "GIT_AUTHOR_EMAIL=alice@example.com",
			"GIT_COMMITTER_NAME=Alice", "GIT_COMMITTER_EMAIL=alice@example.com")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("add", name)
	run("commit", "-q", "-m", "add "+name)
}

func TestValidSHARejectsInjectionAttempts(t *testing.T) {
	bad := []string{
		"",
		"HEAD",
		"main",
		"--all",
		"HEAD; rm -rf /",
		"$(rm -rf /)",
		"`id`",
		"aaa bbb",
		"AAAA1111",              // uppercase
		strings.Repeat("a", 65), // too long
		"../../etc/passwd",
		"a\nb",
	}
	for _, s := range bad {
		if ValidSHA(s) {
			t.Errorf("ValidSHA(%q) accepted malicious input", s)
		}
	}
	good := []string{"abcdef0123456789abcdef0123456789abcdef01", strings.Repeat("a", 64)}
	for _, s := range good {
		if !ValidSHA(s) {
			t.Errorf("ValidSHA(%q) rejected valid hex sha", s)
		}
	}
}

func TestHistoryFindsDeletedSecret(t *testing.T) {
	dir := initRepo(t)

	// Commit 1: secret exists. Commit 2: file deleted. Working tree is clean.
	commitFile(t, dir, "creds.txt", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")

	if err := os.Remove(filepath.Join(dir, "creds.txt")); err != nil {
		t.Fatal(err)
	}
	c := exec.Command("git", "commit", "-qam", "remove creds")
	c.Dir = dir
	c.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Mallory", "GIT_AUTHOR_EMAIL=m@example.com",
		"GIT_COMMITTER_NAME=Mallory", "GIT_COMMITTER_EMAIL=m@example.com")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("commit removal: %v\n%s", err, out)
	}

	objs, err := ListHistoryObjects(dir)
	if err != nil {
		t.Fatal(err)
	}

	var secretBlob *HistoryObject
	for _, o := range objs {
		if o.Path == "creds.txt" && o.Size > 0 {
			secretBlob = &objs[0]
			for i := range objs {
				if objs[i].Path == "creds.txt" {
					secretBlob = &objs[i]
				}
			}
		}
	}
	if secretBlob == nil {
		t.Fatalf("deleted blob not enumerated; got %d objects", len(objs))
	}

	fetcher, err := NewBlobFetcher(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer fetcher.Close()
	content, err := fetcher.Fetch(secretBlob.SHA)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("blob content wrong: %q", content)
	}
	second, _ := fetcher.Fetch(secretBlob.SHA)
	if string(second) != string(content) {
		t.Error("fetcher reuse returned different content")
	}

	info, err := FindOriginCommit(dir, secretBlob.SHA)
	if err != nil {
		t.Fatalf("attribution: %v", err)
	}
	if info == nil {
		t.Fatal("no attribution for live blob")
	}
	if info.Author != "Alice" {
		t.Errorf("author = %q, want Alice", info.Author)
	}
	if len(info.SHA) < 40 {
		t.Errorf("commit sha truncated: %q", info.SHA)
	}
}

func TestFindOriginCommitRejectsInvalidSHA(t *testing.T) {
	dir := initRepo(t)
	if _, err := FindOriginCommit(dir, "--exec=evil"); err == nil {
		t.Fatal("invalid sha must be rejected before reaching git")
	}
}

func TestListHistoryObjectsNonRepo(t *testing.T) {
	if _, err := ListHistoryObjects(t.TempDir()); err == nil {
		t.Fatal("expected error outside a repository")
	}
}
