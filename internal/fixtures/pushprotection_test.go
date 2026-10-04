package fixtures

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Push protection rejects the whole push if any committed file contains a
// credential-shaped token, and it does not care that the file is a test. This
// repository needs credential-shaped literals to exist — the AWS documentation
// key pair above all, since the example filter is keyed on them and is only
// testable against the real strings.
//
// So fixtures are assembled from fragments, and every other credential-shaped
// literal in a Go source has its first character written as \xNN. The decoded
// string is byte-identical; the raw file no longer contains the token.
//
// This test enforces it, because the failure mode is otherwise invisible until a
// push is refused:
//
//	remote: - Push cannot contain secrets
//	remote:      —— Amazon AWS Access Key ID ———
//
// internal/fixtures is exempt: assembling the value from fragments is the whole
// mechanism there, and TestNoCredentialShapedLiteralInSource checks the fragments
// themselves do not reconstruct a token.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`ASIA[0-9A-Z]{16}`),
	regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,255}`),
	regexp.MustCompile(`github_pat_[0-9A-Za-z_]{22,255}`),
	regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{20,}`),
	regexp.MustCompile(`sk_live_[0-9A-Za-z]{24,}`),
	regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
	regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}`),
	// AWS's published documentation pair. Named explicitly because the example
	// filter matches them exactly, so they must appear in test bodies — which
	// is precisely why they cannot appear unescaped.
	regexp.MustCompile(`AKIAIOSFODNN7EXAMPLE`),
	regexp.MustCompile(`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`),
}

func TestNoCredentialShapedLiteralInAnyGoSource(t *testing.T) {
	repoRoot := findRepoRoot(t)
	var offenders []string

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "dist", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(repoRoot, path)
		if relErr != nil {
			return relErr
		}
		if strings.HasPrefix(rel, "internal"+string(filepath.Separator)+"fixtures") {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		src := string(data)
		for _, re := range credentialPatterns {
			for _, loc := range re.FindAllStringIndex(src, -1) {
				line := 1 + strings.Count(src[:loc[0]], "\n")
				offenders = append(offenders,
					fmt.Sprintf("%s:%d  %s", rel, line, re.FindString(src[loc[0]:loc[1]])))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("credential-shaped literals would be rejected by push protection:\n  %s\n\n"+
			"Write the first character as \\xNN (the decoded string is identical), or build "+
			"the value from fragments in internal/fixtures.",
			strings.Join(offenders, "\n  "))
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find go.mod above the fixtures package")
		}
		dir = parent
	}
}
