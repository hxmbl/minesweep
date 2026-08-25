package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"minesweep/findings"
	"minesweep/policy"
)

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Alice", "GIT_AUTHOR_EMAIL=alice@example.com",
		"GIT_COMMITTER_NAME=Alice", "GIT_COMMITTER_EMAIL=alice@example.com")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestHistoryModeScansDeletedSecrets(t *testing.T) {
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "--initial-branch=main", ".")

	if err := os.WriteFile(filepath.Join(dir, "secret.env"), []byte("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"), 0644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "secret.env")
	gitRun(t, dir, "commit", "-qm", "oops")
	if err := os.Remove(filepath.Join(dir, "secret.env")); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "commit", "-qam", "cleanup")

	clean := []byte("just harmless text\n")
	os.WriteFile(filepath.Join(dir, "readme.md"), clean, 0644)
	gitRun(t, dir, "add", "readme.md")
	gitRun(t, dir, "commit", "-qm", "docs")

	eng, err := New(Config{HistoryMode: true})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := eng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, f := range rep.Findings {
		if f.RuleID == "aws-secret-key" && strings.Contains(f.File, "secret.env") {
			found = true
			if len(f.Commit) < 40 || !findings.IsValidSeverity(f.Severity.String()) {
				t.Errorf("attribution incomplete: %+v", f)
			}
			if f.Author != "Alice" {
				t.Errorf("author = %q", f.Author)
			}
		}
	}
	if !found {
		t.Fatalf("history scan missed deleted secret; findings=%d", len(rep.Findings))
	}

	// Working-tree scan of the same repo must be clean: the secret only
	// exists in history.
	plain, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	plainRep, err := plain.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range plainRep.Findings {
		if f.RuleID == "aws-secret-key" {
			t.Errorf("working-tree scan should not see the deleted secret: %+v", f)
		}
	}
}

func TestRedactMasksEvidenceFields(t *testing.T) {
	const secret = "SG.abcdefghijklmnopqrstuv.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	e := &Engine{config: Config{}, policies: testRedactPolicies()}
	out := e.evaluate([]findings.Finding{{
		Type:       "SendGrid API Key",
		RuleID:     "sendgrid-api-key",
		Severity:   findings.SeverityHigh,
		Action:     findings.ActionRedact,
		File:       "sg.py",
		Line:       1,
		Value:      secret,
		Context:    "> key = " + secret + "\n  other line\n",
		SourceLine: "key = " + secret,
	}})

	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.Value != "<REDACTED>" {
		t.Errorf("value = %q", f.Value)
	}
	if strings.Contains(f.SourceLine, secret) || strings.Contains(f.Context, secret) {
		t.Errorf("redact leaked secret via evidence fields:\nsource_line=%q\ncontext=%q",
			f.SourceLine, f.Context)
	}
	if !strings.Contains(f.SourceLine, "<REDACTED>") || !strings.Contains(f.Context, "<REDACTED>") {
		t.Errorf("evidence should contain the mask marker:\n%q / %q", f.SourceLine, f.Context)
	}
}

func testRedactPolicies() []policy.PolicyRule {
	return []policy.PolicyRule{{Tags: []string{"*"}, Action: findings.ActionRedact}}
}
