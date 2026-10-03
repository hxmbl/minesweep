package engine

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"minesweep/findings"
	"minesweep/policy"
	"minesweep/report"
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

// A redaction action must not destroy the finding's value in the engine, and
// must never leave the secret sitting in the evidence it is printed with.
//
// An earlier version rewrote Value to a constant "<REDACTED>" here. That made
// the engine decide disclosure before the output layer knew whether the user had
// passed --dangerously-show-secrets, so the flag revealed the literal string
// "<REDACTED>" instead of the secret, and every redacted finding collapsed onto
// one identical token. Redaction is now the censor's job, at the output
// boundary, where the flag is known.
func TestRedactActionKeepsValueForTheCensor(t *testing.T) {
	const secret = "SG.abcdefghijklmnopqrstuv.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	e := &Engine{config: Config{}, policies: testRedactPolicies()}
	out := e.evaluate([]findings.Finding{{
		Type:       "SendGrid API Key",
		RuleID:     "sendgrid-api-key",
		Severity:   findings.SeverityHigh,
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
	if f.Action != findings.ActionRedact {
		t.Errorf("action = %q, want redact", f.Action)
	}
	if f.Value != secret {
		t.Errorf("engine rewrote Value to %q; the censor owns disclosure", f.Value)
	}
}

// End to end through the censor: a redacted finding must print a per-secret
// token, not the raw value and not a shared constant.
func TestRedactActionCensorsToPerSecretToken(t *testing.T) {
	const first = "SG.abcdefghijklmnopqrstuv.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const second = "token-9f4b2c7a1e6d8053ba4c17e29f60d83a"
	e := &Engine{config: Config{}, policies: testRedactPolicies()}
	out := e.evaluate([]findings.Finding{
		{Type: "SendGrid API Key", RuleID: "sendgrid-api-key", Severity: findings.SeverityHigh,
			File: "a.py", Line: 1, Value: first, SourceLine: "key = " + first, Context: "> key = " + first},
		{Type: "Stripe API Key", RuleID: "stripe-secret-key", Severity: findings.SeverityHigh,
			File: "b.py", Line: 1, Value: second, SourceLine: "key = " + second, Context: "> key = " + second},
	})

	censored := report.CensorReport(&findings.RiskReport{Findings: out})
	if len(censored.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(censored.Findings))
	}
	a, b := censored.Findings[0], censored.Findings[1]
	for _, f := range censored.Findings {
		if strings.Contains(f.Value, "REDACTED") {
			t.Errorf("value still shows the old constant: %q", f.Value)
		}
		if strings.Contains(f.SourceLine, first) || strings.Contains(f.SourceLine, second) {
			t.Errorf("evidence leaked a raw secret: %q", f.SourceLine)
		}
	}
	if a.Value == b.Value {
		t.Errorf("two different secrets share one token %q; correlation is lost", a.Value)
	}
	if !findings.IsCensoredToken(a.Value) || !findings.IsCensoredToken(b.Value) {
		t.Errorf("values are not censorship tokens: %q / %q", a.Value, b.Value)
	}
	if a.Value != findings.SecretToken(first) {
		t.Errorf("token for %q = %q, want the token of its own secret", first, a.Value)
	}
}

func testRedactPolicies() []policy.PolicyRule {
	return []policy.PolicyRule{{Tags: []string{"*"}, Action: findings.ActionRedact}}
}

// Baselines recorded in working-tree mode must match the same secret found
// through history mode (whose File carries an "@sha" suffix).
func TestBaselineCrossModeMatching(t *testing.T) {
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "--initial-branch=main", ".")
	if err := os.WriteFile(filepath.Join(dir, "k.env"), []byte("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"), 0644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, dir, "add", "k.env")
	gitRun(t, dir, "commit", "-qm", "add key")

	// Record baseline in working-tree mode.
	baseDir := t.TempDir()
	baselinePath := filepath.Join(baseDir, "b.json")
	wtEng, err := New(Config{BaselineFile: baselinePath, UpdateBaseline: true})
	if err != nil {
		t.Fatal(err)
	}
	wtRep, err := wtEng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(wtRep.Findings) == 0 {
		t.Fatal("expected working-tree findings to baseline")
	}

	// History scan with the same baseline: the key is old news.
	histEng, err := New(Config{HistoryMode: true, BaselineFile: baselinePath})
	if err != nil {
		t.Fatal(err)
	}
	histRep, err := histEng.Run(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range histRep.Findings {
		if f.RuleID == "aws-access-key-id" {
			t.Errorf("baselined secret leaked through history mode: %+v", f.File)
		}
	}
	if len(histRep.Findings) > 0 {
		t.Errorf("unexpected non-baselined findings: %d", len(histRep.Findings))
	}
}
