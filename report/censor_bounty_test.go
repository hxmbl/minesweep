package report

import (
	"strings"
	"testing"

	"minesweep/findings"
)

// C1: findings with no Value still carry raw file content in Context and
// SourceLine. The file-type and symlink detectors emit exactly such findings,
// and CensorFinding used to return them untouched — so a SQLite database put
// its credentials into every report format verbatim.
func TestCensorFindingCensorsEvidenceWithoutValue(t *testing.T) {
	f := findings.Finding{
		Type:       "Binary File",
		RuleID:     "binary-file-detected",
		Severity:   findings.SeverityInfo,
		File:       "app.db",
		Line:       1,
		SourceLine: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		Context:    "> AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
		Action:     findings.ActionAllow,
	}
	out := CensorFinding(f)
	if strings.Contains(out.SourceLine, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("evidence leaked through a valueless finding: %q", out.SourceLine)
	}
	if strings.Contains(out.Context, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("context leaked through a valueless finding: %q", out.Context)
	}
	if out.Value != "" {
		t.Fatalf("Value should stay empty, got %q", out.Value)
	}
}

// M3: the same secret must show the same token everywhere. Censoring an
// already-tokenized Value hashed the token a second time.
func TestCensorFindingIsIdempotentOnTokens(t *testing.T) {
	raw := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	f := findings.Finding{
		Value:      raw,
		SourceLine: "token = " + raw,
		Context:    "> token = " + raw + "\n",
	}
	once := CensorFinding(f)
	twice := CensorFinding(once)
	if once.Value != twice.Value {
		t.Fatalf("re-censoring changed the value token: %q -> %q", once.Value, twice.Value)
	}
	if once.SourceLine != twice.SourceLine {
		t.Fatalf("re-censoring changed the evidence:\n%q\n%q", once.SourceLine, twice.SourceLine)
	}
	if strings.Contains(twice.SourceLine, raw) {
		t.Fatalf("raw value survived re-censoring: %q", twice.SourceLine)
	}
}

// A token substituted into a line glues onto the identifier in front of it
// (`admin_sha256:1d31bdafd1e9`) and the heuristic pass then censored the
// combination, re-hashing the token and destroying the same-secret correlation
// that baselines depend on.
func TestTokenGluedToIdentifierIsNotReHashed(t *testing.T) {
	raw := "hunter2hunter2"
	once := CensorFinding(findings.Finding{
		Value:      raw,
		SourceLine: "admin_password = " + raw,
	})
	token := once.Value
	if !strings.Contains(once.SourceLine, token) {
		t.Fatalf("token missing from evidence: %q", once.SourceLine)
	}
	// Exactly one token, and it is the same one reported as the value.
	if got := strings.Count(once.SourceLine, tokenPrefix); got != 1 {
		t.Fatalf("expected exactly one token in %q, found %d", once.SourceLine, got)
	}
	if strings.Contains(once.SourceLine, tokenPrefix+"admin") {
		t.Fatalf("token was re-hashed after being glued to an identifier: %q", once.SourceLine)
	}
}

// C1 adjacent variant: the candidate character class used to stop at the first
// punctuation character it did not include, so `P@ssw0rd$ecret!2024` was cut at
// the `!` and the remainder printed in cleartext. A partial redaction is a
// leaked redaction.
func TestCensorSecretSubstringsDoesNotFragmentCredentials(t *testing.T) {
	cases := []string{
		`admin_password = "P@ssw0rd$ecret!2024"`,
		`token = "abc!def$ghij%klmn"`,
		`key = "a+b/c=d~e&f*g?h#i"`,
	}
	for _, in := range cases {
		out := censorAllValues(in, "")
		for _, leak := range []string{"P@ssw0rd", "ecret", "2024", "abc", "def", "ghij", "klmn"} {
			if strings.Contains(out, leak) && !strings.Contains(in, leak) {
				t.Errorf("fragment %q survived censoring of %q -> %q", leak, in, out)
			}
		}
	}
}

// A long hex secret has at most 16 distinct symbols, so the unique-character
// ratio could never clear its threshold and it printed verbatim.
func TestCensorSecretSubstringsCatchesHexSecrets(t *testing.T) {
	in := `checksum = "d41d8cd98f00b204e9800998ecf8427e0123456789abcdef0123456789abcdef"`
	out := censorAllValues(in, "")
	if strings.Contains(out, "d41d8cd98f00b204") {
		t.Fatalf("hex secret survived censoring: %q", out)
	}
}

// Censoring must not destroy ordinary source. Identifiers, paths, URLs, SQL and
// prose have to stay readable or nobody reads the report.
func TestCensorSecretSubstringsPreservesOrdinarySource(t *testing.T) {
	preserve := []string{
		`const url = "https://api.example.com/v1/users/{id}/settings?page=2&sort=name"`,
		`img := "vendor/pkg/ui/img/icons/arrow-left-24px.png"`,
		`sql := "SELECT id FROM users WHERE tenant_id = $1 ORDER BY created_at DESC"`,
		`logger.Info("request completed", zap.String("format", ts))`,
		`token = state.get("token")`,
		`password = os.environ["DB_PASSWORD"]`,
		`// TODO: move to the new converter`,
		`timeout: 30s`,
		`module github.com/spf13/cobra`,
	}
	for _, in := range preserve {
		if out := censorAllValues(in, ""); out != in {
			t.Errorf("ordinary source was altered:\n in: %s\nout: %s", in, out)
		}
	}
}

// The credential beside a readable identifier must still be tokenized.
func TestCensorSecretSubstringsKeepsIdentifierAndHidesValue(t *testing.T) {
	out := censorAllValues(`admin_password = "P@ssw0rd$ecret!2024"`, "")
	if !strings.HasPrefix(out, "admin_password") {
		t.Errorf("identifier should stay readable, got %q", out)
	}
	if strings.Contains(out, "P@ssw0rd") || strings.Contains(out, "2024") {
		t.Errorf("password survived censoring: %q", out)
	}
}

func TestCensorFindingSurvivesEmptyAndOversizedInput(t *testing.T) {
	f := CensorFinding(findings.Finding{})
	if f.SourceLine != "" || f.Context != "" || f.Value != "" {
		t.Fatalf("empty finding was modified: %+v", f)
	}
	long := findings.Finding{Value: "x", Context: strings.Repeat("A", 100_000)}
	if got := CensorFinding(long).Context; len(got) == 0 {
		t.Fatal("long context was dropped entirely")
	}
}
