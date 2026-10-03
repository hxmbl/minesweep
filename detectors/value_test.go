package detectors

import (
	"strings"
	"testing"

	"minesweep/filesystem"
)

func TestLooksLikeCredentialValueRejectsCode(t *testing.T) {
	// Captures that are source code, not secret material. Every one of these
	// was reported as a real finding before the check existed.
	reject := []string{
		"state.get(",   // token = state.get("token")
		"lookup(",      // api_key = lookup("api_key")
		"os.environ[",  // password = os.environ["DB_PASSWORD"]
		"config.",      // truncated attribute chain
		"${SECRET_",    // key = ${SECRET_FROM_VAULT}
		"self.token",   // token = self.token
		"process.env.", // attribute chain with a trailing dot
		"abcdefg",      // too short to be a credential
		"",
	}
	for _, v := range reject {
		if looksLikeCredentialValue(v) {
			t.Errorf("looksLikeCredentialValue(%q) = true; want false (source code, not a secret)", v)
		}
	}
}

func TestLooksLikeCredentialValueAcceptsSecrets(t *testing.T) {
	accept := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"postgres://svc:8fJq2vQzLmNp4Rt@db.internal:5432/app",
		"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
		"Qz7Xm2Pq9Rt4Lv8Nc3Kd6Wj1",
		`"hunter2hunter2"`, // quoted: a password may contain anything
		`'p@ss(w)rd{with}[brackets]'`,
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVP", // JWT: digits in segments
		"~/.ssh/id_rsa",                                     // private key path
		"8fJq2vQzLmNp4Rt",
	}
	for _, v := range accept {
		if !looksLikeCredentialValue(v) {
			t.Errorf("looksLikeCredentialValue(%q) = false; want true (real secret rejected)", v)
		}
	}
}

func TestAssignmentValueLooksLikeCredential(t *testing.T) {
	cases := []struct {
		assignment string
		want       bool
	}{
		{`db_password=Sup3rS3cretValue123`, true},
		{`db_password="Sup3rS3cretValue123"`, true},
		{`db_password=os.environ["X"]`, false},
		{`db_password=config.settings.auth`, false},
		{`db_password=`, false},
		{`db_password`, false},
	}
	for _, c := range cases {
		if got := assignmentValueLooksLikeCredential(c.assignment); got != c.want {
			t.Errorf("assignmentValueLooksLikeCredential(%q) = %v, want %v", c.assignment, got, c.want)
		}
	}
}

// Regression (#8): a credential-shaped identifier on its own must never become
// a finding, and an assignment rule must never consume the following line.
func TestCredentialShapedIdentifiersAreNotFindings(t *testing.T) {
	src := `def find(haystack, token):
    position = 0
    while position < len(haystack) and haystack[position] != token:
        position += 1
    return position

if not token: pass
token = state.get("token")
api_key = lookup("api_key")
password = os.environ["DB_PASSWORD"]
db_password = config.settings.auth
token = "${SECRET_FROM_VAULT}"
`
	rd, err := NewRegexDetector("") // embedded rules only
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	f := &filesystem.File{Path: "finder.py", Content: []byte(src), Size: int64(len(src))}
	if _, err := f.GetContent(); err != nil {
		t.Fatalf("load: %v", err)
	}
	got := rd.Detect(f)
	// The entropy detector is not involved here; only rule findings matter.
	if len(got) != 0 {
		for _, x := range got {
			t.Errorf("unexpected finding on line %d: rule=%s value=%q", x.Line, x.RuleID, x.Value)
		}
	}
}

// The counterpart: the same rules must still fire on real secrets.
func TestRealSecretsStillDetected(t *testing.T) {
	src := `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
DB_PASSWORD=Sup3rS3cretValue123
API_SECRET=Qz7Xm2Pq9Rt4Lv8Nc3Kd6Wj1
aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY01
GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345
password = "hunter2hunter2"
`
	rd, err := NewRegexDetector("") // embedded rules only
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	f := &filesystem.File{Path: ".env", Content: []byte(src), Size: int64(len(src))}
	if _, err := f.GetContent(); err != nil {
		t.Fatalf("load: %v", err)
	}
	seen := map[string]bool{}
	for _, x := range rd.Detect(f) {
		seen[x.RuleID] = true
	}
	for _, want := range []string{
		"aws-access-key-id", "aws-secret-key", "env-password",
		"env-api-key", "env-token", "database-password", "generic-password",
	} {
		if !seen[want] {
			t.Errorf("rule %q no longer detects a real secret; got %v", want, keysOf(seen))
		}
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Regression (#8): an assignment rule must not let \s* carry a match onto the
// next line, so a bare identifier at end of line cannot capture the loop body.
func TestAssignmentRulesDoNotConsumeNextLine(t *testing.T) {
	src := "def find(haystack, token):\n" +
		"    while position < len(haystack) and haystack[position] != token:\n" +
		"        position += 1\n"
	rd, err := NewRegexDetector("") // embedded rules only
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	f := &filesystem.File{Path: "finder.py", Content: []byte(src), Size: int64(len(src))}
	if _, err := f.GetContent(); err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, x := range rd.Detect(f) {
		if strings.HasPrefix(x.Value, "position") || strings.Contains(x.Value, "\n") {
			t.Errorf("finding captured across a line break: rule=%s value=%q", x.RuleID, x.Value)
		}
	}
}
