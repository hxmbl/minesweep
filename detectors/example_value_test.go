package detectors

import "testing"

// A pinned digest is a content address, not a bearer token. The reviewer's third
// finding was three `sha256:`-prefixed values reported at 60-70% by the
// env-token, env-password and env-private-key-path rules. Those rules are right
// about the grammar — `token = <64 hex>` really is credential-shaped — and wrong
// about the world: `sha256:` is the author declaring what the value is.
func TestPinnedDigestNotReportedByAnyRule(t *testing.T) {
	body := "" +
		"token = \"sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"\n" +
		"private_key = \"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n" +
		"session_secret = \"sha256:a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3\"\n" +
		"digest = \"sha512:cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\"\n"

	for _, f := range scanText(t, "pins.py", body) {
		t.Errorf("pinned digest reported: rule=%s line=%d value=%q", f.RuleID, f.Line, f.Value)
	}
}

// A digest used as a base image reference is a content address of a tarball.
func TestPinnedImageDigestNotReported(t *testing.T) {
	body := "image = \"ghcr.io/library/nginx@sha256:aaa1b2c3d4e5f60718293a4b5c6d7e8f9011223344556677889900aabbccddeeff\"\n"
	for _, f := range scanText(t, "compose.yaml", body) {
		t.Errorf("pinned image digest reported: rule=%s value=%q", f.RuleID, f.Value)
	}
}

// The other direction, and the one that matters: a bare hex value under a
// credential name is a different judgement. `sha256:` is an assertion by the
// author; a bare 64-hex run is not, and a provider that issues hex tokens is
// entitled to have them found.
func TestBareHexUnderCredentialNameStillReported(t *testing.T) {
	body := "api_token = \"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\"\n"
	if len(scanText(t, "config.yaml", body)) == 0 {
		t.Error("a bare 64-hex value assigned to api_token must still be reported")
	}
}

// A placeholder that merely shares a prefix with a real credential must still be
// reported. `sha256:` is the digest assertion; `sha256sum` is not.
func TestDigestPrefixLookalikeIsStillReported(t *testing.T) {
	body := "api_key = \"sha256sum-of-something-not-a-digest\"\n"
	got := scanText(t, "build.sh", body)
	if len(got) == 0 {
		t.Error("a value that merely starts with the digest word must still be reported")
	}
}

// AWS publishes a documentation key pair and every AWS tutorial on the internet
// contains it, so it is one of the most-copied strings in the ecosystem. It was
// reported here at 0.95 and blocked the commit that documented the suppression.
func TestAWSDocumentationKeysNotReported(t *testing.T) {
	body := "" +
		"AWS_ACCESS_KEY_ID=\x41KIAIOSFODNN7EXAMPLE\n" +
		"AWS_SECRET_ACCESS_KEY=\x77JalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"

	for _, f := range scanText(t, "tutorial.md", body) {
		t.Errorf("AWS documentation credential reported: rule=%s value=%q", f.RuleID, f.Value)
	}
}

// Matching is exact, so a real key that merely resembles the documentation one
// is still found. A prefix or substring rule would be defeated by an attacker
// padding their own key with the word "EXAMPLE", which is why this list is
// exact-match only.
func TestRealAWSKeysResemblingDocumentationOnesAreReported(t *testing.T) {
	body := "" +
		"AWS_ACCESS_KEY_ID=\x41KIAZQ4TLN2XRH7JWBVG\n" +
		"AWS_SECRET_ACCESS_KEY=\x77JalrXUtnFEMI/K7MDENGbPxRfiCTr0ub4TlzX9Q\n"

	got := scanText(t, ".env", body)
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.RuleID] = true
	}
	for _, want := range []string{"aws-access-key-id", "aws-secret-key"} {
		if !seen[want] {
			t.Errorf("%s did not fire on a real AWS key; got %v", want, seen)
		}
	}
}

// A checked-in .env.example is the single most common source of false positives
// in this tool's world. This body produced fourteen findings before the example
// check, one line of it (`DB_PASSWORD=xxxxxxxx`) producing three.
func TestCheckedInExampleConfigIsNotReported(t *testing.T) {
	body := "" +
		"AUTH_TOKEN=your-token-here\n" +
		"API_KEY=changeme\n" +
		"DB_PASSWORD=xxxxxxxx\n" +
		"SECRET=placeholder\n" +
		"CLIENT_SECRET=REPLACE_ME\n" +
		"SIGNING_KEY=dummy-value-not-real\n"

	for _, f := range scanText(t, ".env.example", body) {
		t.Errorf("placeholder reported: rule=%s line=%d value=%q", f.RuleID, f.Line, f.Value)
	}
}

// The other direction. A placeholder filter that also ate real credentials would
// turn a noisy gate into a silent one, which is the worse failure of the two.
func TestRealSecretsInAnExampleFileAreStillFound(t *testing.T) {
	body := "" +
		"AUTH_TOKEN=your-token-here\n" +
		"API_KEY=\x41KIAZQ4TLN2XRH7JWBVG\n" +
		"GITHUB_TOKEN=\x67hp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n" +
		"SLACK=\x78oxb-291847561029-8475610291847-aBcD1234eFgH5678iJkL\n"

	seen := map[string]bool{}
	for _, f := range scanText(t, ".env.example", body) {
		seen[f.RuleID] = true
	}
	for _, want := range []string{"aws-access-key-id", "github-pat", "generic-slack-token"} {
		if !seen[want] {
			t.Errorf("%s did not fire on a real credential in .env.example; got %v", want, seen)
		}
	}
}

// A credential-free connection string is not a credential. Three separate rules
// used to disagree about this, and the loosest one defined the user experience:
// detectors/database.go required a user and a password, and the two YAML rules
// did not, so `DATABASE_URL=postgres://localhost:5432/mydb` was a HIGH finding.
func TestCredentialFreeDatabaseURLIsNotReported(t *testing.T) {
	body := "" +
		"DATABASE_URL=postgres://localhost:5432/mydb\n" +
		"db_url: mysql://127.0.0.1:3306/app\n" +
		"database_uri: redis://cache.internal:6379/0\n"

	for _, f := range scanText(t, ".env.example", body) {
		t.Errorf("credential-free database URL reported: rule=%s line=%d value=%q", f.RuleID, f.Line, f.Value)
	}
}

// A connection string that does carry a password must still be found, and the
// value reported must be the URL rather than the whole assignment — see
// detectors.credentialValue.
func TestCredentialedDatabaseURLIsReportedWithTheURLAsTheValue(t *testing.T) {
	body := "DATABASE_URL=postgres://svc:P4ssw0rdHere@db.internal:5432/production\n"

	got := scanText(t, ".env", body)
	var found bool
	for _, f := range got {
		if f.RuleID != "env-database-url" {
			continue
		}
		found = true
		if want := "postgres://svc:P4ssw0rdHere@db.internal:5432/production"; f.Value != want {
			t.Errorf("value = %q, want the connection string %q", f.Value, want)
		}
	}
	if !found {
		t.Error("a credentialed DATABASE_URL must be reported")
	}
}

// `aws configure set aws_secret_access_key <value>` has no `=` for the pattern
// to key on, so the key was caught only by the entropy detector at low severity
// — which the pre-commit gate, running at medium, does not block on.
func TestAWSSecretOnACommandLineIsReported(t *testing.T) {
	body := "aws configure set aws_secret_access_key \x77JalrXUtnFEMI/K7MDENGbPxRfiCTr0ub4TlzX9Q\n"
	got := scanText(t, "setup.sh", body)
	for _, f := range got {
		if f.RuleID == "aws-secret-key" {
			return
		}
	}
	t.Errorf("aws configure set was not reported as a secret: %+v", got)
}
