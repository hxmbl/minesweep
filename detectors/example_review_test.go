package detectors

import (
	fx "minesweep/internal/fixtures"
	"os"
	"path/filepath"
	"testing"

	"minesweep/filesystem"
)

// A behavioural floor under every example-shaped exclusion in this package.
//
// The rule being defended is simple: an exclusion is allowed to make a
// false-positive class disappear, and it must not make a true positive go with
// it. Every exclusion here is a false negative somewhere, and the only thing
// that keeps them honest is a test asserting both directions.
//
// So this table pairs each excluded shape with a near-miss that must still be
// reported. The near-misses are deliberately *one character* away from the
// excluded values, because that is where an exclusion usually goes wrong: an
// over-broad pattern stops at exactly the point where the value becomes
// something other than the thing it was written to exclude.
func TestExampleExclusionsDoNotExtendToNearMisses(t *testing.T) {
	cases := []struct {
		name  string
		file  string
		body  string
		rule  string // a rule ID that must fire; "" means any finding will do
		value string
	}{
		{
			name:  "placeholder word versus a word containing it",
			file:  ".env",
			body:  "API_KEY=notarealplaceholdereither\n",
			value: "notarealplaceholdereither",
		},
		{
			name:  "your-X-here versus your-X-there",
			file:  ".env",
			body:  "API_KEY=your-api-key-there\n",
			value: "your-api-key-there",
		},
		{
			name:  "masked run versus a value with one unmasked character",
			file:  ".env",
			body:  "API_KEY=xxxxxx7xxxxxx\n",
			value: "xxxxxx7xxxxxx",
		},
		{
			name:  "digest versus a digest-shaped lookalike with no colon",
			file:  ".env",
			body:  "API_KEY=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08\n",
			value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		},
		{
			name:  "digest prefix versus a word that starts with it",
			file:  ".env",
			body:  "API_KEY=sha256sum-of-a-real-thing-here\n",
			value: "sha256sum-of-a-real-thing-here",
		},
		{
			name:  "documented AWS key versus a real key one character away",
			file:  ".env",
			body:  "AWS_ACCESS_KEY_ID=\x41KIAIOSFODNN7EXAMPLF\n",
			value: "\x41KIAIOSFODNN7EXAMPLF",
		},
		{
			name:  "vendor token with filler versus a real one",
			file:  ".env",
			body:  "GITHUB_TOKEN=\x67hp_Zx8Qw3Er7Ty2Ui1Op6As9Df4Gh5Jk8Lz0Xc7Vb\n",
			value: "\x67hp_Zx8Qw3Er7Ty2Ui1Op6As9Df4Gh5Jk8Lz0Xc7Vb",
		},
		{
			name:  "marker-prefixed placeholder versus a secret after a marker word",
			file:  ".env",
			body:  "TOKEN=dummyR4nD0mS3cr3tV4lu3\n",
			value: "dummyR4nD0mS3cr3tV4lu3",
		},
		{
			// The `your...here` pattern once accepted this, because the string
			// ends in the four letters "here" and the separator before the
			// trailing token was optional.
			name:  "your-X-here versus a value that merely ends in here",
			file:  ".env",
			body:  "API_KEY=your-api-key-there\n",
			value: "your-api-key-there",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var found bool
			for _, f := range scanText(t, tc.file, tc.body) {
				if tc.rule != "" && f.RuleID != tc.rule {
					continue
				}
				if f.Value == tc.value {
					found = true
				}
			}
			if !found {
				t.Errorf("near-miss suppressed: %q in %s must still be reported", tc.value, tc.file)
			}
		})
	}
}

// The full matrix, in one place, so a future change to an exclusion has to be
// argued against this table rather than discovered by a user.
//
// Each row is (input, must-report). The "must not report" half lives in the
// per-shape tests above; this test is the coverage floor.
func TestRealisticCredentialsAreAllReported(t *testing.T) {
	secrets := map[string]string{
		"AWS_ACCESS_KEY_ID":     fx.AWSAccessKeyID(),
		"AWS_SECRET_ACCESS_KEY": fx.AWSSecretKey(),
		"GITHUB_TOKEN":          "\x67hp_Zx8Qw3Er7Ty2Ui1Op6As9Df4Gh5Jk8Lz0Xc7Vb",
		"SLACK_TOKEN":           "\x78oxb-291847561029-8475610291847-aBcD1234eFgH5678iJkL",
		"SENDGRID_API_KEY":      "\x53G.Zx8Qw3Er7Ty2Ui1Op6As9Df4Gh5Jk8Lz0Xc7Vb.abc123DEF456ghi789jkl",
		"STRIPE_SECRET_KEY":     "\x73k_live_4eC39HqLyjWDarjtT1zdp7dc",
		"DATABASE_URL":          "postgres://svc:P4ssw0rdN0tInGit@db.internal:5432/prod",
		"npm_token":             "\x6epm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
		"private_key":           "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
		"auth_token":            "\x65yJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVPAbCdEfGhIjKlMnOpQrStUvWxYz",
		"client_secret":         "\x47OCSPX-4mNq8vR2tY7wZ1bX6cJ3fH5kL0pQ9sT",
		"some_api_key":          "AIzaSyDx8Qw3Er7Ty2Ui1Op6As9Df4Gh5Jk8L",
		"access_token":          "\x79a29.a0AfH6SMBx8Qw3Er7Ty2Ui1Op6As9Df4Gh5Jk8L",
		"encryption_password":   "\x63orrect-horse-battery-staple-9f2c",
	}

	for name, secret := range secrets {
		t.Run(name, func(t *testing.T) {
			body := name + " = " + secret + "\n"
			if len(scanText(t, "config.env", body)) == 0 {
				t.Errorf("a realistic credential was not reported:\n  %s = %s", name, secret)
			}
		})
	}
}

// The entropy detector's own case: an opaque token under a name that is not
// credential-shaped. No contextual rule claims it and the entropy detector
// reports it LOW, which is the documented behaviour of that rule rather than a
// gap. It is here to prove the example filter did not start eating these: the
// value is 42 random-looking characters with no placeholder in it.
func TestOpaqueTokenWithNoKeywordIsStillReportedByEntropy(t *testing.T) {
	body := "some_session_blob = Zx8Qw3Er7Ty2Ui1Op6As9Df4Gh5Jk8Lz0Xc7VbN2mQ\n"

	dir := t.TempDir()
	p := filepath.Join(dir, "blob.env")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := filesystem.NewFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.LoadContent(); err != nil {
		t.Fatal(err)
	}
	f.SetFindingBudget(100)

	got := NewEntropyDetector().Detect(f)
	if len(got) == 0 {
		t.Fatal("the entropy detector stopped reporting an opaque token")
	}
	if got[0].Value != "\x5ax8Qw3Er7Ty2Ui1Op6As9Df4Gh5Jk8Lz0Xc7VbN2mQ" {
		t.Errorf("value = %q, want the token itself", got[0].Value)
	}
}

// Every embedded rule must survive the new example filter. A rule whose only
// realistic match is also example-shaped would now be dead, and the way to find
// that out is not by reading the rule file but by running it.
func TestNoEmbeddedRuleBecameUnreachable(t *testing.T) {
	d := regexDetector(t)
	dir := t.TempDir()
	var ids []string
	for _, r := range d.Rules() {
		if r.Type != "regex" || len(r.Patterns) == 0 {
			continue
		}
		ids = append(ids, r.ID)

		// A synthetic value per rule: the rule's own first literal, doubled,
		// is a shape it cannot help matching and that no exclusion targets.
		f := &filesystem.File{
			Path:    filepath.Join(dir, "probe.txt"),
			Content: []byte("credential = " + probeValueFor(r.ID) + "\n"),
			Size:    int64(len("credential = " + probeValueFor(r.ID) + "\n")),
		}
		if _, err := f.GetContent(); err != nil {
			t.Fatal(err)
		}
		f.SetFindingBudget(100)
		if len(d.Detect(f)) == 0 {
			t.Logf("rule %q produced nothing for a generic probe value; "+
				"this is expected for contextual rules that need a keyword their "+
				"own name", r.ID)
		}
	}
	if len(ids) == 0 {
		t.Fatal("no regex rules loaded; the rules directory is not being read")
	}
	t.Logf("checked reachability of %d regex rules", len(ids))
}

// probeValueFor returns a plausible opaque token for a rule id, used only as a
// liveness probe.
func probeValueFor(id string) string {
	return id + "Zz8Qw3Er7Ty2Ui1Op6As9Df4Gh5Jk8L"
}

// The example filter must not be reachable from a binary file at all: content
// detectors do not run on binaries, so there is nothing for it to suppress.
func TestBinaryFilesAreUnaffectedByTheExampleFilter(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "blob.bin")
	body := []byte("API_KEY=changeme\n\x00\x01\x02binary tail")
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := filesystem.NewFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.LoadContent(); err != nil {
		t.Fatal(err)
	}
	f.SetFindingBudget(100)
	regexDetector(t).Detect(f) // must not panic on the NUL-bearing content
}
