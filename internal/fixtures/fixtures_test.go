package fixtures

import (
	"os"
	"regexp"
	"testing"
)

// readSelf returns this package's source, so the literal scan below inspects the
// bytes that would be pushed rather than a reconstruction of them.
func readSelf() (string, error) {
	b, err := os.ReadFile("fixtures.go")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Every fixture must satisfy the shape the detector it feeds actually matches.
// A fixture that quietly stopped matching would turn a detection test into a
// test of nothing, and it would fail as a missed-detection bug in a package far
// from here.
//
// The patterns are copies of the ones in rules/*.yml. They are duplicated
// deliberately: a fixture helper that imported the rule's own regex would go
// quiet when the rule changes, which is the failure this is meant to prevent.
func TestFixturesMatchTheShapeTheirDetectorRequires(t *testing.T) {
	cases := []struct {
		name string
		got  string
		re   string
	}{
		{"AWSAccessKeyID", AWSAccessKeyID(), `^AKIA[0-9A-Z]{16}$`},
		{"AWSSecretKey", AWSSecretKey(), `^[A-Za-z0-9/+=]{40}$`},
		{"SlackToken", SlackToken(), `^xox[baprs]-[0-9A-Za-z\-_]+$`},
		{"StripeSecretKey", StripeSecretKey(), `^sk_live_[0-9a-zA-Z]{24}$`},
		{"GitHubPAT", GitHubPAT(), `^ghp_[0-9A-Za-z]{36}$`},
		{"GoogleAPIKey", GoogleAPIKey(), `^AIza[0-9A-Za-z\-_]{35}$`},
		{"OpaqueToken", OpaqueToken(), `^[A-Za-z0-9]{20,}$`},
	}
	for _, c := range cases {
		if !regexp.MustCompile(c.re).MatchString(c.got) {
			t.Errorf("%s = %q does not match %s", c.name, c.got, c.re)
		}
	}
}

// The AWS documentation pair must be the real published strings, because the
// example filter is keyed on them exactly. If either drifts, the filter silently
// stops recognising it and the only symptom is a reappearing false positive.
func TestAWSDocumentationPairIsExact(t *testing.T) {
	keyIDSuffix, secretSuffix := "IOSFODNN7EXAMPLE", "XUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	keyID, secretKey := AWSDocumentationPair()

	// The expected values are assembled from fragments for the same reason the
	// fixtures are: a literal copy of a published credential-shaped string is a
	// blocked push.
	if want := "AKIA" + keyIDSuffix; keyID != want {
		t.Errorf("documentation key id = %q, want %q; the example filter is keyed on the exact published value",
			keyID, want)
	}
	if want := "wJalr" + secretSuffix; secretKey != want {
		t.Errorf("documentation secret = %q, want the published value", secretKey)
	}
}

// The property this package exists for: no source file may contain a
// credential-shaped literal, because GitHub's push protection rejects the push
// and cannot tell a test fixture from a leak.
//
// This is checked against the package's own source rather than trusted, so a
// future contributor who adds a bare literal gets a test failure instead of a
// rejected push.
func TestNoCredentialShapedLiteralInSource(t *testing.T) {
	patterns := map[string]*regexp.Regexp{
		"AWS access key id":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"GitHub PAT":            regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`),
		"Slack token":           regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{20,}`),
		"Stripe live key":       regexp.MustCompile(`sk_live_[0-9A-Za-z]{24}`),
		"Google API key":        regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`),
		"SendGrid key":          regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{16,}\.`),
		"AWS secret access key": regexp.MustCompile(`[A-Za-z0-9/+=]{40}`),
	}

	// Read this file back off disk: the literals are split across string
	// literals in source precisely so that a source scan does not see them.
	src, err := readSelf()
	if err != nil {
		t.Fatal(err)
	}
	for name, re := range patterns {
		if m := re.FindString(src); m != "" {
			t.Errorf("source contains a %s-shaped literal (%q); "+
				"build fixtures from fragments in this package instead, or the push will be "+
				"rejected by push protection", name, m)
		}
	}
}
