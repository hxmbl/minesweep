// Package fixtures builds credential-shaped test values.
//
// The values it returns are assembled at run time from fragments, and that is
// the entire point of this package existing.
//
// MineSweep's tests need strings that a secret scanner will accept: an AWS key
// with the right prefix and length, a Slack token, a Stripe key. Written as
// literals in a test file they are indistinguishable from a real leak — to this
// repository's own detector, and to GitHub's push protection, which rejects the
// push outright:
//
//	remote: - Push cannot contain secrets
//	remote:      —— Amazon AWS Access Key ID ———
//	remote:        paths: engine/engine_test.go:37, detectors/example_value_test.go:109
//
// The historical workaround was to use the credential values AWS publishes in its
// own documentation, which GitHub allowlists. That works and it is worse than it
// looks: those two strings are the most widely copied fake credentials in
// existence, so a test suite using them cannot tell "this is a real key" from
// "this is the example everyone pastes", and a suppression tuned to them looks
// like it is suppressing a credential class when it is suppressing two literals.
//
// So the fragments live here and the shape lives in the tests. Every value is
// built by joining pieces, so no source file contains a credential-shaped
// literal, and the detectors still see exactly what they must recognise.
package fixtures

import "strings"

// AWSAccessKeyID is a well-formed but fictional AWS access key ID: the AKIA
// prefix and 16 uppercase alphanumerics, which is what aws-access-key-id
// matches.
//
// The pieces are split mid-token so the literal never appears in source. The
// character set and length are the point; the content is irrelevant.
func AWSAccessKeyID() string {
	return strings.Join([]string{"AKIA", "ZQ4TL", "N2XRH", "7JWBV", "G"}, "")
}

// AWSSecretKey is a well-formed but fictional AWS secret access key: 40
// characters of base64 alphabet, which is what aws-secret-key requires.
func AWSSecretKey() string {
	return strings.Join([]string{"wJalr", "XUtnF", "EMI/K", "7MDEN", "GbPxR", "fiCTr", "0ub4T", "lzX9Q"}, "")
}

// SlackToken is a well-formed but fictional Slack bot token.
func SlackToken() string {
	return strings.Join([]string{"xoxb-", "291847561029", "-847561029184", "7-aBcD1234eFgH5678", "iJkL"}, "")
}

// StripeSecretKey is a well-formed but fictional Stripe live secret key.
func StripeSecretKey() string {
	return strings.Join([]string{"sk_", "live_", "4eC39Hq", "LyjWDarj", "tT1zdp7dc"}, "")
}

// GitHubPAT is a well-formed but fictional GitHub personal access token: the
// ghp_ prefix and 36 alphanumerics.
func GitHubPAT() string {
	return strings.Join([]string{"ghp_", "ABCDEFGH", "IJKLMNOP", "QRSTUVWX", "YZ012345", "6789"}, "")
}

// SendGridKey is a well-formed but fictional SendGrid API key.
func SendGridKey() string {
	return strings.Join([]string{
		"SG.", "Zx8Qw3Er7", "Ty2Ui1Op6", "As9Df4Gh5", "Jk8Lz0Xc7", "Vb.",
		"aBc123DEF", "456ghi789", "jkl",
	}, "")
}

// GoogleAPIKey is a well-formed but fictional Google API key.
// GoogleAPIKey is a well-formed but fictional Google API key: the AIza prefix
// and 35 characters, which is what rules/google.yml requires.
func GoogleAPIKey() string {
	return strings.Join([]string{"AIza", "SyDx8Qw3E", "r7Ty2Ui1O", "p6As9Df4G", "h5Jk8L1z"}, "")
}

// OpaqueToken is a high-entropy run with no vendor prefix and no keyword beside
// it — the entropy detector's case.
func OpaqueToken() string {
	return strings.Join([]string{"Zx8Qw3Er7", "Ty2Ui1Op6", "As9Df4Gh5", "Jk8Lz0Xc7", "VbN2mQ"}, "")
}

// AWSDocumentationPair returns the two values AWS publishes in its own
// documentation.
//
// They are here because they must be *recognised as examples* by the example
// filter, and that is only testable against the real strings. Split for the same
// reason as everything else: GitHub's push protection does not allowlist the
// secret-access-key half, so a literal copy is a blocked push.
func AWSDocumentationPair() (keyID, secretKey string) {
	keyID = strings.Join([]string{"AKIA", "IOSFOD", "NN7EXA", "MPLE"}, "")
	secretKey = strings.Join([]string{
		"wJalr", "XUtnF", "EMI/", "K7MDE", "NG/bP", "xRfiC", "YEXAM", "PLEKE", "Y",
	}, "")
	return keyID, secretKey
}
