package detectors

import (
	"strings"
	"testing"

	fx "minesweep/internal/fixtures"

	"minesweep/findings"
)

// STRM-721 and STRM-722 came out of the v2.5.0 canary scan, which reported four
// shapes at incident severity that are not incidents:
//
//	.pub fixture          -> ssh-authorized-keys at HIGH (public keys are shared on purpose)
//	sk_live_000…0         -> stripe-secret-key at CRITICAL (zero-entropy decoy)
//	sk_test_…             -> stripe-secret-key at CRITICAL (Stripe's documented test key)
//
// The tests below pin both directions: the false positives must stop firing at
// severity, and the real detections they sit next to must keep firing.

const sshPublicKeyLine = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 user@example.com\n"

func findType(t *testing.T, got []findings.Finding, typ string) *findings.Finding {
	t.Helper()
	for i := range got {
		if got[i].Type == typ {
			return &got[i]
		}
	}
	return nil
}

func TestSSHPublicKeyFileIsExcluded(t *testing.T) {
	// A checked-in public key is the normal case, not a leak. The *.pub filter
	// means it produces no finding at all.
	if got := scanText(t, "id_rsa.pub", sshPublicKeyLine); len(got) != 0 {
		t.Fatalf("a .pub file must produce no findings, got %d: %v", len(got), got)
	}
}

func TestSSHAuthorizedKeysIsLowSeverity(t *testing.T) {
	// An authorized_keys file is still worth mentioning — it records that a key
	// is trusted somewhere — but at LOW it is context, not an incident.
	got := scanText(t, "authorized_keys", sshPublicKeyLine)
	f := findType(t, got, "SSH Authorized Keys")
	if f == nil {
		t.Fatalf("authorized_keys content should still be detected, got %v", got)
	}
	if f.Severity != findings.SeverityLow {
		t.Fatalf("authorized_keys should be LOW, got %v", f.Severity)
	}
}

func TestSSHPrivateKeyIsStillCritical(t *testing.T) {
	// The fix must not touch private keys.
	body := "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
	got := scanText(t, "id_rsa", body)
	f := findType(t, got, "SSH Private Key")
	if f == nil {
		t.Fatalf("private key should still be detected, got %v", got)
	}
	if f.Severity != findings.SeverityCritical {
		t.Fatalf("private key should be CRITICAL, got %v", f.Severity)
	}
}

func TestStripeZeroEntropyDecoyIsNotReported(t *testing.T) {
	// A zero-filled suffix matches the key alphabet and length but carries
	// ~1.4 bits/char, well under the 3.0 floor.
	body := "sk_live_" + strings.Repeat("0", 24) + "\n"
	if got := scanText(t, "notes.txt", body); findType(t, got, "Stripe Secret Key") != nil {
		t.Fatalf("zero-entropy decoy must not be reported as a secret key: %v", got)
	}
}

func TestStripeDocumentedTestKeyIsNotCritical(t *testing.T) {
	// Stripe's own documented test key: real-shaped, but test mode.
	body := fx.StripeTestSecretKey() + "\n"
	got := scanText(t, "notes.txt", body)
	if f := findType(t, got, "Stripe Secret Key"); f != nil {
		t.Fatalf("a test key must not be reported as a live secret key: %v", f)
	}
	f := findType(t, got, "Stripe Test Secret Key")
	if f == nil {
		t.Fatalf("test key should still be reported at low severity, got %v", got)
	}
	if f.Severity != findings.SeverityLow {
		t.Fatalf("test key should be LOW, got %v", f.Severity)
	}
}

func TestStripeLiveKeyIsStillCritical(t *testing.T) {
	body := fx.StripeSecretKey() + "\n"
	got := scanText(t, "notes.txt", body)
	f := findType(t, got, "Stripe Secret Key")
	if f == nil {
		t.Fatalf("a live key must still be detected, got %v", got)
	}
	if f.Severity != findings.SeverityCritical {
		t.Fatalf("live key should be CRITICAL, got %v", f.Severity)
	}
}

// The key-type token is deliberately open-ended now: an algorithm we have not
// enumerated yet must still be recognised, while *.pub files stay excluded.
func TestSSHUnknownKeyTypeIsStillDetected(t *testing.T) {
	body := "ssh-future-ed25519@vendor AAAA" + strings.Repeat("B", 40) + " host\n"
	got := scanText(t, "authorized_keys", body)
	f := findType(t, got, "SSH Authorized Keys")
	if f == nil || f.Severity != findings.SeverityLow {
		t.Fatalf("unknown public-key type should be detected at LOW, got %v", got)
	}
}

func TestPrivateKeyPEMWrappersAreAllCritical(t *testing.T) {
	for _, header := range []string{
		"-----BEGIN PRIVATE KEY-----",           // PKCS#8
		"-----BEGIN ENCRYPTED PRIVATE KEY-----", // encrypted PKCS#8
		"-----BEGIN RSA PRIVATE KEY-----",       // PKCS#1
		"-----BEGIN EC PRIVATE KEY-----",        // EC
		"-----BEGIN OPENSSH PRIVATE KEY-----",   // OpenSSH
	} {
		t.Run(header, func(t *testing.T) {
			body := header + "\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n"
			f := findType(t, scanText(t, "key.pem", body), "SSH Private Key")
			if f == nil || f.Severity != findings.SeverityCritical {
				t.Fatalf("%s should be CRITICAL, got %v", header, f)
			}
		})
	}
}

func TestStripeRestrictedAndWebhookDecoysAreNotReported(t *testing.T) {
	body := "rk_live_" + strings.Repeat("0", 24) + "\nwhsec_" + strings.Repeat("0", 32) + "\n"
	got := scanText(t, "notes.txt", body)
	for _, typ := range []string{"Stripe Restricted Key", "Stripe Webhook Secret"} {
		if f := findType(t, got, typ); f != nil {
			t.Fatalf("zero-entropy decoy must not be reported as %s: %v", typ, f)
		}
	}
}

func TestStripeRestrictedAndWebhookStillDetected(t *testing.T) {
	// Assembled from fragments so the test file does not itself contain
	// secret-shaped strings that pushes reject.
	seed := strings.Join([]string{"4eC39Hq", "LyjWDarj", "tT1zdp7dc"}, "")
	body := strings.Join([]string{"rk_", "live_", seed}, "") + "\n"
	body += strings.Join([]string{"whsec_", seed, "Ab12Cd34"}, "") + "\n"
	got := scanText(t, "notes.txt", body)
	if f := findType(t, got, "Stripe Restricted Key"); f == nil {
		t.Fatalf("a real restricted key must still be detected, got %v", got)
	}
	if f := findType(t, got, "Stripe Webhook Secret"); f == nil {
		t.Fatalf("a real webhook secret must still be detected, got %v", got)
	}
}

func TestStripeRestrictedTestKeyIsLowNotHigh(t *testing.T) {
	seed := strings.Join([]string{"4eC39Hq", "LyjWDarj", "tT1zdp7dc"}, "")
	body := strings.Join([]string{"rk_", "test_", seed}, "") + "\n"
	got := scanText(t, "notes.txt", body)
	if f := findType(t, got, "Stripe Restricted Key"); f != nil {
		t.Fatalf("rk_test_ must not be reported as a live restricted key: %v", f)
	}
	f := findType(t, got, "Stripe Restricted Test Key")
	if f == nil || f.Severity != findings.SeverityLow {
		t.Fatalf("rk_test_ should be LOW, got %v", got)
	}
}
