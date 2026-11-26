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
