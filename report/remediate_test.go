package report

import (
	"strings"
	"testing"

	"minesweep/findings"
)

func TestRemediationExactRuleID(t *testing.T) {
	got := RemediationText("aws-access-key-id", nil)
	if !strings.Contains(got, "AWS IAM") {
		t.Errorf("expected AWS-specific remediation, got %q", got)
	}

	got = RemediationText("ssh-private-key", []string{"credentials"})
	if !strings.Contains(got, "git history") {
		t.Errorf("expected private-key remediation mentioning git history, got %q", got)
	}
}

func TestRemediationByTagPriority(t *testing.T) {
	cases := []struct {
		name     string
		ruleID   string
		tags     []string
		contains string
	}{
		{"private key in first position", "unknown-rule", []string{"private-key", "credentials"}, "Private keys"},
		{"jwt before credentials", "unknown-rule", []string{"jwt", "credentials"}, "compromised"},
		{"api-key fallback", "unknown-rule", []string{"api-key", "email"}, "API key"},
		{"password fallback", "unknown-rule", []string{"password"}, "Change this password"},
		{"database fallback", "unknown-rule", []string{"database"}, "database credentials"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RemediationText(c.ruleID, c.tags)
			if !strings.Contains(got, c.contains) {
				t.Errorf("RemediationText(%q, %v) = %q, want substring %q", c.ruleID, c.tags, got, c.contains)
			}
		})
	}
}

func TestRemediationSeverityFallback(t *testing.T) {
	f := findings.Finding{RuleID: "no-such-rule", Severity: findings.SeverityCritical}
	got := remediationFor(f)
	if !strings.Contains(got, "compromised") {
		t.Errorf("critical fallback should mention compromise, got %q", got)
	}

	low := findings.Finding{RuleID: "no-such-rule", Severity: findings.SeverityLow}
	if txt := remediationFor(low); txt != "" {
		t.Errorf("low severity unknown rule should have no remediation, got %q", txt)
	}
}

func TestEveryBuiltInRuleIDHasSpecificRemediation(t *testing.T) {
	for _, id := range []string{
		"aws-access-key-id", "aws-secret-key", "aws-session-token",
		"github-pat", "gcp-service-account-key", "google-api-key",
		"ssh-private-key", "pgp-private-key",
		"stripe-secret-key", "sendgrid-api-key", "generic-npm-token",
		"database-url", "postgres-connection-string", "mongodb-connection-string",
		"mysql-connection-string", "redis-connection-string",
		"entropy-high", "base64-high-entropy",
	} {
		if RemediationText(id, nil) == "" {
			t.Errorf("rule %q has no remediation entry", id)
		}
	}
}

func TestWrapText(t *testing.T) {
	long := strings.Repeat("word ", 40)
	wrapped := wrapText(long, 10)
	for _, line := range strings.Split(wrapped, "\n") {
		if len(line) > wrapWidth+10 {
			t.Errorf("wrapped line too long: %d chars", len(line))
		}
	}
	if short := wrapText("tiny", 10); short != "tiny" {
		t.Errorf("short text should be unchanged, got %q", short)
	}
}
