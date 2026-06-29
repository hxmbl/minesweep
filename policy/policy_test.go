package policy

import (
	"os"
	"path/filepath"
	"testing"

	"minesweep/findings"
)

func TestEvaluate(t *testing.T) {
	policies := []PolicyRule{
		{Tags: []string{"private-key"}, Action: findings.ActionBlock, Reason: "Never share private keys"},
		{Tags: []string{"credentials"}, Action: findings.ActionRedact, MinSeverity: "high"},
	}

	f1 := findings.Finding{
		Type:     "SSH Private Key",
		Severity: findings.SeverityCritical,
		Tags:     []string{"ssh", "credentials", "private-key"},
	}
	action1 := Evaluate(f1, policies)
	if action1 != findings.ActionBlock {
		t.Fatalf("expected block for private key, got %s", action1)
	}

	f2 := findings.Finding{
		Type:     "AWS Access Key ID",
		Severity: findings.SeverityCritical,
		Tags:     []string{"aws", "cloud", "credentials"},
	}
	action2 := Evaluate(f2, policies)
	if action2 != findings.ActionRedact {
		t.Fatalf("expected redact for critical credentials, got %s", action2)
	}
}

func TestDefaultAction(t *testing.T) {
	tests := []struct {
		severity findings.Severity
		want     findings.Action
	}{
		{findings.SeverityCritical, findings.ActionBlock},
		{findings.SeverityHigh, findings.ActionRedact},
		{findings.SeverityMedium, findings.ActionWarn},
		{findings.SeverityLow, findings.ActionAllow},
		{findings.SeverityInfo, findings.ActionAllow},
	}
	for _, tt := range tests {
		f := findings.Finding{Severity: tt.severity}
		got := Evaluate(f, nil)
		if got != tt.want {
			t.Errorf("default for %s = %s, want %s", tt.severity, got, tt.want)
		}
	}
}

func TestResolveProfile(t *testing.T) {
	policies, err := ResolveProfile("../profiles", "developer")
	if err != nil {
		t.Fatalf("ResolveProfile: %v", err)
	}
	if len(policies) == 0 {
		t.Fatal("expected policies from profile")
	}
	t.Logf("loaded %d policy rules from developer profile", len(policies))
}

// ─── Brutal policy tests ────────────────────────────────────────────

func TestEvaluateEmptyPolicies(t *testing.T) {
	f := findings.Finding{
		Type:     "Test Finding",
		Severity: findings.SeverityCritical,
		Tags:     []string{"test"},
	}
	action := Evaluate(f, nil)
	if action != findings.ActionBlock {
		t.Fatalf("expected block for critical finding with nil policies, got %s", action)
	}

	action = Evaluate(f, []PolicyRule{})
	if action != findings.ActionBlock {
		t.Fatalf("expected block for critical finding with empty policies, got %s", action)
	}
}

func TestEvaluateAllSeverities(t *testing.T) {
	tests := []struct {
		severity findings.Severity
		want     findings.Action
	}{
		{findings.SeverityInfo, findings.ActionAllow},
		{findings.SeverityLow, findings.ActionAllow},
		{findings.SeverityMedium, findings.ActionWarn},
		{findings.SeverityHigh, findings.ActionRedact},
		{findings.SeverityCritical, findings.ActionBlock},
	}
	for _, tt := range tests {
		t.Run(tt.severity.String(), func(t *testing.T) {
			f := findings.Finding{Severity: tt.severity}
			got := Evaluate(f, nil)
			if got != tt.want {
				t.Errorf("default action for %s = %s, want %s", tt.severity, got, tt.want)
			}
		})
	}
}

func TestEvaluateConflictingPolicies(t *testing.T) {
	policies := []PolicyRule{
		{Tags: []string{"credentials"}, Action: findings.ActionAllow},
		{Tags: []string{"credentials"}, Action: findings.ActionBlock, MinSeverity: "high"},
	}
	f := findings.Finding{
		Type:     "AWS Key",
		Severity: findings.SeverityCritical,
		Tags:     []string{"aws", "credentials"},
	}
	// First matching policy wins: "credentials" matches first, so ActionAllow
	action := Evaluate(f, policies)
	if action != findings.ActionAllow {
		t.Fatalf("expected first policy (allow) to win, got %s", action)
	}
}

func TestEvaluateWildcardTag(t *testing.T) {
	policies := []PolicyRule{
		{Tags: []string{"*"}, Action: findings.ActionBlock, Reason: "catch-all"},
	}
	f := findings.Finding{
		Type:     "Anything",
		Severity: findings.SeverityLow,
		Tags:     []string{"whatever"},
	}
	action := Evaluate(f, policies)
	if action != findings.ActionBlock {
		t.Fatalf("expected wildcard tag * to match, got %s", action)
	}
}

func TestEvaluateNoMatchingTag(t *testing.T) {
	policies := []PolicyRule{
		{Tags: []string{"unrelated"}, Action: findings.ActionBlock},
	}
	f := findings.Finding{
		Type:     "Test",
		Severity: findings.SeverityCritical,
		Tags:     []string{"something-else"},
	}
	// Falls back to default
	action := Evaluate(f, policies)
	if action != findings.ActionBlock {
		t.Fatalf("expected block (default for critical), got %s", action)
	}
}

func TestEvaluateMinSeverityFilter(t *testing.T) {
	policies := []PolicyRule{
		{Tags: []string{"creds"}, Action: findings.ActionBlock, MinSeverity: "high"},
	}
	lowF := findings.Finding{
		Type:     "Low Cred",
		Severity: findings.SeverityLow,
		Tags:     []string{"creds"},
	}
	action := Evaluate(lowF, policies)
	if action == findings.ActionBlock {
		t.Fatal("low severity should not match high+ policy")
	}
	highF := findings.Finding{
		Type:     "High Cred",
		Severity: findings.SeverityHigh,
		Tags:     []string{"creds"},
	}
	action = Evaluate(highF, policies)
	if action != findings.ActionBlock {
		t.Fatal("high severity should match high+ policy")
	}
}

func TestEvaluateMultipleTags(t *testing.T) {
	policies := []PolicyRule{
		{Tags: []string{"a", "b"}, Action: findings.ActionBlock},
	}
	f := findings.Finding{
		Type:     "Test",
		Severity: findings.SeverityLow,
		Tags:     []string{"a"},
	}
	action := Evaluate(f, policies)
	if action != findings.ActionBlock {
		t.Fatalf("finding with one matching tag should match OR-semantics policy, got %s", action)
	}
}

func TestResolveProfileNotFound(t *testing.T) {
	_, err := ResolveProfile("../profiles", "nonexistent-profile-name")
	if err == nil {
		t.Fatal("expected error for nonexistent profile")
	}
}

func TestResolveProfileEmptyDir(t *testing.T) {
	dir := t.TempDir()
	_, err := ResolveProfile(dir, "default")
	if err == nil {
		t.Fatal("expected error for empty profiles dir")
	}
}

func TestResolveProfileCycleDetected(t *testing.T) {
	dir := t.TempDir()

	aContent := []byte("name: A\nextends: b\nactions:\n  - tags: [\"a\"]\n    action: allow\n")
	bContent := []byte("name: B\nextends: a\nactions:\n  - tags: [\"b\"]\n    action: warn\n")
	os.WriteFile(filepath.Join(dir, "a.yml"), aContent, 0644)
	os.WriteFile(filepath.Join(dir, "b.yml"), bContent, 0644)

	_, err := ResolveProfile(dir, "a")
	if err == nil {
		t.Fatal("expected error for cyclic profile resolution (a -> b -> a)")
	}
}

func TestResolveProfileSelfExtends(t *testing.T) {
	dir := t.TempDir()

	selfContent := []byte("name: Self\nextends: self\nactions:\n  - tags: [\"x\"]\n    action: block\n")
	os.WriteFile(filepath.Join(dir, "self.yml"), selfContent, 0644)

	_, err := ResolveProfile(dir, "self")
	if err == nil {
		t.Fatal("expected error for self-extending profile (self -> self)")
	}
}
