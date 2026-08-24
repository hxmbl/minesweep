package policy

import (
	"strings"
	"testing"
)

func TestValidateRulesRejectsBadAction(t *testing.T) {
	rules := []PolicyRule{{Tags: []string{"aws"}, Action: "blok"}}
	err := ValidateRules(rules)
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
	if !strings.Contains(err.Error(), "blok") || !strings.Contains(err.Error(), "allow, warn, redact, block") {
		t.Errorf("error should mention bad value and valid set: %v", err)
	}
}

func TestValidateRulesRejectsBadSeverity(t *testing.T) {
	rules := []PolicyRule{{Tags: []string{"aws"}, Action: "warn", MinSeverity: "hight"}}
	if err := ValidateRules(rules); err == nil {
		t.Fatal("expected error for invalid min_severity")
	}
}

func TestValidateRulesAcceptsBuiltinProfiles(t *testing.T) {
	for _, name := range []string{"default", "developer", "enterprise", "public-github"} {
		rules, err := ResolveProfile("../profiles", name)
		if err != nil {
			t.Errorf("built-in profile %q failed validation: %v", name, err)
		}
		if len(rules) == 0 {
			t.Errorf("profile %q resolved to zero rules", name)
		}
	}
}
