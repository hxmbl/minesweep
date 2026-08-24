package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"minesweep/detectors"
	"minesweep/engine"
	"minesweep/findings"
)

func TestRunInitCreatesConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if err := runInit(false); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	data, err := os.ReadFile(".minesweep.yml")
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}
	if !strings.Contains(string(data), "profile: default") {
		t.Error("expected template to set default profile")
	}
}

func TestRunInitRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	if err := os.WriteFile(".minesweep.yml", []byte("keep: me\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runInit(false); err == nil {
		t.Fatal("expected error when config exists without --force")
	}
	if err := runInit(true); err != nil {
		t.Fatalf("runInit --force: %v", err)
	}
	data, _ := os.ReadFile(".minesweep.yml")
	if strings.Contains(string(data), "keep: me") {
		t.Error("--force should overwrite the file")
	}
}

func TestMatchRulesExactPrefixAndSubstring(t *testing.T) {
	all := []detectors.Rule{
		{ID: "aws-access-key-id", Name: "AWS Access Key ID"},
		{ID: "aws-account-id", Name: "AWS Account ID"},
		{ID: "github-pat", Name: "GitHub Personal Access Token"},
	}

	if got := matchRules(all, "github-pat"); len(got) != 1 || got[0].ID != "github-pat" {
		t.Errorf("exact match failed: %v", got)
	}
	if got := matchRules(all, "aws-a"); len(got) != 2 {
		t.Errorf("prefix match should find both aws rules, got %d", len(got))
	}
	if got := matchRules(all, "personal access"); len(got) != 1 || got[0].ID != "github-pat" {
		t.Errorf("substring-by-name match failed: %v", got)
	}
	if got := matchRules(all, "zzz-nothing"); len(got) != 0 {
		t.Errorf("expected no matches, got %v", got)
	}
}

func TestExplainRuleAmbiguousAndMissing(t *testing.T) {
	all := []detectors.Rule{
		{ID: "aws-access-key-id", Name: "AWS Access Key ID"},
		{ID: "aws-account-id", Name: "AWS Account ID"},
	}

	if err := explainRule(all, "aws-access-key-id"); err != nil {
		t.Errorf("exact match should succeed, got %v", err)
	}
	if err := explainRule(all, "zzz-nothing"); err == nil {
		t.Error("unknown rule should return an error")
	}
}

func TestLoadAllRulesFindsEmbedded(t *testing.T) {
	cfg.RulesDir = filepath.Join(t.TempDir(), "does-not-exist")
	all, err := loadAllRules()
	if err != nil {
		t.Fatalf("loadAllRules: %v", err)
	}
	if len(all) < 40 {
		t.Errorf("expected embedded fallback with many rules, got %d", len(all))
	}
	for _, r := range all {
		if r.ID == "" {
			t.Fatal("rule with empty ID loaded")
		}
	}
}

func TestNextStepHints(t *testing.T) {
	cfg = engine.Config{}
	report := &findings.RiskReport{Findings: []findings.Finding{{Severity: findings.SeverityHigh}}}

	hints := nextStepHints(t.TempDir(), report)
	joined := strings.Join(hints, "\n")
	if !strings.Contains(joined, "--update-baseline") {
		t.Errorf("expected baseline hint for unbaselined findings, got: %s", joined)
	}
	if !strings.Contains(joined, "-v") {
		t.Errorf("expected verbose hint, got: %s", joined)
	}

	clean := &findings.RiskReport{}
	hints = nextStepHints(t.TempDir(), clean)
	for _, h := range hints {
		if strings.Contains(h, "--update-baseline") {
			t.Error("clean scan should not suggest baselining")
		}
	}
}

func TestHasPreCommitHook(t *testing.T) {
	top := t.TempDir()
	if hasPreCommitHook(top) {
		t.Fatal("no hook dir yet; should be false")
	}
	hooks := filepath.Join(top, ".git", "hooks")
	if err := os.MkdirAll(hooks, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte("# MineSweep pre-commit hook\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if !hasPreCommitHook(top) {
		t.Fatal("expected MineSweep hook detection")
	}

	other := filepath.Join(hooks, "unrelated.sh")
	_ = other
	if err := os.WriteFile(filepath.Join(hooks, "pre-commit"), []byte("# someone else's hook\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if hasPreCommitHook(top) {
		t.Error("foreign hooks must not count as ours")
	}
}

func TestRenderGroupedHelpCoversAllFlags(t *testing.T) {
	root := &cobra.Command{
		Use:  "minesweep [path]",
		Long: "test",
	}
	root.Flags().String("rules", "", "r")
	root.Flags().String("policy", "", "")
	root.Flags().String("profile", "", "")

	out := renderGroupedHelp(root)
	if !strings.Contains(out, "Essential:") || !strings.Contains(out, "Policy & rules:") {
		t.Errorf("expected section titles in help:\n%s", out)
	}
	if !strings.Contains(out, "--profile") {
		t.Error("expected registered flag rendered in its section")
	}
}

func TestDisplayVersionFallback(t *testing.T) {
	if displayVersion() == "" {
		t.Fatal("displayVersion should never be empty")
	}
	orig := toolVersion
	defer func() { toolVersion = orig }()
	toolVersion = "9.9.9"
	if displayVersion() != "9.9.9" {
		t.Errorf("stamped version not honored: %q", displayVersion())
	}
}
