package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"minesweep/config"
	"minesweep/engine"
)

func TestApplyConfigValuesDiscoveredIgnoresSecurityKeys(t *testing.T) {
	cfg := engine.Config{RulesDir: "rules"}
	fc := &config.FileConfig{
		SuppressFile:   "cover.json",
		Profile:        "developer",
		FailOn:         "critical",
		SkipExtensions: []string{".go"},
	}

	var warn bytes.Buffer
	ignored := applyConfigValues(&cfg, fc, "/repo", map[string]bool{}, false, &warn)

	if len(ignored) != 4 {
		t.Fatalf("ignored = %v, want 4 labels", ignored)
	}
	if cfg.SuppressFile != "" || cfg.Profile != "" || cfg.FailOn != "" {
		t.Errorf("security keys leaked from discovered config: %+v", cfg)
	}
	if len(cfg.SkipExtensions) != 0 {
		t.Error("skip_extensions must be ignored from discovered config")
	}
	out := warn.String()
	for _, want := range []string{"suppress_file", "profile", "fail_on", "--config"} {
		if !bytes.Contains([]byte(out), []byte(want)) {
			t.Errorf("warning missing %q:\n%s", want, out)
		}
	}
}

func TestApplyConfigValuesTrustedHonorsSecurityKeys(t *testing.T) {
	cfg := engine.Config{}
	fc := &config.FileConfig{SuppressFile: "sup.json", Profile: "developer", FailOn: "high"}

	var warn bytes.Buffer
	ignored := applyConfigValues(&cfg, fc, t.TempDir(), map[string]bool{}, true, &warn)

	if len(ignored) != 0 {
		t.Fatalf("trusted config should honor everything, ignored=%v", ignored)
	}
	if !strings.HasSuffix(cfg.SuppressFile, "sup.json") || cfg.Profile != "developer" || cfg.FailOn != "high" {
		t.Errorf("trusted security keys not applied: %+v", cfg)
	}
}

func TestApplyConfigValuesRelativePathsResolveAgainstConfigDir(t *testing.T) {
	cfg := engine.Config{}
	fc := &config.FileConfig{
		RulesDir:     "myrules",
		SuppressFile: "sub/sup.json",
	}
	applyConfigValues(&cfg, fc, filepath.Join(string(filepath.Separator), "repo", ".config"),
		map[string]bool{}, true, nil)

	if cfg.RulesDir != filepath.Join(string(filepath.Separator), "repo", ".config", "myrules") {
		t.Errorf("rules_dir = %q", cfg.RulesDir)
	}
	wantSup := filepath.Join(string(filepath.Separator), "repo", ".config", "sub", "sup.json")
	if cfg.SuppressFile != wantSup {
		t.Errorf("suppress_file = %q, want %q", cfg.SuppressFile, wantSup)
	}
}

func TestApplyConfigValuesExplicitFlagsWinOverTrustedFile(t *testing.T) {
	cfg := engine.Config{}
	fc := &config.FileConfig{Profile: "developer", Workers: 8}

	changed := map[string]bool{"profile": true} // user passed --profile enterprise
	var other bytes.Buffer
	applyConfigValues(&cfg, fc, ".", changed, true, &other)

	if cfg.Profile != "" {
		t.Errorf("explicit CLI flag must beat file value; got profile=%q", cfg.Profile)
	}
	if cfg.Workers != 8 {
		t.Errorf("non-conflicting file key should apply; workers=%d", cfg.Workers)
	}
}

func TestApplyConfigValuesSafeKeysWorkFromDiscovered(t *testing.T) {
	cfg := engine.Config{}
	fc := &config.FileConfig{Workers: 4, Verbose: true}

	var warn bytes.Buffer
	ignored := applyConfigValues(&cfg, fc, ".", map[string]bool{}, false, &warn)

	if cfg.Workers != 4 || !cfg.Verbose {
		t.Errorf("safe keys must apply even when discovered: %+v", cfg)
	}
	if len(ignored) != 0 || warn.Len() != 0 {
		t.Errorf("no warning expected for safe-only config: %v / %s", ignored, warn.String())
	}
}
