package main

import (
	"bytes"
	"io"
	"slices"
	"testing"

	"minesweep/config"
	"minesweep/engine"
)

// #4: max_file_size_mb was classed as "performance", so a repo-supplied config
// could use it to make a credential file unreadable. An 8 MB .env holding an AWS
// key scanned clean and exited 0 with only
//
//	max_file_size_mb: 1
//
// in a discovered .minesweep.yml. Every knob that reduces coverage is now
// secure:true, and applyConfigValues must name what it dropped.
func TestDiscoveredConfigCannotShrinkCoverage(t *testing.T) {
	fc := &config.FileConfig{MaxFileSizeMB: 1, MaxFiles: 5, MaxFindings: 5, MemoryLimitMB: 16}

	var buf bytes.Buffer
	changed := map[string]bool{}
	ignored := applyConfigValues(&engine.Config{}, fc, t.TempDir(), changed, false, &buf)

	missed := ""
	for _, label := range []string{"max_file_size_mb", "max_files", "max_findings", "memory_limit_mb"} {
		if !slices.Contains(ignored, label) {
			missed = label
			break
		}
	}
	if missed != "" {
		t.Errorf("coverage-reducing key %q was not reported as ignored (ignored: %v)", missed, ignored)
	}

	c := engine.Config{}
	var buf2 bytes.Buffer
	applyConfigValues(&c, fc, t.TempDir(), map[string]bool{}, false, &buf2)
	if c.MaxFileSizeMB != 0 || c.MaxFiles != 0 || c.MaxFindings != 0 || c.MemoryLimitMB != 0 {
		t.Errorf("untrusted config reached the engine: %+v", c)
	}
	if buf2.Len() == 0 {
		t.Error("dropping keys must be reported, not silent")
	}
}

// The same config, explicitly named with --config, is the user's own and is
// honoured.
func TestTrustedConfigStillAppliesCoverageKeys(t *testing.T) {
	fc := &config.FileConfig{MaxFileSizeMB: 1}
	c := engine.Config{}
	applyConfigValues(&c, fc, t.TempDir(), map[string]bool{}, true, io.Discard)
	if c.MaxFileSizeMB != 1 {
		t.Errorf("an explicit --config should apply max_file_size_mb, got %+v", c)
	}
}

func TestAllCoverageKeysAreSecure(t *testing.T) {
	// These are the keys that decide how much of the tree is inspected, or how
	// much of the report is kept. None may be honoured from a discovered config.
	wantSecure := []string{
		"max_files", "max_findings", "memory_limit_mb", "max_file_size_mb",
	}
	found := map[string]bool{}
	for _, f := range configFields {
		if f.label == "max_file_size_mb" || f.label == "max_files" ||
			f.label == "max_findings" || f.label == "memory_limit_mb" {
			found[f.label] = true
			if !f.secure {
				t.Errorf("config field %q reduces coverage but is not secure", f.label)
			}
		}
	}
	for _, label := range wantSecure {
		if !found[label] {
			t.Errorf("config field %q is missing from the trust table", label)
		}
	}
}

// A discovered config must not be able to print raw credentials. The key used to
// parse successfully and then be silently discarded, so a user who set it saw
// hashed values and no explanation.
func TestDangerouslyShowSecretsIsSecure(t *testing.T) {
	fc := &config.FileConfig{DangerouslyShowSecrets: true}
	var buf bytes.Buffer
	c := engine.Config{}
	ignored := applyConfigValues(&c, fc, t.TempDir(), map[string]bool{}, false, &buf)

	if c.DangerouslyShowSecrets {
		t.Error("a discovered config enabled raw secret output")
	}
	if !slices.Contains(ignored, "dangerously_show_secrets") {
		t.Errorf("the key was not reported as ignored: %v", ignored)
	}

	// An explicitly named --config is the user acting deliberately.
	c2 := engine.Config{}
	var buf2 bytes.Buffer
	applyConfigValues(&c2, fc, t.TempDir(), map[string]bool{}, true, &buf2)
	if !c2.DangerouslyShowSecrets {
		t.Error("an explicit --config should be able to enable raw secret output")
	}
}
