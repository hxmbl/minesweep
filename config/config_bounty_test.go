package config

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// H3: a config file discovered by walking up from the scan target belongs to
// whatever is being scanned, or to an unrelated project, or to a parent
// directory. Strict parsing let any of them abort every scan beneath it with a
// hard error.
func TestLoadFileIsStrict(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.yml")
	if err := os.WriteFile(p, []byte("fail_onn: high\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(p); err == nil {
		t.Fatal("an explicitly named config with an unknown key must be an error")
	} else if !strings.Contains(err.Error(), "fail_onn") {
		t.Fatalf("error should name the key, got: %v", err)
	}
}

func TestLoadFileLaxIgnoresUnknownKeys(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.yml")
	if err := os.WriteFile(p, []byte("fail_onn: high\nworkers: 4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var unknown []string
	cfg, err := LoadFileLax(p, func(k string) { unknown = append(unknown, k) })
	if err != nil {
		t.Fatalf("a discovered config with an unknown key must not abort the scan: %v", err)
	}
	if cfg.Workers != 4 {
		t.Errorf("known keys must still apply; workers = %d", cfg.Workers)
	}
	sort.Strings(unknown)
	if len(unknown) != 1 || unknown[0] != "fail_onn" {
		t.Errorf("unknown = %v, want [fail_onn]", unknown)
	}
}

// Malformed YAML is unreadable input, not merely unfamiliar input, and must
// still fail: silently ignoring it would apply defaults the user did not ask
// for.
func TestLoadFileLaxStillRejectsMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.yml")
	if err := os.WriteFile(p, []byte("workers: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileLax(p, func(string) {}); err == nil {
		t.Fatal("malformed YAML must still be an error")
	}
}

// A type mismatch on a known key must be reported, not silently zeroed.
func TestLoadFileLaxRejectsTypeMismatch(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.yml")
	if err := os.WriteFile(p, []byte("workers: \"not-a-number\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileLax(p, func(string) {}); err == nil {
		t.Fatal("a type mismatch on a known key must be an error")
	}
}

// The permissive loader must still accept a fully valid file.
func TestLoadFileLaxAcceptsValidFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.yml")
	body := "profile: developer\nfail_on: high\nworkers: 2\ntags: [aws]\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFileLax(p, func(k string) { t.Errorf("valid file reported unknown key %q", k) })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != "developer" || cfg.FailOn != "high" || cfg.Workers != 2 || len(cfg.Tags) != 1 {
		t.Fatalf("valid config not parsed: %+v", cfg)
	}
}

// A missing file is not an error for either loader; FindAndLoad reports "no
// config" by returning nil.
func TestFindAndLoadNoConfig(t *testing.T) {
	cfg, path, err := FindAndLoadLax(t.TempDir(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if cfg != nil || path != "" {
		t.Fatalf("expected no config, got %+v at %q", cfg, path)
	}
}
