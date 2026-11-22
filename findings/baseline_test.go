package findings

import (
	"encoding/json"
	fx "minesweep/internal/fixtures"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindingHash(t *testing.T) {
	f := Finding{
		Type:   "AWS Access Key ID",
		File:   ".env",
		Line:   5,
		Value:  fx.AWSAccessKeyID(),
		RuleID: "aws-access-key",
	}

	h1 := FindingHash(f)
	h2 := FindingHash(f)

	if h1 != h2 {
		t.Errorf("expected same hash for same finding, got %s and %s", h1, h2)
	}
	if !strings.HasPrefix(h1, "b3:") || len(strings.TrimPrefix(h1, "b3:")) != 64 {
		t.Errorf("expected BLAKE3 fingerprint (b3: plus 64 hex chars), got %q", h1)
	}
}

func TestFindingHashDifferentValues(t *testing.T) {
	f1 := Finding{Type: "AWS", File: ".env", Line: 5, Value: "key1", RuleID: "aws-key"}
	f2 := Finding{Type: "AWS", File: ".env", Line: 5, Value: "key2", RuleID: "aws-key"}

	if FindingHash(f1) == FindingHash(f2) {
		t.Error("expected different hashes for different values")
	}
}

func TestFindingHashDifferentTypes(t *testing.T) {
	f1 := Finding{Type: "AWS", File: ".env", Line: 5, Value: "key", RuleID: "aws-key"}
	f2 := Finding{Type: "GCP", File: ".env", Line: 5, Value: "key", RuleID: "gcp-key"}

	if FindingHash(f1) == FindingHash(f2) {
		t.Error("expected different hashes for different rule IDs")
	}
}

func TestSaveLoadBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	b := &Baseline{
		Version:  "1",
		Findings: make(map[string]BaselineEntry),
	}
	f1 := Finding{Type: "AWS", File: ".env", Line: 5, Value: "key1", RuleID: "aws-key"}
	f2 := Finding{Type: "GCP", File: "config.yml", Line: 10, Value: "key2", RuleID: "gcp-key"}

	h1 := FindingHash(f1)
	h2 := FindingHash(f2)
	b.Findings[h1] = BaselineEntry{File: ".env", Line: 5}
	b.Findings[h2] = BaselineEntry{File: "config.yml", Line: 10}

	if err := SaveBaseline(path, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("baseline file not created")
	}

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(loaded.Findings) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(loaded.Findings))
	}

	if _, ok := loaded.Findings[h1]; !ok {
		t.Errorf("expected hash %s in baseline", h1)
	}
	if _, ok := loaded.Findings[h2]; !ok {
		t.Errorf("expected hash %s in baseline", h2)
	}
}

func TestLoadBaselineMissingFile(t *testing.T) {
	loaded, err := LoadBaseline("/nonexistent/path/baseline.json")
	if err != nil {
		t.Fatalf("LoadBaseline should return empty baseline for missing file, got error: %v", err)
	}
	if len(loaded.Findings) != 0 {
		t.Errorf("expected empty findings, got %d entries", len(loaded.Findings))
	}
}

func TestFilterNewFindings(t *testing.T) {
	existing := &Baseline{
		Version:  "1",
		Findings: make(map[string]BaselineEntry),
	}

	all := []Finding{
		{Type: "AWS", File: ".env", Line: 5, Value: "old_key", RuleID: "aws-key"},
		{Type: "GCP", File: "config.yml", Line: 10, Value: "new_key", RuleID: "gcp-key"},
	}

	existing.Findings[FindingHash(all[0])] = BaselineEntry{File: ".env", Line: 5}

	newFindings := FilterNewFindings(all, existing)

	if len(newFindings) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(newFindings))
	}
	if newFindings[0].Value != "new_key" {
		t.Errorf("expected new_key, got %s", newFindings[0].Value)
	}
}

func TestFilterNewFindingsLegacySHA256Baseline(t *testing.T) {
	finding := Finding{Type: "AWS", File: ".env", Line: 5, Value: "old_key", RuleID: "aws-key"}
	baseline := &Baseline{Version: "1", Findings: map[string]BaselineEntry{legacyFindingHash(finding): {File: ".env", Line: 5}}}

	if got := FilterNewFindings([]Finding{finding}, baseline); len(got) != 0 {
		t.Fatalf("legacy SHA-256 baseline entry did not filter finding: %+v", got)
	}
}

func TestFilterNewFindingsEmptyBaseline(t *testing.T) {
	all := []Finding{
		{Type: "AWS", File: ".env", Line: 5, Value: "key1", RuleID: "aws-key"},
		{Type: "GCP", File: "config.yml", Line: 10, Value: "key2", RuleID: "gcp-key"},
	}

	newFindings := FilterNewFindings(all, nil)

	if len(newFindings) != 2 {
		t.Fatalf("expected 2 new findings with nil baseline, got %d", len(newFindings))
	}
}

func TestUpdateBaseline(t *testing.T) {
	b := &Baseline{
		Version:  "1",
		Findings: make(map[string]BaselineEntry),
	}

	f1 := Finding{Type: "AWS", File: ".env", Line: 5, Value: "old_key", RuleID: "aws-key"}
	b.Findings[FindingHash(f1)] = BaselineEntry{File: ".env", Line: 5}

	newFindings := []Finding{
		{Type: "GCP", File: "config.yml", Line: 10, Value: "new_key", RuleID: "gcp-key"},
	}

	UpdateBaseline(b, newFindings)

	if len(b.Findings) != 2 {
		t.Fatalf("expected 2 hashes after update, got %d", len(b.Findings))
	}
}

func TestGetBaselineStats(t *testing.T) {
	b := &Baseline{
		Version: "1",
		Findings: map[string]BaselineEntry{
			"hash1": {File: ".env", Line: 5},
			"hash2": {File: "config.yml", Line: 10},
			"hash3": {File: ".env", Line: 20},
		},
	}

	total, files := GetBaselineStats(b)
	if total != 3 {
		t.Errorf("expected 3 total, got %d", total)
	}
	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d", len(files))
	}
}

func TestGetBaselineStatsNil(t *testing.T) {
	total, files := GetBaselineStats(nil)
	if total != 0 {
		t.Errorf("expected 0 total, got %d", total)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestUpdateBaselineNeverWritesRawSecrets(t *testing.T) {
	secret := fx.AWSAccessKeyID()
	f := Finding{Type: "AWS", File: ".env", Line: 5, Value: secret, RuleID: "aws-access-key-id"}
	b := &Baseline{Version: "1", Findings: make(map[string]BaselineEntry)}
	UpdateBaseline(b, []Finding{f})

	entry := b.Findings[FindingHash(f)]
	if entry.ValueToken == "" {
		t.Fatal("value-bearing finding was baselined without recording its value token")
	}

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := SaveBaseline(path, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved baseline: %v", err)
	}
	if strings.Contains(string(data), secret) {
		t.Fatalf("baseline file contains the raw secret: %s", data)
	}

	changed := f
	changed.Value = secret + "-different"
	if FindingHash(changed) == FindingHash(f) {
		t.Fatal("fingerprint does not bind the secret value")
	}
}

func TestBaselineProvenanceSurvivesRegeneration(t *testing.T) {
	f := Finding{Type: "AWS", File: ".env", Line: 5, Value: "key1", RuleID: "aws-key"}
	hash := FindingHash(f)
	b := &Baseline{
		Version: "1",
		Findings: map[string]BaselineEntry{
			hash: {File: ".env", Line: 5, RuleID: "aws-key", Reason: "accepted by Alice", Author: "alice", Date: "2026-11-22"},
		},
	}
	UpdateBaseline(b, []Finding{f})

	got := b.Findings[hash]
	if got.Reason != "accepted by Alice" || got.Author != "alice" || got.Date != "2026-11-22" {
		t.Fatalf("provenance lost on regeneration: %+v", got)
	}

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := SaveBaseline(path, b); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved baseline: %v", err)
	}
	for _, want := range []string{"accepted by Alice", "alice", "2026-11-22"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("saved baseline missing %q: %s", want, data)
		}
	}
}

func TestBaselineWarningsForValueLessEntriesOnly(t *testing.T) {
	valueLess := Finding{Type: "binary", File: "blob.bin", Line: 1, RuleID: "binary-rule"}
	b := &Baseline{
		Version: "1",
		Findings: map[string]BaselineEntry{
			FindingHash(valueLess): {File: "blob.bin", Line: 1, RuleID: "binary-rule"},
		},
	}
	if got := BaselineWarnings(b); len(got) != 1 || !strings.Contains(got[0], "binary-rule") {
		t.Fatalf("expected one value-less warning, got %v", got)
	}

	withValue := Finding{Type: "AWS", File: ".env", Line: 5, Value: "key1", RuleID: "aws-key"}
	UpdateBaseline(b, []Finding{withValue})
	if got := BaselineWarnings(b); len(got) != 1 {
		t.Fatalf("value-bearing entry must not warn, got %v", got)
	}

	// Old baselines recorded no value token but bound the value into a
	// SHA-256 fingerprint; loading one must not warn about every entry.
	var legacy Baseline
	if err := json.Unmarshal([]byte(`{"version":"1","findings":{"deadbeef":".env:5"}}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy baseline: %v", err)
	}
	if got := BaselineWarnings(&legacy); len(got) != 0 {
		t.Fatalf("legacy baseline should not warn, got %v", got)
	}
}

func TestValueLessBaselineEntrySuppressesChangedValue(t *testing.T) {
	f := Finding{Type: "binary", File: "blob.bin", Line: 1, Value: "old", RuleID: "binary-rule"}
	b := &Baseline{
		Version: "1",
		Findings: map[string]BaselineEntry{
			FindingHash(f): {File: "blob.bin", Line: 1, RuleID: "binary-rule"},
		},
	}
	changed := f
	changed.Value = "brand new content"
	if got := FilterNewFindings([]Finding{changed}, b); len(got) != 0 {
		t.Fatalf("value-less entry should suppress the rule at that path, got %+v", got)
	}
	otherLine := changed
	otherLine.Line = 2
	if got := FilterNewFindings([]Finding{otherLine}, b); len(got) != 1 {
		t.Fatalf("value-less entry must not suppress other lines, got %+v", got)
	}
}

func TestPruneBaselineRemovesOnlyStaleEntries(t *testing.T) {
	keep := Finding{Type: "AWS", File: ".env", Line: 5, Value: "key1", RuleID: "aws-key"}
	stale := Finding{Type: "AWS", File: "gone.env", Line: 9, Value: "key2", RuleID: "aws-key"}
	b := &Baseline{
		Version: "1",
		Findings: map[string]BaselineEntry{
			FindingHash(keep):  {File: ".env", Line: 5, RuleID: "aws-key", Reason: "still relevant"},
			FindingHash(stale): {File: "gone.env", Line: 9, RuleID: "aws-key", Reason: "was a test"},
		},
	}
	removed := PruneBaseline(b, []Finding{keep})
	if len(removed) != 1 || removed[0].File != "gone.env" {
		t.Fatalf("expected one stale removal, got %+v", removed)
	}
	if len(b.Findings) != 1 {
		t.Fatalf("expected one entry left, got %d", len(b.Findings))
	}
	if got := b.Findings[FindingHash(keep)].Reason; got != "still relevant" {
		t.Fatalf("matching entry was altered: %q", got)
	}
	if got := PruneReason(removed[0], []Finding{keep}); got != "file no longer has findings" {
		t.Fatalf("unexpected prune reason: %q", got)
	}

	moved := keep
	moved.Line = 8
	if got := PruneReason(BaselineEntry{File: ".env", Line: 5, RuleID: "aws-key"}, []Finding{moved}); got != "line moved" {
		t.Fatalf("unexpected line-drift reason: %q", got)
	}
	changed := keep
	changed.Value = "different"
	if got := PruneReason(BaselineEntry{File: ".env", Line: 5, RuleID: "aws-key"}, []Finding{changed}); got != "value changed" {
		t.Fatalf("unexpected value-change reason: %q", got)
	}
}
