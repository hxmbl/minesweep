package findings

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindingHash(t *testing.T) {
	f := Finding{
		Type:   "AWS Access Key ID",
		File:   ".env",
		Line:   5,
		Value:  "AKIAIOSFODNN7EXAMPLE",
		RuleID: "aws-access-key",
	}

	h1 := FindingHash(f)
	h2 := FindingHash(f)

	if h1 != h2 {
		t.Errorf("expected same hash for same finding, got %s and %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("expected SHA-256 hash (64 hex chars), got %d chars", len(h1))
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
		Findings: make(map[string]string),
	}
	f1 := Finding{Type: "AWS", File: ".env", Line: 5, Value: "key1", RuleID: "aws-key"}
	f2 := Finding{Type: "GCP", File: "config.yml", Line: 10, Value: "key2", RuleID: "gcp-key"}

	h1 := FindingHash(f1)
	h2 := FindingHash(f2)
	b.Findings[h1] = ".env:5"
	b.Findings[h2] = "config.yml:10"

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
		Findings: make(map[string]string),
	}

	all := []Finding{
		{Type: "AWS", File: ".env", Line: 5, Value: "old_key", RuleID: "aws-key"},
		{Type: "GCP", File: "config.yml", Line: 10, Value: "new_key", RuleID: "gcp-key"},
	}

	existing.Findings[FindingHash(all[0])] = ".env:5"

	newFindings := FilterNewFindings(all, existing)

	if len(newFindings) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(newFindings))
	}
	if newFindings[0].Value != "new_key" {
		t.Errorf("expected new_key, got %s", newFindings[0].Value)
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
		Findings: make(map[string]string),
	}

	f1 := Finding{Type: "AWS", File: ".env", Line: 5, Value: "old_key", RuleID: "aws-key"}
	b.Findings[FindingHash(f1)] = ".env:5"

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
		Findings: map[string]string{
			"hash1": ".env:5",
			"hash2": "config.yml:10",
			"hash3": ".env:20",
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
