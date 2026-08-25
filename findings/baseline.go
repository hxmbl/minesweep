package findings

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// historyDisplaySuffix matches the "@sha12" suffix history mode appends to
// file paths. Baselines must be namespace-agnostic: a working-tree baseline
// entry has to match the same secret discovered through --history.
var historyDisplaySuffix = regexp.MustCompile(`@[0-9a-f]{12}$`)

func normalizeBaselineFile(file string) string {
	return historyDisplaySuffix.ReplaceAllString(file, "")
}

type Baseline struct {
	Version  string            `json:"version"`
	Findings map[string]string `json:"findings"`
}

type BaselineEntry struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	RuleID string `json:"rule_id"`
	Value  string `json:"value,omitempty"`
}

func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{
				Version:  "1",
				Findings: make(map[string]string),
			}, nil
		}
		return nil, fmt.Errorf("read baseline file: %w", err)
	}

	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline file: %w", err)
	}

	if b.Findings == nil {
		b.Findings = make(map[string]string)
	}
	return &b, nil
}

func SaveBaseline(path string, b *Baseline) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	return os.WriteFile(path, data, 0644) //nolint:gosec // standard permissions for CLI output
}

func FindingHash(f Finding) string {
	entry := BaselineEntry{
		File:   normalizeBaselineFile(f.File),
		Line:   f.Line,
		RuleID: f.RuleID,
		Value:  f.Value,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}

func FilterNewFindings(findings []Finding, baseline *Baseline) []Finding {
	if baseline == nil {
		return findings
	}

	var newFindings []Finding
	for _, f := range findings {
		hash := FindingHash(f)
		if _, exists := baseline.Findings[hash]; !exists {
			newFindings = append(newFindings, f)
		}
	}
	return newFindings
}

func UpdateBaseline(baseline *Baseline, findings []Finding) {
	if baseline.Findings == nil {
		baseline.Findings = make(map[string]string)
	}
	for _, f := range findings {
		hash := FindingHash(f)
		baseline.Findings[hash] = fmt.Sprintf("%s:%d", normalizeBaselineFile(f.File), f.Line)
	}
}

func GetBaselineStats(baseline *Baseline) (total int, files []string) {
	if baseline == nil {
		return 0, nil
	}

	fileSet := make(map[string]bool)
	for _, loc := range baseline.Findings {
		parts := splitLocation(loc)
		if len(parts) > 0 {
			fileSet[parts[0]] = true
		}
	}

	for f := range fileSet {
		files = append(files, f)
	}
	sort.Strings(files)
	return len(baseline.Findings), files
}

func splitLocation(s string) []string {
	// Split on the last colon to handle Windows paths (e.g. C:\path\file:123).
	// The stored format is always "file:line" where line is numeric.
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+1:]}
}
