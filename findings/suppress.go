package findings

import (
	"encoding/json"
	"os"
	"regexp"
)

// Suppression identifies findings to exclude from reports. ID is a human
// label for the entry (not matched against anything); at least one of
// RuleID, File, or Pattern should be set to actually match findings.
// Line, when > 0, additionally restricts a File match to that line.
type Suppression struct {
	ID      string `yaml:"id" json:"id"`
	RuleID  string `yaml:"rule_id" json:"rule_id"`
	File    string `yaml:"file" json:"file"`
	Line    int    `yaml:"line,omitempty" json:"line,omitempty"`
	Pattern string `yaml:"pattern" json:"pattern"`
	Reason  string `yaml:"reason" json:"reason"`
}

type SuppressionList struct {
	Version     string        `yaml:"version" json:"version"`
	Suppression []Suppression `yaml:"suppressions" json:"suppressions"`
}

func LoadSuppressions(path string) (*SuppressionList, error) {
	if path == "" {
		return &SuppressionList{Version: "1"}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &SuppressionList{Version: "1"}, nil
		}
		return nil, err
	}

	var list SuppressionList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}

	return &list, nil
}

func SaveSuppressions(path string, list *SuppressionList) error {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644) //nolint:gosec // standard permissions for CLI output
}

func FilterSuppressed(findings []Finding, suppressions *SuppressionList) []Finding {
	if suppressions == nil || len(suppressions.Suppression) == 0 {
		return findings
	}

	patterns := compilePatterns(suppressions.Suppression)
	return filterByEntries(findings, suppressions.Suppression, patterns)
}

// compilePatterns precompiles the pattern of each suppression entry.
// Invalid patterns yield nil and never match (they are ignored).
func compilePatterns(entries []Suppression) []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, len(entries))
	for i, s := range entries {
		if s.Pattern == "" {
			continue
		}
		if re, err := regexp.Compile(s.Pattern); err == nil {
			patterns[i] = re
		}
	}
	return patterns
}

// isSuppressed reports whether a finding matches an entry. A field only
// constrains the match when it is populated, so single-field entries keep
// their historical meaning (rule_id alone, file alone, or pattern alone);
// entries combining multiple fields require ALL of them to match.
func isSuppressed(f Finding, s Suppression, re *regexp.Regexp) bool {
	constrained := false

	if s.RuleID != "" {
		constrained = true
		if f.RuleID != s.RuleID {
			return false
		}
	}
	if s.File != "" {
		constrained = true
		if f.File != s.File {
			return false
		}
	}
	if s.Line > 0 {
		constrained = true
		if f.Line != s.Line {
			return false
		}
	}
	if s.Pattern != "" {
		constrained = true
		if re == nil || !(re.MatchString(f.Value) || re.MatchString(f.File)) {
			return false
		}
	}

	return constrained
}

func filterByEntries(findings []Finding, entries []Suppression, patterns []*regexp.Regexp) []Finding {
	var result []Finding
	for _, f := range findings {
		suppressed := false
		for i, s := range entries {
			if isSuppressed(f, s, patterns[i]) {
				suppressed = true
				break
			}
		}
		if !suppressed {
			result = append(result, f)
		}
	}
	return result
}
