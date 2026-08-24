package findings

import (
	"encoding/json"
	"os"
	"regexp"
)

// Suppression identifies findings to exclude from reports. ID is a human
// label for the entry (not matched against anything); at least one of
// RuleID, File, or Pattern should be set to actually match findings.
type Suppression struct {
	ID      string `yaml:"id" json:"id"`
	RuleID  string `yaml:"rule_id" json:"rule_id"`
	File    string `yaml:"file" json:"file"`
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

	var result []Finding
	for _, f := range findings {
		if !isSuppressed(f, suppressions.Suppression, patterns) {
			result = append(result, f)
		}
	}
	return result
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

func isSuppressed(f Finding, entries []Suppression, patterns []*regexp.Regexp) bool {
	for i, s := range entries {
		if s.RuleID != "" && f.RuleID == s.RuleID {
			return true
		}
		if s.File != "" && f.File == s.File {
			return true
		}
		if re := patterns[i]; re != nil {
			if re.MatchString(f.Value) || re.MatchString(f.File) {
				return true
			}
		}
	}
	return false
}
