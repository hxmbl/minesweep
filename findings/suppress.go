package findings

import (
	"encoding/json"
	"os"
	"regexp"
)

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
	return os.WriteFile(path, data, 0644)
}

func FilterSuppressed(findings []Finding, suppressions *SuppressionList) []Finding {
	if suppressions == nil || len(suppressions.Suppression) == 0 {
		return findings
	}

	var result []Finding
	for _, f := range findings {
		if !isSuppressed(f, suppressions) {
			result = append(result, f)
		}
	}
	return result
}

func isSuppressed(f Finding, suppressions *SuppressionList) bool {
	for _, s := range suppressions.Suppression {
		if s.ID != "" && f.File == s.ID {
			return true
		}
		if s.RuleID != "" && f.RuleID == s.RuleID {
			return true
		}
		if s.File != "" && f.File == s.File {
			return true
		}
		if s.Pattern != "" {
			if matched, _ := regexp.MatchString(s.Pattern, f.Value); matched {
				return true
			}
			if matched, _ := regexp.MatchString(s.Pattern, f.File); matched {
				return true
			}
		}
	}
	return false
}
