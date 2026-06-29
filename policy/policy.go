package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"minesweep/findings"
)

type PolicyRule struct {
	Tags       []string         `yaml:"tags"`
	Action     findings.Action  `yaml:"action"`
	Reason     string           `yaml:"reason,omitempty"`
	MinSeverity string          `yaml:"min_severity,omitempty"`
}

type Profile struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Extends     string       `yaml:"extends,omitempty"`
	Actions     []PolicyRule `yaml:"actions"`
}

type PolicyFile struct {
	Policies []PolicyRule `yaml:"policies"`
}

func Evaluate(finding findings.Finding, policies []PolicyRule) findings.Action {
	for _, p := range policies {
		if !hasMatchingTag(finding, p.Tags) {
			continue
		}
		if p.MinSeverity != "" {
			minSev := findings.ParseSeverity(p.MinSeverity)
			if finding.Severity < minSev {
				continue
			}
		}
		return p.Action
	}
	return defaultAction(finding)
}

func defaultAction(f findings.Finding) findings.Action {
	switch {
	case f.Severity >= findings.SeverityCritical:
		return findings.ActionBlock
	case f.Severity >= findings.SeverityHigh:
		return findings.ActionRedact
	case f.Severity >= findings.SeverityMedium:
		return findings.ActionWarn
	default:
		return findings.ActionAllow
	}
}

func hasMatchingTag(f findings.Finding, tags []string) bool {
	for _, t := range tags {
		if t == "*" {
			return true
		}
		for _, ft := range f.Tags {
			if t == ft {
				return true
			}
		}
	}
	return false
}

func LoadPolicyFile(path string) ([]PolicyRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", path, err)
	}
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policy %q: %w", path, err)
	}
	return pf.Policies, nil
}

func LoadProfile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("read profile %q: %w", path, err)
	}
	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Profile{}, fmt.Errorf("parse profile %q: %w", path, err)
	}
	return p, nil
}

func LoadProfileByName(profilesDir, name string) (Profile, error) {
	path := filepath.Join(profilesDir, name+".yml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = filepath.Join(profilesDir, name+".yaml")
	}
	return LoadProfile(path)
}

func ResolveProfile(profilesDir, name string) ([]PolicyRule, error) {
	return resolveProfileWithSeen(profilesDir, name, map[string]bool{})
}

func resolveProfileWithSeen(profilesDir, name string, seen map[string]bool) ([]PolicyRule, error) {
	if seen[name] {
		return nil, fmt.Errorf("profile cycle detected: %q already in resolution chain", name)
	}
	seen[name] = true

	p, err := LoadProfileByName(profilesDir, name)
	if err != nil {
		return nil, err
	}
	var rules []PolicyRule
	rules = append(rules, p.Actions...)
	if p.Extends != "" {
		parent, err := resolveProfileWithSeen(profilesDir, p.Extends, seen)
		if err != nil {
			return nil, err
		}
		rules = append(rules, parent...)
	}
	return rules, nil
}
