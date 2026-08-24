package policy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"minesweep/findings"
)

type PolicyRule struct {
	Tags        []string        `yaml:"tags"`
	Action      findings.Action `yaml:"action"`
	Reason      string          `yaml:"reason,omitempty"`
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
	if err := ValidateRules(pf.Policies); err != nil {
		return nil, fmt.Errorf("policy %q: %w", path, err)
	}
	return pf.Policies, nil
}

// LoadPolicyFileFS loads a policy from any fs.FS source (disk or embedded).
func LoadPolicyFileFS(fsys fs.FS, name string) ([]PolicyRule, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", name, err)
	}
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policy %q: %w", name, err)
	}
	if err := ValidateRules(pf.Policies); err != nil {
		return nil, fmt.Errorf("policy %q: %w", name, err)
	}
	return pf.Policies, nil
}

// ValidateRules rejects rules whose action or min_severity is not a known
// value. Without this, a typo such as "action: blok" flows through the whole
// pipeline producing unlabeled findings and confusing exit codes.
func ValidateRules(rules []PolicyRule) error {
	for i, r := range rules {
		switch r.Action {
		case findings.ActionAllow, findings.ActionWarn, findings.ActionRedact, findings.ActionBlock:
		default:
			return fmt.Errorf("rule %d (%s): invalid action %q (valid: allow, warn, redact, block)", i+1, strings.Join(r.Tags, ","), r.Action)
		}
		if r.MinSeverity != "" && !findings.IsValidSeverity(r.MinSeverity) {
			return fmt.Errorf("rule %d (%s): invalid min_severity %q (valid: info, low, medium, high, critical)", i+1, strings.Join(r.Tags, ","), r.MinSeverity)
		}
	}
	return nil
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

// LoadProfileFS loads a profile (by file name with or without extension)
// from any fs.FS source.
func LoadProfileFS(fsys fs.FS, name string) (Profile, error) {
	candidates := []string{name + ".yml", name + ".yaml"}
	if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
		candidates = []string{name}
	}
	for _, c := range candidates {
		if _, err := fs.Stat(fsys, c); err == nil {
			data, err := fs.ReadFile(fsys, c)
			if err != nil {
				return Profile{}, fmt.Errorf("read profile %q: %w", c, err)
			}
			var p Profile
			if err := yaml.Unmarshal(data, &p); err != nil {
				return Profile{}, fmt.Errorf("parse profile %q: %w", c, err)
			}
			return p, nil
		}
	}
	// Neither candidate exists — produce an error mentioning the primary name.
	return Profile{}, fmt.Errorf("read profile %q: not found", name+".yml")
}

func LoadProfileByName(profilesDir, name string) (Profile, error) {
	path := filepath.Join(profilesDir, name+".yml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = filepath.Join(profilesDir, name+".yaml")
	}
	return LoadProfile(path)
}

func ResolveProfile(profilesDir, name string) ([]PolicyRule, error) {
	return ResolveProfileFS(os.DirFS(profilesDir), name)
}

func ResolveProfileFS(profilesFS fs.FS, name string) ([]PolicyRule, error) {
	return resolveProfileWithSeenFS(profilesFS, name, map[string]bool{})
}

func resolveProfileWithSeenFS(profilesFS fs.FS, name string, seen map[string]bool) ([]PolicyRule, error) {
	if seen[name] {
		return nil, fmt.Errorf("profile cycle detected: %q already in resolution chain", name)
	}
	seen[name] = true

	p, err := LoadProfileFS(profilesFS, name)
	if err != nil {
		return nil, err
	}
	if err := ValidateRules(p.Actions); err != nil {
		return nil, fmt.Errorf("profile %q: %w", name, err)
	}
	rules := make([]PolicyRule, 0, len(p.Actions))
	rules = append(rules, p.Actions...)
	if p.Extends != "" {
		parent, err := resolveProfileWithSeenFS(profilesFS, p.Extends, seen)
		if err != nil {
			return nil, err
		}
		rules = append(rules, parent...)
	}
	return rules, nil
}
