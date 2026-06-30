package detectors

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"

	"minesweep/filesystem"
	"minesweep/findings"
)

type RuleFile struct {
	Rules []Rule `yaml:"rules"`
}

type Rule struct {
	ID          string      `yaml:"id"`
	Type        string      `yaml:"type"`
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Severity    string      `yaml:"severity"`
	Tags        []string    `yaml:"tags"`
	Patterns    []Pattern   `yaml:"patterns,omitempty"`
	FileFilter  *FileFilter `yaml:"file_filter,omitempty"`
}

type Pattern struct {
	Regex        string  `yaml:"regex"`
	Confidence   float64 `yaml:"confidence"`
	CaptureGroup int     `yaml:"capture_group,omitempty"`
	compiled     *regexp.Regexp
}

type FileFilter struct {
	Include []string `yaml:"include,omitempty"`
	Exclude []string `yaml:"exclude,omitempty"`
}

type matchResult struct {
	Value  string
	Start  int
	End    int
	Line   int
	Column int
}

type RegexDetector struct {
	rules []Rule
}

func NewRegexDetector(rulesDir string) (*RegexDetector, error) {
	rules, err := loadRules(rulesDir, "regex")
	if err != nil {
		return nil, err
	}
	return &RegexDetector{rules: rules}, nil
}

func (d *RegexDetector) Name() string {
	return "regex"
}

func (d *RegexDetector) Detect(file *filesystem.File) []findings.Finding {
	var fResults []findings.Finding
	for _, rule := range d.rules {
		if !matchesFileFilter(rule.FileFilter, file.Path) {
			continue
		}
		for _, pat := range rule.Patterns {
			matches := pat.match(file.Content)
			for _, m := range matches {
				tags := make([]string, len(rule.Tags))
				copy(tags, rule.Tags)
				fResults = append(fResults, findings.Finding{
					Type:       rule.Name,
					Severity:   findings.ParseSeverity(rule.Severity),
					Confidence: pat.Confidence,
					File:       file.Path,
					Line:       m.Line,
					Column:     m.Column,
					Value:      m.Value,
					Reason:     rule.Description,
					RuleID:     rule.ID,
					Tags:       tags,
				})
			}
		}
	}
	return fResults
}

func (p *Pattern) compile() error {
	if p.CaptureGroup < 0 {
		return fmt.Errorf("negative capture_group (%d) is not allowed", p.CaptureGroup)
	}
	re, err := regexp.Compile(p.Regex)
	if err != nil {
		return fmt.Errorf("compile pattern %q: %w", p.Regex, err)
	}
	p.compiled = re
	return nil
}

func (p *Pattern) match(content []byte) []matchResult {
	if p.compiled == nil {
		return nil
	}
	matches := p.compiled.FindAllSubmatchIndex(content, -1)
	if matches == nil {
		return nil
	}
	var results []matchResult
	for _, m := range matches {
		g := p.CaptureGroup * 2
		if g >= len(m) {
			g = 0
		}
		start := m[g]
		end := m[g+1]
		if start == -1 || end == -1 {
			continue
		}
		results = append(results, matchResult{
			Value:  string(content[start:end]),
			Start:  start,
			End:    end,
			Line:   lineNumber(content, start),
			Column: columnNumber(content, start),
		})
	}
	return results
}

func loadRules(rulesDir, ruleType string) ([]Rule, error) {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir %q: %w", rulesDir, err)
	}
	var allRules []Rule
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".yml" && filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join(rulesDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read rule file %q: %w", path, err)
		}
		var rf RuleFile
		if err := yaml.Unmarshal(data, &rf); err != nil {
			return nil, fmt.Errorf("parse rule file %q: %w", path, err)
		}
		for i := range rf.Rules {
			if rf.Rules[i].Type != ruleType {
				continue
			}
			for j := range rf.Rules[i].Patterns {
				if err := rf.Rules[i].Patterns[j].compile(); err != nil {
					return nil, fmt.Errorf("compile pattern in %q: %w", path, err)
				}
			}
			allRules = append(allRules, rf.Rules[i])
		}
	}
	return allRules, nil
}

func matchesFileFilter(f *FileFilter, path string) bool {
	if f == nil {
		return true
	}
	if len(f.Exclude) > 0 {
		for _, pattern := range f.Exclude {
			match, err := filepath.Match(pattern, filepath.Base(path))
			if err == nil && match {
				return false
			}
		}
	}
	if len(f.Include) > 0 {
		for _, pattern := range f.Include {
			match, err := filepath.Match(pattern, filepath.Base(path))
			if err == nil && match {
				return true
			}
		}
		return false
	}
	return true
}

func lineNumber(content []byte, pos int) int {
	line := 1
	for i := 0; i < pos && i < len(content); i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

func columnNumber(content []byte, pos int) int {
	col := 1
	for i := pos - 1; i >= 0 && content[i] != '\n'; i-- {
		col++
	}
	return col
}
