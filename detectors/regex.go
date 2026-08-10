package detectors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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
	compiledErr  error
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

// Regex timeout for matching operations to prevent ReDoS
const regexTimeout = 100 * time.Millisecond

// Maximum length of content to match against (to prevent memory exhaustion)
const maxMatchLength = 10 * 1024 * 1024 // 10MB

type RegexDetector struct {
	rules []Rule
}

func NewRegexDetector(rulesDir string) (*RegexDetector, error) {
	rules, err := loadRules(rulesDir, "regex")
	if err != nil {
		return nil, err
	}

	userRulesDir := getUserRulesDir()
	if userRulesDir != "" {
		if userRules, err := loadRules(userRulesDir, "regex"); err == nil {
			rules = mergeRules(rules, userRules)
		}
	}

	return &RegexDetector{rules: rules}, nil
}

func (d *RegexDetector) Name() string {
	return "regex"
}

func (d *RegexDetector) Detect(file *filesystem.File) []findings.Finding {
	if file.IsBinary {
		return nil
	}

	var fResults []findings.Finding
	
	// Limit content length for regex matching to prevent memory issues
	content := file.Content
	if len(content) > maxMatchLength {
		content = content[:maxMatchLength]
	}
	
	lines := strings.Split(string(content), "\n")
	for _, rule := range d.rules {
		if !matchesFileFilter(rule.FileFilter, file.Path) {
			continue
		}
		for _, pat := range rule.Patterns {
			// Check if pattern compilation failed (invalid regex)
			if pat.compiledErr != nil {
				continue
			}
			if pat.compiled == nil {
				continue
			}
			
			// Use safe matching with timeout
			matches := pat.safeMatch(content)
			for _, m := range matches {
				tags := make([]string, len(rule.Tags))
				copy(tags, rule.Tags)
				context := extractContext(lines, m.Line-1, 2)
				sourceLine := ""
				if m.Line-1 >= 0 && m.Line-1 < len(lines) {
					sourceLine = strings.TrimSpace(lines[m.Line-1])
				}
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
					Context:    context,
					SourceLine: sourceLine,
				})
			}
		}
	}
	return fResults
}

func extractContext(lines []string, center, radius int) string {
	start := center - radius
	if start < 0 {
		start = 0
	}
	end := center + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	var sb strings.Builder
	for i := start; i < end; i++ {
		prefix := "  "
		if i == center {
			prefix = "> "
		}
		sb.WriteString(prefix)
		sb.WriteString(strings.TrimSpace(lines[i]))
		sb.WriteString("\n")
	}
	return sb.String()
}

func (p *Pattern) compile() error {
	if p.CaptureGroup < 0 {
		return fmt.Errorf("negative capture_group (%d) is not allowed", p.CaptureGroup)
	}
	
	// Check for potentially dangerous regex patterns that could cause ReDoS
	if isDangerousRegex(p.Regex) {
		return fmt.Errorf("regex pattern %q appears to be vulnerable to ReDoS (catastrophic backtracking)", p.Regex)
	}
	
	re, err := regexp.Compile(p.Regex)
	if err != nil {
		return fmt.Errorf("compile pattern %q: %w", p.Regex, err)
	}
	p.compiled = re
	return nil
}

// isDangerousRegex checks for patterns that are known to cause ReDoS
func isDangerousRegex(pattern string) bool {
	// Patterns that can cause catastrophic backtracking:
	// 1. Nested quantifiers like (a+)+ or (a*)*a
	// 2. Overlapping alternations with quantifiers
	// 3. Multiple adjacent quantifiers
	
	dangerousPatterns := []string{
		`\(\s*[^)]+\s*\+\s*\)\s*\+`,  // (a+)+ 
		`\(\s*[^)]+\s*\*\s*\)\s*\*`,  // (a*)*
		`\(\s*[^)]+\s*\+\s*\)\s*\{`,  // (a+){n,m}
		`\(\s*[^)]+\s*\*\s*\)\s*\+`,  // (a*)+
		`\+\s*\+`,                    // ++
		`\*\s*\*`,                    // **
		`\?\s*\+`,                    // ?+
		`\+\s*\?`,                    // +?
		`\*\s*\+`,                    // *+
		`\+\s*\*`,                    // +*
	}
	
	for _, dangerous := range dangerousPatterns {
		if matched, _ := regexp.MatchString(dangerous, pattern); matched {
			return true
		}
	}
	
	// Check for excessive quantifier nesting
	// Count the depth of nested quantifiers
	depth := 0
	maxDepth := 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '(', '[', '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case ')', ']', '}':
			depth--
		}
	}
	
	// If we have deeply nested patterns with quantifiers, flag as potentially dangerous
	if maxDepth > 5 {
		return true
	}
	
	return false
}

// safeMatch performs regex matching with timeout protection
func (p *Pattern) safeMatch(content []byte) []matchResult {
	if p.compiled == nil {
		return nil
	}
	
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), regexTimeout)
	defer cancel()
	
	// Channel to receive results or timeout
	resultCh := make(chan []matchResult, 1)
	
	go func() {
		matches := p.compiled.FindAllSubmatchIndex(content, -1)
		if matches == nil {
			resultCh <- nil
			return
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
		resultCh <- results
	}()
	
	select {
	case results := <-resultCh:
		return results
	case <-ctx.Done():
		// Timeout occurred - log and return empty
		// In production, you might want to return an error or partial results
		return nil
	}
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
					// Log the error but don't fail - just skip this pattern
					rf.Rules[i].Patterns[j].compiledErr = err
				}
			}
			allRules = append(allRules, rf.Rules[i])
		}
	}
	return allRules, nil
}

func getUserRulesDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		configDir = filepath.Join(home, ".config")
	}

	rulesDir := filepath.Join(configDir, "minesweep", "rules")
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		return ""
	}
	return rulesDir
}

func mergeRules(defaultRules, userRules []Rule) []Rule {
	userIDs := make(map[string]bool)
	for _, r := range userRules {
		userIDs[r.ID] = true
	}

	var merged []Rule
	for _, r := range defaultRules {
		if !userIDs[r.ID] {
			merged = append(merged, r)
		}
	}
	merged = append(merged, userRules...)
	return merged
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
