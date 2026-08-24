package detectors

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"minesweep/filesystem"
	"minesweep/findings"

	"minesweep"
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
	// Allowlist holds gitleaks-style post-match suppression semantics for
	// imported rules. Native rules use file_filter and inline ignores.
	Allowlist *importedAllowlist `yaml:"-"`
}

type Pattern struct {
	Regex        string  `yaml:"regex"`
	Confidence   float64 `yaml:"confidence"`
	CaptureGroup int     `yaml:"capture_group,omitempty"`
	// MinEntropy, when > 0, requires the captured secret to have Shannon
	// entropy above the threshold (gitleaks-style filtering).
	MinEntropy  float64 `yaml:"min_entropy,omitempty"`
	compiled    *regexp.Regexp
	compiledErr error
	gate        literalGate
}

type FileFilter struct {
	Include []string `yaml:"include,omitempty"`
	Exclude []string `yaml:"exclude,omitempty"`
}

type matchResult struct {
	Value string
	Start int
	End   int
}

// Maximum length of content to match against (to prevent memory exhaustion)
const maxMatchLength = 10 * 1024 * 1024 // 10MB

type RegexDetector struct {
	rules []Rule
}

func NewRegexDetector(rulesDir string) (*RegexDetector, error) {
	var (
		rules []Rule
		err   error
	)
	if rulesDir != "" {
		if info, statErr := os.Stat(rulesDir); statErr == nil && info.IsDir() {
			rules, err = loadRules(rulesDir, "regex")
			if err != nil {
				return nil, err
			}
		} else {
			// No on-disk rules directory: fall back to the embedded defaults.
			fsys, subErr := fs.Sub(minesweep.Assets, "rules")
			if subErr != nil {
				return nil, subErr
			}
			rules, err = loadRulesFS(fsys, "regex")
			if err != nil {
				return nil, fmt.Errorf("load embedded rules: %w", err)
			}
		}
	}

	userRulesDir := getUserRulesDir()
	if userRulesDir != "" {
		userRules, uErr := loadRules(userRulesDir, "regex")
		if uErr != nil {
			fmt.Fprintf(os.Stderr, "minesweep: warning: ignoring user rules dir %q: %v\n", userRulesDir, uErr)
		} else {
			rules = mergeRules(rules, userRules)
		}
	}

	return &RegexDetector{rules: rules}, nil
}

func (d *RegexDetector) Name() string {
	return "regex"
}

// Rules returns the loaded rule definitions, including any merged user rules.
func (d *RegexDetector) Rules() []Rule {
	return d.rules
}

func (d *RegexDetector) Detect(file *filesystem.File) []findings.Finding {
	if file.IsBinary {
		return nil
	}

	var fResults []findings.Finding

	content, err := file.GetContent()
	if err != nil {
		return nil
	}
	lowered := file.LoweredContent()
	if len(content) > maxMatchLength {
		content = content[:maxMatchLength]
		if len(lowered) > maxMatchLength {
			lowered = lowered[:maxMatchLength]
		}
	}

	base := filepath.Base(file.Path)
	var li *filesystem.LineIndex
	for _, rule := range d.rules {
		if !matchesFileFilter(rule.FileFilter, base) {
			continue
		}
		for _, pat := range rule.Patterns {
			if pat.compiledErr != nil || pat.compiled == nil {
				continue
			}
			for _, m := range pat.safeMatch(content, lowered) {
				if li == nil {
					li = file.Lines()
				}
				line, col := li.LineCol(m.Start)
				sourceLine := strings.TrimSpace(li.LineText(line - 1))
				if rule.Allowlist != nil &&
					suppressedByAllowlist(rule.Allowlist, file.Path, m.Value, sourceLine) {
					continue
				}
				tags := make([]string, len(rule.Tags))
				copy(tags, rule.Tags)
				fResults = append(fResults, findings.Finding{
					Type:       rule.Name,
					Severity:   findings.ParseSeverity(rule.Severity),
					Confidence: pat.Confidence,
					File:       file.Path,
					Line:       line,
					Column:     col,
					Value:      m.Value,
					Reason:     rule.Description,
					RuleID:     rule.ID,
					Tags:       tags,
					Context:    li.Context(line-1, 2),
					SourceLine: sourceLine,
				})
			}
		}
	}
	return fResults
}

func (p *Pattern) compile() error {
	if p.compiled != nil {
		return nil // Already compiled
	}
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
	p.gate = extractLiteralGate(p.Regex)
	return nil
}

// isDangerousRegex checks for patterns that are known to cause ReDoS
func isDangerousRegex(pattern string) bool {
	// Patterns that can cause catastrophic backtracking:
	// 1. Nested quantifiers like (a+)+ or (a*)*a
	// 2. Overlapping alternations with quantifiers
	// 3. Multiple adjacent quantifiers

	dangerousPatterns := []string{
		`\(\s*[^)]+\s*\+\s*\)\s*\+`, // (a+)+
		`\(\s*[^)]+\s*\*\s*\)\s*\*`, // (a*)*
		`\(\s*[^)]+\s*\+\s*\)\s*\{`, // (a+){n,m}
		`\(\s*[^)]+\s*\*\s*\)\s*\+`, // (a*)+
		`\+\s*\+`,                   // ++
		`\*\s*\*`,                   // **
		`\?\s*\+`,                   // ?+
		`\+\s*\?`,                   // +?
		`\*\s*\+`,                   // *+
		`\+\s*\*`,                   // +*
	}

	for _, dangerous := range dangerousPatterns {
		if matched, _ := regexp.MatchString(dangerous, pattern); matched {
			return true
		}
	}

	// Check for excessive quantifier nesting.
	// Count the depth of nested groups/character classes, ignoring escaped
	// characters and quantifier braces (e.g. {2,3}), which otherwise inflate
	// the depth for perfectly sane patterns like AKIA[0-9A-Z]{16}.
	depth := 0
	maxDepth := 0
	escaped := false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if escaped {
			escaped = false
			continue
		}
		switch c {
		case '\\':
			escaped = true
		case '(', '[':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case ')', ']':
			depth--
		}
	}

	// If we have deeply nested patterns with quantifiers, flag as potentially dangerous
	if maxDepth > 5 {
		return true
	}

	return false
}

// safeMatch runs a regex match. Go's regexp uses RE2 (linear time), so a
// wall-clock timeout is unnecessary and caused false negatives on large files
// when timed-out match goroutines piled up and starved later patterns.
//
// Before scanning, the pattern's necessary-literal gate is evaluated; most
// patterns require an anchor literal ("password", "AKIA", "postgres://"),
// and files lacking it skip the NFA entirely.
func (p *Pattern) safeMatch(content, lowered []byte) []matchResult {
	if p.compiled == nil {
		return nil
	}
	if p.gate != nil && !p.gate.satisfied(content, lowered) {
		return nil
	}

	// Cap matches to avoid pathological memory use on large files with
	// repetitive content that generates millions of submatches.
	matches := p.compiled.FindAllSubmatchIndex(content, maxMatchesPerPattern)
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
		value := content[start:end]
		if p.MinEntropy > 0 && shannonEntropyBytes(value) < p.MinEntropy {
			continue
		}
		results = append(results, matchResult{
			Value: string(value),
			Start: start,
			End:   end,
		})
	}
	return results
}

func loadRules(rulesDir, ruleType string) ([]Rule, error) {
	return loadRulesFS(os.DirFS(rulesDir), ruleType)
}

func loadRulesFS(rulesFS fs.FS, ruleType string) ([]Rule, error) {
	entries, err := fs.ReadDir(rulesFS, ".")
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	var allRules []Rule
	var loadErrs []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yml" && ext != ".yaml" && ext != ".toml" {
			continue
		}
		data, err := fs.ReadFile(rulesFS, entry.Name())
		if err != nil {
			loadErrs = append(loadErrs, fmt.Sprintf("read %q: %v", entry.Name(), err))
			continue
		}

		var fileRules []Rule
		switch ext {
		case ".toml":
			fileRules, err = LoadGitleaksRules(data, entry.Name())
			if err != nil {
				loadErrs = append(loadErrs, fmt.Sprintf("parse %q: %v", entry.Name(), err))
				continue
			}
		default:
			var rf RuleFile
			if err := yaml.Unmarshal(data, &rf); err != nil {
				loadErrs = append(loadErrs, fmt.Sprintf("parse %q: %v", entry.Name(), err))
				continue
			}
			fileRules = rf.Rules
		}

		for i := range fileRules {
			if fileRules[i].Type != "regex" {
				continue
			}
			failed := 0
			for j := range fileRules[i].Patterns {
				if err := fileRules[i].Patterns[j].compile(); err != nil {
					// Warn loudly: a silently skipped pattern is silently
					// missing coverage.
					failed++
					fmt.Fprintf(os.Stderr, "minesweep: warning: rule %q (%s): skipping pattern %d: %v\n",
						fileRules[i].ID, entry.Name(), j+1, err)
				}
			}
			if failed > 0 && failed == len(fileRules[i].Patterns) {
				fmt.Fprintf(os.Stderr, "minesweep: warning: rule %q is disabled (all patterns failed to compile)\n", fileRules[i].ID)
				continue
			}
			allRules = append(allRules, fileRules[i])
		}
	}
	if len(loadErrs) > 0 {
		fmt.Fprintf(os.Stderr, "minesweep: warning: %d rule file(s) had errors and were skipped\n", len(loadErrs))
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

func matchesFileFilter(f *FileFilter, base string) bool {
	if f == nil {
		return true
	}
	if len(f.Exclude) > 0 {
		for _, pattern := range f.Exclude {
			match, err := filepath.Match(pattern, base)
			if err != nil {
				fmt.Fprintf(os.Stderr, "minesweep: warning: invalid file filter pattern %q: %v\n", pattern, err)
				continue
			}
			if match {
				return false
			}
		}
	}
	if len(f.Include) > 0 {
		for _, pattern := range f.Include {
			match, err := filepath.Match(pattern, base)
			if err != nil {
				fmt.Fprintf(os.Stderr, "minesweep: warning: invalid file filter pattern %q: %v\n", pattern, err)
				continue
			}
			if match {
				return true
			}
		}
		return false
	}
	return true
}
