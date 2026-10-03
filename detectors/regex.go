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
	Allowlist []*importedAllowlist `yaml:"-"`
}

type Pattern struct {
	Regex        string  `yaml:"regex"`
	Confidence   float64 `yaml:"confidence"`
	CaptureGroup int     `yaml:"capture_group,omitempty"`
	// MinEntropy, when > 0, requires the captured secret to have Shannon
	// entropy above the threshold (gitleaks-style filtering).
	MinEntropy float64 `yaml:"min_entropy,omitempty"`
	// RequireValue declares that this pattern captures a credential value, as
	// opposed to only naming the credential (a "SECRET=" style canary). Such a
	// capture is discarded when it holds source code rather than an opaque
	// token — see looksLikeCredentialValue.
	RequireValue bool `yaml:"require_value,omitempty"`
	compiled     *regexp.Regexp
	compiledErr  error
	gate         literalGate
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

type RegexDetector struct {
	rules []Rule
}

func NewRegexDetector(rulesDir string) (*RegexDetector, error) {
	var rules []Rule

	// Embedded defaults are the base signal: a partial on-disk or user rules
	// directory must extend them, not replace them wholesale — dropping a
	// file could silently remove coverage the user never asked to remove.
	// Overrides (on-disk, then user) replace rules that share an ID.
	embeddedRules, embeddedErr := loadEmbeddedRules()
	if embeddedErr != nil {
		return nil, embeddedErr
	}
	if rulesDir != "" {
		if info, statErr := os.Stat(rulesDir); statErr == nil && info.IsDir() {
			diskRules, diskErr := loadRules(rulesDir, "regex")
			if diskErr != nil {
				return nil, diskErr
			}
			rules = mergeRules(embeddedRules, diskRules)
		} else {
			rules = embeddedRules
		}
	} else {
		rules = embeddedRules
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

func loadEmbeddedRules() ([]Rule, error) {
	fsys, err := fs.Sub(minesweep.Assets, "rules")
	if err != nil {
		return nil, fmt.Errorf("embedded rules: %w", err)
	}
	rules, err := loadRulesFS(fsys, "regex")
	if err != nil {
		return nil, fmt.Errorf("load embedded rules: %w", err)
	}
	return rules, nil
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
	// Content length is not capped here. The previous 10 MB truncation
	// silently dropped everything after the 10 MB mark, so a file that was
	// merely large reported a clean result while hiding its tail — the worst
	// kind of failure for a secret scanner. Size is now bounded once, at load
	// time, by filesystem.File.MaxContentBytes (--max-file-size-mb), and a
	// file that exceeds it is recorded as unreadable rather than half-scanned.

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
			// Re-read the remaining budget per pattern rather than once per file:
			// the detectors before this one have already spent part of it.
			remaining, armed := file.RemainingFindingBudget()
			limit := 0
			if armed {
				if remaining <= 0 {
					return fResults
				}
				limit = remaining
			}
			for _, m := range pat.safeMatch(content, lowered, limit) {
				if li == nil {
					li = file.Lines()
				}
				line, col := li.LineCol(m.Start)
				if len(rule.Allowlist) > 0 &&
					suppressedByAllowlist(rule.Allowlist, file.Path, m.Value, sourceLineOf(li, line)) {
					continue
				}
				// Evidence (Context, SourceLine) is deliberately NOT built
				// here. Most findings are discarded by confidence and severity
				// filtering downstream, and the surrounding lines are the
				// largest field on a finding. The engine attaches evidence to
				// the survivors only.
				if !file.ClaimFinding() {
					return fResults
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
				})
			}
		}
	}
	return fResults
}

// sourceLineOf returns the trimmed text of a 1-based line, for allowlist
// matching that needs the line text without materializing a Finding for it.
func sourceLineOf(li *filesystem.LineIndex, line int) string {
	return strings.TrimSpace(li.LineText(line - 1))
}

func (p *Pattern) compile() error {
	if p.compiled != nil {
		return nil // Already compiled
	}
	if p.CaptureGroup < 0 {
		return fmt.Errorf("negative capture_group (%d) is not allowed", p.CaptureGroup)
	}

	re, err := regexp.Compile(p.Regex)
	if err != nil {
		return fmt.Errorf("compile pattern %q: %w", p.Regex, err)
	}
	p.compiled = re
	p.gate = extractLiteralGate(p.Regex)
	return nil
}

// isDangerousRegex has been removed. Go's regexp package uses RE2, which runs
// in linear time and space for every input, so "catastrophic backtracking"
// cannot occur; the old heuristic also rejected valid rules ((a+)+$ etc.).
// Invalid patterns such as possessive quantifiers (a++) are still caught by
// regexp.Compile itself, which fails on unsupported constructs.

// safeMatch runs a regex match. Go's regexp uses RE2 (linear time), so a
// wall-clock timeout is unnecessary and caused false negatives on large files
// when timed-out match goroutines piled up and starved later patterns.
//
// Before scanning, the pattern's necessary-literal gate is evaluated; most
// patterns require an anchor literal ("password", "AKIA", "postgres://"),
// and files lacking it skip the NFA entirely.
func (p *Pattern) safeMatch(content, lowered []byte, limit int) []matchResult {
	if p.compiled == nil {
		return nil
	}
	if p.gate != nil && !p.gate.satisfied(content, lowered) {
		return nil
	}

	// Cap matches to avoid pathological memory use on large files with
	// repetitive content that generates millions of submatches.
	//
	// The file's remaining budget is a second, tighter bound. Without it a
	// pattern still allocated a matchResult (with a copy of the matched bytes)
	// for every hit before ClaimFinding was ever consulted, so an exhausted
	// budget stopped the output but not the work.
	n := maxMatchesPerPattern
	if limit > 0 && limit < n {
		n = limit
	}
	matches := p.compiled.FindAllSubmatchIndex(content, n)
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
		if p.RequireValue && !judgeCapturedValue(string(value), g > 0) {
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
			// A typo'd severity is a silent downgrade in policy terms; make
			// it visible while still defaulting to info at scan time.
			if !findings.IsValidSeverity(fileRules[i].Severity) {
				fmt.Fprintf(os.Stderr, "minesweep: warning: rule %q (%s) has invalid severity %q, treating as info\n",
					fileRules[i].ID, entry.Name(), fileRules[i].Severity)
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
