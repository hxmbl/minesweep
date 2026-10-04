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
	// BuiltIn marks a rule compiled in Go rather than loaded from a rule file.
	// Such rules have no regex to show and cannot be overridden from a rules
	// directory; `explain` reports them so their IDs are not mysterious.
	BuiltIn bool `yaml:"-"`
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
	rules = embeddedRules

	switch {
	case rulesDir == "":
		// nothing more to load
	case isDir(rulesDir):
		diskRules, diskErr := loadRules(rulesDir, "regex")
		if diskErr != nil {
			return nil, diskErr
		}
		rules = mergeRules(rules, diskRules)
	case isRegularFile(rulesDir):
		// A single rule file. `minesweep -r ~/.config/gitleaks.toml` and
		// `minesweep -r ./my-rules.yml` previously fell through to the embedded
		// rules with no diagnostic at all, so a migrating user got neither
		// their rules nor their allowlists and had no reason to suspect it.
		fileRules, loadErr := loadRulesFile(rulesDir)
		if loadErr != nil {
			return nil, fmt.Errorf("rules file %q: %w", rulesDir, loadErr)
		}
		if len(fileRules) == 0 {
			fmt.Fprintf(os.Stderr, "minesweep: warning: %q contained no regex rules\n", rulesDir)
		}
		rules = mergeRules(rules, fileRules)
	default:
		// Neither a directory nor a file at the requested path. The caller is
		// expected to have validated a path the user named explicitly; here the
		// embedded rules stand in, which is what an installed binary with no
		// local rules directory needs.
		return &RegexDetector{rules: rules}, nil
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

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// loadRulesFile loads one rule file, dispatching on its extension.
func loadRulesFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller-specified rules file
	if err != nil {
		return nil, err
	}
	name := filepath.Base(path)
	if strings.EqualFold(filepath.Ext(name), ".toml") {
		return LoadGitleaksRules(data, name)
	}
	var rf RuleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, err
	}
	return finalizeRuleFile(rf.Rules, name)
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

// BuiltInRules returns the rules provided by the compiled-in detectors, so a
// caller can present the full set of rule IDs a scan can produce.
func BuiltInRules() []Rule {
	var out []Rule
	out = append(out, NewDatabaseDetector().BuiltInRules()...)
	out = append(out, NewOAuthDetector().BuiltInRules()...)
	out = append(out,
		Rule{
			ID: "entropy-high", Type: "entropy", Name: "High Entropy String",
			Description: "A run of characters with high Shannon entropy on a line " +
				"that also reads as credential-bearing",
			Severity: findings.SeverityLow.String(),
			Tags:     []string{"entropy", "potential-secret"}, BuiltIn: true,
		},
		Rule{
			ID: "symlink-detected", Type: "symlink", Name: "Symbolic link",
			Description: "A symbolic link; one that resolves outside the scan root " +
				"is reported as such and its contents are not read",
			Severity: findings.SeverityInfo.String(),
			Tags:     []string{"symlink", "filesystem"}, BuiltIn: true,
		},
		Rule{
			ID: "binary-file-detected", Type: "filetype", Name: "Binary File",
			Description: "Content detectors do not run on binary content, so a " +
				"credential embedded in a binary file would not be reported",
			Severity: findings.SeverityInfo.String(),
			Tags:     []string{"filetype", "binary"}, BuiltIn: true,
		},
		Rule{
			ID: "executable-file-detected", Type: "filetype", Name: "Executable File",
			Description: "An executable file; worth auditing separately",
			Severity:    findings.SeverityInfo.String(),
			Tags:        []string{"filetype", "executable"}, BuiltIn: true,
		},
	)
	return out
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
			for _, m := range pat.safeMatch(content, lowered) {
				if li == nil {
					li = file.Lines()
				}
				line, col := li.LineCol(m.Start)
				if len(rule.Allowlist) > 0 &&
					suppressedByAllowlist(rule.Allowlist, file.RelPath(), m.Value, sourceLineOf(li, line)) {
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
			fileRules, err = finalizeRuleFile(rf.Rules, entry.Name())
			if err != nil {
				loadErrs = append(loadErrs, fmt.Sprintf("parse %q: %v", entry.Name(), err))
				continue
			}
		}

		allRules = append(allRules, fileRules...)
	}
	if len(loadErrs) > 0 {
		fmt.Fprintf(os.Stderr, "minesweep: warning: %d rule file(s) had errors and were skipped\n", len(loadErrs))
	}
	// Rules within one source are keyed by ID: a later file replaces an
	// earlier one, so filename ordering expresses precedence (fs.ReadDir
	// returns sorted names). Appending instead left two rules sharing an ID
	// both active with the first one always winning, so the documented
	// "override by redefining the ID" workflow was silently dead and
	// `explain` reported "2 rules match".
	return dedupeByID(allRules), nil
}

// dedupeByID keeps the last rule declared for each ID.
func dedupeByID(rules []Rule) []Rule {
	if len(rules) < 2 {
		return rules
	}
	last := make(map[string]int, len(rules))
	for i, r := range rules {
		last[r.ID] = i
	}
	out := make([]Rule, 0, len(rules))
	for i, r := range rules {
		if last[r.ID] == i {
			out = append(out, r)
		}
	}
	return out
}

// finalizeRuleFile validates and compiles the rules declared in one YAML file.
func finalizeRuleFile(rules []Rule, source string) ([]Rule, error) {
	var out []Rule
	for i := range rules {
		if rules[i].Type != "regex" {
			continue
		}
		// A typo'd severity is a silent downgrade in policy terms; make
		// it visible while still defaulting to info at scan time.
		if !findings.IsValidSeverity(rules[i].Severity) {
			fmt.Fprintf(os.Stderr, "minesweep: warning: rule %q (%s) has invalid severity %q, treating as info\n",
				rules[i].ID, source, rules[i].Severity)
		}
		if rules[i].ID == "" {
			return nil, fmt.Errorf("rule #%d has no id", i+1)
		}
		failed := 0
		for j := range rules[i].Patterns {
			if err := rules[i].Patterns[j].compile(); err != nil {
				// Warn loudly: a silently skipped pattern is silently
				// missing coverage.
				failed++
				fmt.Fprintf(os.Stderr, "minesweep: warning: rule %q (%s): skipping pattern %d: %v\n",
					rules[i].ID, source, j+1, err)
			}
		}
		if len(rules[i].Patterns) > 0 && failed == len(rules[i].Patterns) {
			fmt.Fprintf(os.Stderr, "minesweep: warning: rule %q is disabled (all patterns failed to compile)\n", rules[i].ID)
			continue
		}
		// Validate file_filter patterns once, here. matchesFileFilter runs per
		// file per rule, so an invalid pattern used to print the same warning
		// once for every file scanned.
		validateFileFilter(rules[i].ID, source, rules[i].FileFilter)
		out = append(out, rules[i])
	}
	return out, nil
}

// validateFileFilter reports malformed file_filter patterns once per rule.
func validateFileFilter(ruleID, source string, ff *FileFilter) {
	if ff == nil {
		return
	}
	for _, group := range []struct {
		name     string
		patterns []string
	}{{"include", ff.Include}, {"exclude", ff.Exclude}} {
		for _, p := range group.patterns {
			if _, err := filepath.Match(p, "probe"); err != nil {
				fmt.Fprintf(os.Stderr, "minesweep: warning: rule %q (%s): invalid file_filter.%s pattern %q: %v\n",
					ruleID, source, group.name, p, err)
			}
		}
	}
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
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) { //nolint:gosec // fixed path under the user's config dir
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

// matchesFileFilter reports whether a rule applies to a file with this base
// name.
//
// Patterns are validated at load time (see validateFileFilter), so a malformed
// pattern is warned about once per rule rather than once per file per rule; at
// scan time a malformed pattern simply does not match.
func matchesFileFilter(f *FileFilter, base string) bool {
	if f == nil {
		return true
	}
	for _, pattern := range f.Exclude {
		if match, err := filepath.Match(pattern, base); err == nil && match {
			return false
		}
	}
	if len(f.Include) > 0 {
		for _, pattern := range f.Include {
			if match, err := filepath.Match(pattern, base); err == nil && match {
				return true
			}
		}
		return false
	}
	return true
}
