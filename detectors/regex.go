package detectors

import (
	"bytes"
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
		// An explicit --rules is a request. Whether it names a directory or a
		// single file, a path that cannot be read has to be an error: the old
		// os.Stat/IsDir test fell through to the embedded rules, so
		// `--rules ./my-rules.yml` and `--rules ./typo.yml` both scanned
		// silently with the built-in rules only. A migrating user adding gitleaks
		// rules then got neither the rules nor any indication they were missing.
		//
		// A missing path is only an error because a non-empty rulesDir now
		// always means the user asked for it.
		info, statErr := os.Stat(rulesDir)
		switch {
		case statErr != nil:
			return nil, fmt.Errorf("rules path %q: %w", rulesDir, statErr)
		case info.IsDir():
			diskRules, diskErr := loadRules(rulesDir, "regex")
			if diskErr != nil {
				return nil, diskErr
			}
			rules = mergeRules(embeddedRules, diskRules)
		default:
			singleRules, loadErr := loadRulesFile(rulesDir, "regex")
			if loadErr != nil {
				return nil, loadErr
			}
			rules = mergeRules(embeddedRules, singleRules)
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
	rules, err := loadRulesFS(fsys, "regex", true)
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

// AddRules merges additional rules in, replacing any that share an ID. Used for
// rules discovered per scan rather than configured up front.
func (d *RegexDetector) AddRules(extra []Rule) {
	if len(extra) == 0 {
		return
	}
	d.rules = mergeRules(d.rules, extra)
}

// GitleaksConfigNames are the filenames searched for in a scanned tree, in
// priority order.
var GitleaksConfigNames = []string{".gitleaks.toml", "gitleaks.toml"}

// FindGitleaksConfig returns the path of a gitleaks config in root, or "".
//
// Search is deliberately shallow: the config belongs to the tree being scanned,
// not to some enclosing project. Only the scan root itself is consulted, so
// scanning a subdirectory of a repository does not silently adopt the
// repository's configuration, and running from an unrelated working directory
// adopts nothing.
func FindGitleaksConfig(root string) string {
	for _, name := range GitleaksConfigNames {
		p := filepath.Join(root, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
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
	// An explicitly named rules directory is a trust decision.
	return loadRulesFS(os.DirFS(rulesDir), ruleType, true)
}

// parseRules decodes one rule file and prepares its rules. The extension picks
// the format: .toml is a gitleaks config, everything else is the YAML form.
func parseRules(data []byte, name, ruleType string, honourAllowlist bool) ([]Rule, error) {
	var fileRules []Rule
	if strings.EqualFold(filepath.Ext(name), ".toml") {
		var err error
		fileRules, err = LoadGitleaksRules(data, name, honourAllowlist)
		if err != nil {
			return nil, err
		}
	} else {
		// Strict decoding: "confidnce:" or "filefilter:" would otherwise parse
		// into a zero value and produce a rule that silently never fires. The
		// severity check below already fails loudly on a bad value; an unknown
		// key deserves the same treatment.
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		var rf RuleFile
		if err := dec.Decode(&rf); err != nil {
			return nil, err
		}
		fileRules = rf.Rules
	}

	out := make([]Rule, 0, len(fileRules))
	for i := range fileRules {
		if fileRules[i].Type != ruleType {
			continue
		}
		// A typo'd severity is a silent downgrade in policy terms; make
		// it visible while still defaulting to info at scan time.
		if !findings.IsValidSeverity(fileRules[i].Severity) {
			fmt.Fprintf(os.Stderr, "minesweep: warning: rule %q (%s) has invalid severity %q, treating as info\n",
				fileRules[i].ID, name, fileRules[i].Severity)
		}
		failed := 0
		for j := range fileRules[i].Patterns {
			if fileRules[i].Patterns[j].Confidence < 0 || fileRules[i].Patterns[j].Confidence > 1 {
				fmt.Fprintf(os.Stderr,
					"minesweep: warning: rule %q (%s) pattern %d has confidence %g outside 0..1; the pattern is disabled\n",
					fileRules[i].ID, name, j+1, fileRules[i].Patterns[j].Confidence)
				fileRules[i].Patterns[j].Confidence = -1
			}
			if err := fileRules[i].Patterns[j].compile(); err != nil {
				// Warn loudly: a silently skipped pattern is silently
				// missing coverage.
				failed++
				fmt.Fprintf(os.Stderr, "minesweep: warning: rule %q (%s): skipping pattern %d: %v\n",
					fileRules[i].ID, name, j+1, err)
			}
		}
		if failed > 0 && failed == len(fileRules[i].Patterns) {
			fmt.Fprintf(os.Stderr, "minesweep: warning: rule %q is disabled (all patterns failed to compile)\n", fileRules[i].ID)
			continue
		}
		// A pattern whose confidence is out of range cannot match anything, and
		// would otherwise sit in the rule looking loaded. Drop it rather than let
		// it fail silently at scan time.
		patterns := fileRules[i].Patterns[:0]
		for _, p := range fileRules[i].Patterns {
			if p.Confidence >= 0 {
				patterns = append(patterns, p)
			}
		}
		fileRules[i].Patterns = patterns
		if len(fileRules[i].Patterns) == 0 {
			continue
		}
		out = append(out, fileRules[i])
	}
	return out, nil
}

// loadRulesFile loads a single rule file, for --rules pointing at one file
// rather than a directory.
func loadRulesFile(path, ruleType string) ([]Rule, error) {
	// G304: path is the single file the user named with --rules.
	b, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read rules file %q: %w", path, err)
	}
	rules, err := parseRules(b, filepath.Base(path), ruleType, true)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("rules file %q contains no %s rules", path, ruleType)
	}
	return rules, nil
}

func loadRulesFS(rulesFS fs.FS, ruleType string, honourAllowlist bool) ([]Rule, error) {
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

		fileRules, err := parseRules(data, entry.Name(), ruleType, honourAllowlist)
		if err != nil {
			loadErrs = append(loadErrs, fmt.Sprintf("parse %q: %v", entry.Name(), err))
			continue
		}
		allRules = append(allRules, fileRules...)
	}
	if len(loadErrs) > 0 {
		fmt.Fprintf(os.Stderr, "minesweep: warning: %d rule file(s) had errors and were skipped\n", len(loadErrs))
	}
	// Deduplicate within this source, last file wins. mergeRules only applied
	// ACROSS sources (embedded, then --rules, then the user dir), never WITHIN one
	// directory, so a rules directory could not override a rule: two files
	// defining "dup-rule" both stayed live, `explain` reported "2 rules match",
	// and a scan reported whichever pattern happened to be evaluated first. That
	// silently kills the main reason to ship a rules directory -- tuning a noisy
	// rule down.
	//
	// Last-wins, so filename ordering expresses precedence. fs.ReadDir returns
	// names sorted, which makes that ordering predictable ("10-base.yml" is
	// overridden by "20-override.yml").
	return dedupeByID(allRules), nil
}

// dedupeByID keeps the last definition of each rule ID while preserving the
// position of that ID's FIRST appearance, so the resulting order does not churn
// when a later file overrides an earlier one.
func dedupeByID(rules []Rule) []Rule {
	last := make(map[string]int, len(rules))
	for i, r := range rules {
		last[r.ID] = i
	}
	out := make([]Rule, 0, len(last))
	emitted := make(map[string]struct{}, len(last))
	for _, r := range rules {
		if _, done := emitted[r.ID]; done {
			continue
		}
		emitted[r.ID] = struct{}{}
		out = append(out, rules[last[r.ID]])
	}
	return out
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

	// G304: configDir is the user's own XDG_CONFIG_HOME or ~/.config, and
	// rulesDir is a fixed subpath of it. Nothing here comes from a scanned file.
	rulesDir := filepath.Join(configDir, "minesweep", "rules")
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) { //nolint:gosec
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
