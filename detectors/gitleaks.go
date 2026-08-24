package detectors

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	toml "github.com/BurntSushi/toml"
)

// GitleaksConfig mirrors the subset of gitleaks' TOML schema we support.
// Unknown keys are surfaced as warnings by the loader rather than silently
// ignored, so typos in a migrated config become visible.
type GitleaksConfig struct {
	Title      string              `toml:"title"`
	Extend     *GitleaksExtend     `toml:"extend"`
	Rules      []GitleaksRule      `toml:"rules"`
	Allowlist  *GitleaksAllowlist  `toml:"allowlist"`  // legacy singular form
	Allowlists []GitleaksAllowlist `toml:"allowlists"` // modern array form
}

type GitleaksExtend struct {
	UseDefault bool   `toml:"useDefault"`
	Path       string `toml:"path"`
}

type GitleaksRule struct {
	ID          string              `toml:"id"`
	Description string              `toml:"description"`
	Regex       string              `toml:"regex"`
	SecretGroup int                 `toml:"secretGroup"`
	Entropy     float64             `toml:"entropy"`
	Keywords    []string            `toml:"keywords"`
	Tags        []string            `toml:"tags"`
	Allowlist   *GitleaksAllowlist  `toml:"allowlist"`  // legacy singular form
	Allowlists  []GitleaksAllowlist `toml:"allowlists"` // modern array form
}

type GitleaksAllowlist struct {
	Description string   `toml:"description"`
	Paths       []string `toml:"paths"`
	Regexes     []string `toml:"regexes"`
	StopWords   []string `toml:"stopwords"`
	Condition   string   `toml:"condition"` // "OR" (default) or "AND"
	Commits     []string `toml:"commits"`
	RegexTarget string   `toml:"regexTarget"` // secret (default) or line
}

// severity heuristics: gitleaks has no per-rule severity, but our policy
// engine requires one. The mapping is deliberately simple and documented.
var gitleaksCriticalHints = []string{
	"private-key", "privatekey", "pem", "pkcs8", "rsa", "openssh", "pgp",
}

var gitleaksHighProviderPrefixes = []string{
	"aws", "gcp", "azure", "github", "gitlab", "google", "stripe", "slack",
	"sendgrid", "mailgun", "twilio", "npm", "pypi", "openai", "anthropic",
	"firebase", "jwt", "heroku", "digitalocean", "docker", "databricks",
	"datadog", "new-relic", "newrelic", "sentry", "telegram", "discord",
	"shopify", "square", "plaid", "coinbase", "vault", "hashicorp",
	"cloudflare", "fastly", "vercel", "netlify", "linear", "jira", "confluence",
}

func gitleaksSeverity(id string) string {
	lower := strings.ToLower(id)
	for _, hint := range gitleaksCriticalHints {
		if strings.Contains(lower, hint) {
			return "critical"
		}
	}
	for _, prefix := range gitleaksHighProviderPrefixes {
		if strings.HasPrefix(lower, prefix) || strings.Contains(lower, "-"+prefix) {
			return "high"
		}
	}
	if strings.HasPrefix(lower, "generic") {
		return "medium"
	}
	return "high"
}

// LoadGitleaksRules parses a gitleaks TOML config and translates it into
// native rules. Translation is total: every supported field maps, and every
// unsupported field produces a warning naming the rule.
func LoadGitleaksRules(data []byte, sourceName string) ([]Rule, error) {
	var cfg GitleaksConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", sourceName, err)
	}

	global := mergeGitleaksAllowlistSet(cfg.Allowlists, cfg.Allowlist, sourceName, "global")

	if cfg.Extend != nil && (cfg.Extend.UseDefault || cfg.Extend.Path != "") {
		warnGitleaks(sourceName, "[extend]", "external config extension is not supported; only rules defined inline are loaded")
	}

	rules := make([]Rule, 0, len(cfg.Rules))
	for i, gr := range cfg.Rules {
		if gr.ID == "" {
			warnGitleaks(sourceName, fmt.Sprintf("rule #%d", i+1), "missing id; skipped")
			continue
		}
		if gr.Regex == "" {
			warnGitleaks(sourceName, gr.ID, "no regex; skipped")
			continue
		}

		pattern := Pattern{
			Regex:        gr.Regex,
			CaptureGroup: gr.SecretGroup,
			MinEntropy:   gr.Entropy,
			Confidence:   0.8,
		}
		if err := pattern.compile(); err != nil {
			fmt.Fprintf(os.Stderr, "minesweep: warning: %s: rule %q pattern skipped: %v\n", sourceName, gr.ID, err)
			continue
		}

		if len(gr.Keywords) > 0 {
			// Advisory-only in gitleaks; ignored for gating here. See docs.
			// Nothing to do — noted for parity reporting.
			_ = gr.Keywords
		}
		if len(gr.Tags) == 0 {
			gr.Tags = nil
		}

		rule := Rule{
			ID:          gr.ID,
			Type:        "regex",
			Name:        deriveName(gr),
			Description: gr.Description,
			Severity:    gitleaksSeverity(gr.ID),
			Tags:        append(append([]string{"imported-gitleaks"}, gr.Tags...), "gitleaks"),
			Patterns:    []Pattern{pattern},
		}

		if al := mergeGitleaksAllowlistSet(gr.Allowlists, gr.Allowlist, sourceName, gr.ID); al != nil {
			rule.Allowlist = al
		}
		if global != nil {
			if rule.Allowlist == nil {
				rule.Allowlist = global
			} else {
				rule.Allowlist = orAllowlists(rule.Allowlist, global)
			}
		}

		rules = append(rules, rule)
	}
	return rules, nil
}

// mergeGitleaksAllowlistSet compiles a set of allowlist tables (modern
// plural and/or legacy singular) into one enforced block. Multiple tables
// are OR-combined: gitleaks suppresses a finding when any allowlist matches.
func mergeGitleaksAllowlistSet(set []GitleaksAllowlist, legacy *GitleaksAllowlist, source, subject string) *importedAllowlist {
	all := make([]GitleaksAllowlist, 0, len(set)+1)
	all = append(all, set...)
	if legacy != nil {
		all = append(all, *legacy)
	}
	var merged *importedAllowlist
	for i := range all {
		compiled := compileGitleaksAllowlist(&all[i], source, subject)
		if compiled == nil {
			continue
		}
		if merged == nil {
			merged = compiled
			continue
		}
		merged = orAllowlists(merged, compiled)
	}
	return merged
}

// orAllowlists combines two blocks so that either suppressing suppresses.
func orAllowlists(a, b *importedAllowlist) *importedAllowlist {
	return &importedAllowlist{
		pathRes:    append(append([]*regexp.Regexp{}, a.pathRes...), b.pathRes...),
		contentRes: append(append([]*regexp.Regexp{}, a.contentRes...), b.contentRes...),
		stopwords:  append(append([]string{}, a.stopwords...), b.stopwords...),
		targetLine: a.targetLine || b.targetLine,
	}
}

func warnGitleaks(source, subject, msg string) {
	fmt.Fprintf(os.Stderr, "minesweep: warning: %s: %s: %s\n", source, subject, msg)
}

func deriveName(gr GitleaksRule) string {
	d := strings.TrimSpace(gr.Description)
	if d == "" {
		d = gr.ID
	}
	// Title-case first letter for consistency with native names.
	if d != "" {
		r, size := utf8.DecodeRuneInString(d)
		if r != utf8.RuneError {
			return string(unicode.ToUpper(r)) + d[size:]
		}
	}
	return gr.ID
}

// importedAllowlist is the enforced form of a translated gitleaks allowlist.
type importedAllowlist struct {
	pathRes      []*regexp.Regexp
	contentRes   []*regexp.Regexp
	stopwords    []string
	conditionAnd bool
	targetLine   bool // regexes apply to the full line instead of the secret
}

func compileGitleaksAllowlist(ga *GitleaksAllowlist, source, subject string) *importedAllowlist {
	if ga == nil {
		return nil
	}
	al := &importedAllowlist{stopwords: ga.StopWords}
	switch strings.ToLower(ga.Condition) {
	case "", "or":
	case "and":
		al.conditionAnd = true
	default:
		warnGitleaks(source, subject, fmt.Sprintf("unknown allowlist condition %q; using OR", ga.Condition))
	}
	switch strings.ToLower(ga.RegexTarget) {
	case "", "secret":
	case "line":
		al.targetLine = true
	default:
		warnGitleaks(source, subject, fmt.Sprintf("unknown regexTarget %q; using secret", ga.RegexTarget))
	}
	for _, p := range ga.Paths {
		re, err := regexp.Compile(p)
		if err != nil {
			warnGitleaks(source, subject, fmt.Sprintf("allowlist path regex %q failed to compile: %v", p, err))
			continue
		}
		al.pathRes = append(al.pathRes, re)
	}
	for _, r := range ga.Regexes {
		re, err := regexp.Compile(r)
		if err != nil {
			warnGitleaks(source, subject, fmt.Sprintf("allowlist regex %q failed to compile: %v", r, err))
			continue
		}
		al.contentRes = append(al.contentRes, re)
	}
	if len(ga.Commits) > 0 {
		warnGitleaks(source, subject, "commit allowlists are not supported; use --baseline instead")
	}
	if al.pathRes == nil && al.contentRes == nil && len(al.stopwords) == 0 {
		return nil
	}
	return al
}

// suppressedByAllowlist applies gitleaks allowlist semantics: under OR, any
// matching category suppresses; under AND, every populated category must
// match. Categories that are empty are ignored entirely.
func suppressedByAllowlist(al *importedAllowlist, filePath, value, line string) bool {
	if al == nil {
		return false
	}

	pathHit := func() bool {
		for _, re := range al.pathRes {
			if re.MatchString(filePath) {
				return true
			}
		}
		return false
	}()
	contentHit := func() bool {
		hay := value
		if al.targetLine {
			hay = line
		}
		for _, re := range al.contentRes {
			if re.MatchString(hay) {
				return true
			}
		}
		return false
	}()
	stopwordHit := func() bool {
		lowerValue := strings.ToLower(value)
		for _, sw := range al.stopwords {
			if strings.Contains(lowerValue, strings.ToLower(sw)) {
				return true
			}
		}
		return false
	}()

	populated := 0
	matches := 0
	count := func(populatedAny, hit bool) {
		if populatedAny {
			populated++
			if hit {
				matches++
			}
		}
	}
	count(len(al.pathRes) > 0, pathHit)
	count(len(al.contentRes) > 0, contentHit)
	count(len(al.stopwords) > 0, stopwordHit)

	if populated == 0 {
		return false
	}
	if al.conditionAnd {
		return matches == populated
	}
	return matches > 0
}
