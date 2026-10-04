package findings

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Suppression identifies findings to exclude from reports. ID is a human
// label for the entry (not matched against anything); at least one of
// RuleID, File, or Pattern should be set to actually match findings.
// Line, when > 0, additionally restricts a File match to that line.
// Suppression identifies findings to exclude from reports. ID is a human
// label for the entry (not matched against anything); at least one of
// RuleID, File, Tags, or Pattern should be set to actually match findings.
// Line, when > 0, additionally restricts a File match to that line.
//
// The user's only noise escape hatch used to be per-finding baseline
// acceptance, which spends a finding from a budget that does not grow and
// records no reason. For a class of finding that recurs by construction — every
// keyword-context match in a documentation file, every pinned digest in a
// lockfile — that is the wrong granularity: each occurrence costs a separate
// decision and a separate baseline entry, and none of them stops the next one.
//
// So a suppression may name a class rather than an instance:
//
//	{rule_id: env-password}          every finding from one rule
//	{tags: [database]}               every finding carrying a tag
//	{file: "**/*.md"}                every finding under matching paths
//	{rule_id: env-password, file: "docs/**"}   the intersection
//
// File accepts a glob. A value with no wildcard keeps its historical exact-match
// meaning, so an existing suppression file behaves identically.
type Suppression struct {
	ID      string   `yaml:"id" json:"id"`
	RuleID  string   `yaml:"rule_id" json:"rule_id"`
	File    string   `yaml:"file" json:"file"`
	Tags    []string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Line    int      `yaml:"line,omitempty" json:"line,omitempty"`
	Pattern string   `yaml:"pattern" json:"pattern"`
	Reason  string   `yaml:"reason" json:"reason"`
}

type SuppressionList struct {
	Version     string        `yaml:"version" json:"version"`
	Suppression []Suppression `yaml:"suppressions" json:"suppressions"`
}

func LoadSuppressions(path string) (*SuppressionList, error) {
	if path == "" {
		return &SuppressionList{Version: "1"}, nil
	}

	data, err := os.ReadFile(path) //nolint:gosec // reading the --suppress file the caller named
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
	return os.WriteFile(path, data, 0644) //nolint:gosec // standard permissions for CLI output
}

func FilterSuppressed(findings []Finding, suppressions *SuppressionList) []Finding {
	if suppressions == nil || len(suppressions.Suppression) == 0 {
		return findings
	}

	patterns := compilePatterns(suppressions.Suppression)
	return filterByEntries(findings, suppressions.Suppression, patterns)
}

// compilePatterns precompiles the pattern of each suppression entry.
// Invalid patterns yield nil and never match (they are ignored).
func compilePatterns(entries []Suppression) []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, len(entries))
	for i, s := range entries {
		if s.Pattern == "" {
			continue
		}
		if re, err := regexp.Compile(s.Pattern); err == nil {
			patterns[i] = re
		}
	}
	return patterns
}

// isSuppressed reports whether a finding matches an entry. A field only
// constrains the match when it is populated, so single-field entries keep
// their historical meaning (rule_id alone, file alone, or pattern alone);
// entries combining multiple fields require ALL of them to match.
func isSuppressed(f Finding, s Suppression, re *regexp.Regexp) bool {
	constrained := false

	if s.RuleID != "" {
		constrained = true
		if f.RuleID != s.RuleID {
			return false
		}
	}
	if s.File != "" {
		constrained = true
		// Normalize both sides so a suppression recorded against the
		// working-tree path also matches a history-mode finding whose path
		// carries an "@sha12" suffix.
		if !suppressionPathMatches(s.File, normalizeBaselineFile(f.File)) {
			return false
		}
	}
	if len(s.Tags) > 0 {
		constrained = true
		if !hasAnySuppressionTag(f.Tags, s.Tags) {
			return false
		}
	}
	if s.Line > 0 {
		constrained = true
		if f.Line != s.Line {
			return false
		}
	}
	if s.Pattern != "" {
		constrained = true
		if re == nil ||
			(!re.MatchString(f.Value) && !re.MatchString(normalizeBaselineFile(f.File))) {
			return false
		}
	}

	return constrained
}

func hasAnySuppressionTag(findingTags, want []string) bool {
	for _, w := range want {
		for _, ft := range findingTags {
			if ft == w {
				return true
			}
		}
	}
	return false
}

// hasGlobMeta reports whether p contains a wildcard, and therefore needs glob
// matching rather than the historical exact comparison.
func hasGlobMeta(p string) bool {
	return strings.ContainsAny(p, "*?[")
}

// suppressionPathMatches reports whether a File field matches a finding path.
//
// A pattern without a wildcard is compared exactly. That is the historical
// behaviour and it is preserved unchanged, so an existing suppression file means
// exactly what it meant before globs existed — including that `README.md` does
// not match `docs/README.md`.
//
// A pattern with a wildcard is matched as a glob, and `**` crosses directory
// separators. Go's path.Match does not support `**`, and a suppression language
// that cannot say "every markdown file" is missing the most common case by a
// wide margin.
//
// A wildcard pattern with no separator is also matched against the base name,
// because path.Match will not let `*` cross a separator and `*.md` is what
// everyone actually writes. Without that, `*.md` would silently match nothing —
// the worst possible failure for a suppression, which reports success by saying
// nothing.
func suppressionPathMatches(pattern, target string) bool {
	pattern = filepath.ToSlash(pattern)
	target = filepath.ToSlash(target)

	if !hasGlobMeta(pattern) {
		return pattern == target
	}
	if matchGlobPath(pattern, target) {
		return true
	}
	if !strings.Contains(pattern, "/") {
		if ok, err := path.Match(pattern, path.Base(target)); err == nil && ok {
			return true
		}
	}
	return false
}

// matchGlobPath matches a slash-separated path against a glob, treating a `**`
// segment as zero or more path segments.
func matchGlobPath(pattern, target string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(target, "/"))
}

func matchSegments(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// `**` absorbs zero or more segments.
			if len(pat) == 1 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if matchSegments(pat[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], name[0])
		if err != nil || !ok {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}

func filterByEntries(findings []Finding, entries []Suppression, patterns []*regexp.Regexp) []Finding {
	var result []Finding
	for _, f := range findings {
		suppressed := false
		for i, s := range entries {
			if isSuppressed(f, s, patterns[i]) {
				suppressed = true
				break
			}
		}
		if !suppressed {
			result = append(result, f)
		}
	}
	return result
}
