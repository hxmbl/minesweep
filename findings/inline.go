package findings

import (
	"regexp"
	"strings"
)

var inlineIgnoreRe = regexp.MustCompile(`(?i)(?:#|//)\s*(?:minesweep|secret(?:s)?)\s*:\s*ignore(?:\s*\(([^)]+)\))?`)
var inlineIgnoreAltRe = regexp.MustCompile(`(?i)(?:#|//)\s*(?:nosec|noscan|noqa)\s*(?:\([^)]*\))?\s*$`)

type InlineSuppression struct {
	RuleIDs []string
	Reason  string
}

func ParseInlineSuppression(line string) *InlineSuppression {
	matches := inlineIgnoreRe.FindStringSubmatch(line)
	if matches != nil {
		s := &InlineSuppression{Reason: "inline ignore"}
		if len(matches) > 1 && matches[1] != "" {
			s.RuleIDs = parseRuleIDs(matches[1])
		}
		return s
	}

	if inlineIgnoreAltRe.MatchString(line) {
		return &InlineSuppression{Reason: "inline ignore (nosec)"}
	}

	return nil
}

// LineLookup is the minimum a file's line index must provide to evaluate
// inline suppressions. It exists so this package stays free of an import
// cycle with filesystem.
type LineLookup interface {
	LineCount() int
	LineText(idx int) string
}

// FilterInlineSuppressionsLines applies inline suppressions using a line
// index instead of a []string.
//
// The previous implementation split the whole file into lines — copying every
// byte and allocating a string header per line — and then ran the suppression
// regex over every one of them, even for a file with a single finding. Only
// the finding's own line and the three above it can ever suppress it, so this
// version looks at at most four lines per finding and memoizes the result.
func FilterInlineSuppressionsLines(findings []Finding, lines LineLookup) []Finding {
	if len(findings) == 0 || lines == nil {
		return findings
	}
	n := lines.LineCount()

	// Sparse memo: only the lines that were actually consulted are cached.
	suppression := make(map[int]*InlineSuppression)
	cached := make(map[int]*InlineSuppression)
	suppressAt := func(line int) *InlineSuppression {
		if sp, ok := cached[line]; ok {
			return sp
		}
		sp := ParseInlineSuppression(lines.LineText(line - 1))
		cached[line] = sp
		if sp != nil {
			suppression[line] = sp
		}
		return sp
	}

	result := make([]Finding, 0, len(findings))
	for _, f := range findings {
		target := f.Line
		if target <= 0 || target > n {
			result = append(result, f)
			continue
		}
		if isSuppressedAt(f, n, suppressAt) {
			continue
		}
		result = append(result, f)
	}
	return result
}

// isSuppressedAt walks back up to three lines looking for a suppression that
// covers f, matching the original window.
func isSuppressedAt(f Finding, n int, suppressAt func(int) *InlineSuppression) bool {
	for check := f.Line; check >= 1 && check >= f.Line-3; check-- {
		if check > n {
			continue
		}
		sp := suppressAt(check)
		if sp == nil {
			continue
		}
		if sp.RuleIDs == nil {
			return true
		}
		for _, ruleID := range sp.RuleIDs {
			if ruleID == f.RuleID {
				return true
			}
		}
	}
	return false
}

func parseRuleIDs(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
