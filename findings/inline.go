package findings

import (
	"regexp"
	"strings"
)

// inlineIgnoreRe is the only recognised inline suppression form.
//
// It used to have a sibling that accepted a bare `# noqa`, `# nosec` or
// `# noscan` anywhere in the line. Those markers belong to other tools, they
// are written for entirely different purposes — a linter suppression, not a
// decision to leak a credential — and they are honoured from the content being
// scanned, which means the thing under examination gets to decide whether it is
// examined. A single `# noqa` above a line silenced a critical AWS key in every
// scan mode, including `--diff` on an untrusted pull request and `--staged` in
// the pre-commit hook.
//
// An inline suppression is now explicit about wanting minesweep specifically,
// and optional rule IDs can be attached: `minesweep: ignore` or
// `minesweep: ignore(aws-access-key-id, env-password)`.
var inlineIgnoreRe = regexp.MustCompile(`(?i)(?:#|//)\s*minesweep\s*:\s*ignore(?:\s*\(([^)]*)\))?\s*$`)

type InlineSuppression struct {
	RuleIDs []string
	Reason  string
}

func ParseInlineSuppression(line string) *InlineSuppression {
	matches := inlineIgnoreRe.FindStringSubmatch(line)
	if matches != nil {
		s := &InlineSuppression{Reason: "inline ignore"}
		if len(matches) > 1 && strings.TrimSpace(matches[1]) != "" {
			s.RuleIDs = parseRuleIDs(matches[1])
		}
		return s
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
// isSuppressedAt walks back up to three lines looking for a suppression that
// covers f, matching the original window.
//
// A suppression naming rule IDs is matched case-insensitively: rule IDs come
// from user-authored YAML, where `AWS-Access-Key-Id` and `aws-access-key-id`
// are the same rule, and a case-sensitive comparison silently failed to
// suppress — a suppression that appears not to work invites a second, cruder
// one.
func isSuppressedAt(f Finding, n int, suppressAt func(int) *InlineSuppression) bool {
	target := strings.ToLower(strings.TrimSpace(f.RuleID))
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
			if strings.EqualFold(ruleID, target) {
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
