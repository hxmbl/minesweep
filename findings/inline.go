package findings

import (
	"regexp"
	"strings"
)

var inlineIgnoreRe = regexp.MustCompile(`(?i)(?:minesweep|secret(?:s)?)\s*:\s*ignore(?:\s*\(([^)]+)\))?`)
var inlineIgnoreAltRe = regexp.MustCompile(`(?i)(?:nosec|noscan|noqa)\s*(?:\([^)]*\))?\s*$`)

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

func FilterInlineSuppressions(findings []Finding, fileContent string) []Finding {
	if len(findings) == 0 {
		return findings
	}

	lines := strings.Split(fileContent, "\n")
	lineSuppressions := make(map[int]*InlineSuppression)

	for i, line := range lines {
		if sp := ParseInlineSuppression(line); sp != nil {
			lineSuppressions[i+1] = sp
		}
	}

	var result []Finding
	for _, f := range findings {
		if isInlineSuppressed(f, lines, lineSuppressions) {
			continue
		}
		result = append(result, f)
	}

	return result
}

func isInlineSuppressed(f Finding, lines []string, suppressions map[int]*InlineSuppression) bool {
	targetLine := f.Line
	if targetLine <= 0 || targetLine > len(lines) {
		return false
	}

	for checkLine := targetLine; checkLine >= 1 && checkLine >= targetLine-3; checkLine-- {
		if sp, ok := suppressions[checkLine]; ok {
			if sp.RuleIDs == nil {
				return true
			}
			for _, ruleID := range sp.RuleIDs {
				if ruleID == f.RuleID {
					return true
				}
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
