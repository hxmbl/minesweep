package report

import (
	"regexp"
	"sort"
	"strings"
)

// SanitizeTerminal neutralizes terminal control sequences embedded in
// attacker-influenced strings (file paths, secret values, context lines,
// git author names, commit summaries). Escape sequence injection can set
// window titles, clear screens, or overlay fake UI while a user reads
// a scan report.
//
// ESC is rendered visibly as \e; other C0 controls except \n and \t are
// rendered in caret notation. Newlines/tabs are preserved because report
// layout depends on them.
func SanitizeTerminal(s string) string {
	if !strings.ContainsFunc(s, needsEscape) {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))

	for _, r := range s {
		switch {
		case r == 0x1b:
			b.WriteString(`\e`)
		case r == 0x7f:
			b.WriteString("^?")
		case r < 0x20 && r != '\n' && r != '\t':
			b.WriteByte('^')
			b.WriteByte(byte(r) + '@')
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}

func needsEscape(r rune) bool {
	return (r >= 0 && r < 0x20 && r != '\n' && r != '\t') || r == 0x7f
}

// CensorValue replaces every occurrence of a sensitive value in a source
// line with a shortened, visibly censored version.
func CensorValue(line, value string) string {
	if line == "" || value == "" {
		return line
	}

	return strings.ReplaceAll(line, value, censoredValue(value))
}

func censoredValue(value string) string {
	switch {
	case len(value) > 8:
		return value[:8] + ".._[CENSORED]"
	case len(value) > 4:
		return value[:4] + ".._[CENSORED]"
	default:
		return value[:2] + ".._[CENSORED]"
	}
}

// censorAllValues censors the primary finding value and other values that
// strongly resemble credentials or secrets. It is intentionally conservative
// about what it considers secret-like: snippets are opt-in, but ordinary code
// should still remain readable.
func censorAllValues(line, primaryValue string) string {
	if line == "" {
		return line
	}

	result := CensorValue(line, primaryValue)
	return censorSecretSubstrings(result)

}

// secretCandidate matches contiguous credential-like tokens. Requiring a
// substantial alphanumeric component prevents ordinary punctuation-heavy
// source such as URLs and paths from becoming one giant candidate.
var secretCandidate = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9_.:/=-]{7,}[A-Za-z0-9]`)

// censorSecretSubstrings finds and censors secret-like tokens without treating
// an entire URL/path as a secret merely because it contains punctuation.
func censorSecretSubstrings(line string) string {
	matches := secretCandidate.FindAllStringIndex(line, -1)
	if len(matches) == 0 {
		return line
	}

	type candidate struct {
		start int
		end   int
		value string
	}

	candidates := make([]candidate, 0, len(matches))
	for _, match := range matches {
		value := line[match[0]:match[1]]

		if strings.Contains(value, "[CENSORED]") || !looksLikeSecret(value) {
			continue
		}

		candidates = append(candidates, candidate{
			start: match[0],
			end:   match[1],
			value: value,
		})
	}

	if len(candidates) == 0 {
		return line
	}

	// Process right-to-left so replacing one candidate does not invalidate
	// offsets for candidates that appear earlier in the original string.
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].start > candidates[j].start
	})

	result := line
	for _, candidate := range candidates {
		if candidate.end > len(result) {
			continue
		}

		// Ignore candidates whose original span has already been changed by
		// an overlapping replacement.
		if result[candidate.start:candidate.end] != candidate.value {
			continue
		}

		replacement := censoredValue(candidate.value)
		result = result[:candidate.start] + replacement + result[candidate.end:]
	}

	return result

}

// looksLikeSecret determines whether a string has characteristics commonly
// associated with credentials or other high-entropy secret material.
func looksLikeSecret(s string) bool {
	if len(s) < 8 {
		return false
	}

	hasLetters := false
	hasDigits := false
	hasSpecial := false

	for _, c := range s {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasLetters = true
		case c >= '0' && c <= '9':
			hasDigits = true
		case c == '_' || c == '-' || c == '.' || c == '/' || c == '=' || c == ':':
			hasSpecial = true
		}
	}

	// A candidate should contain at least two different character classes.
	mixCount := 0
	if hasLetters {
		mixCount++
	}
	if hasDigits {
		mixCount++
	}
	if hasSpecial {
		mixCount++
	}

	if mixCount < 2 {
		return false
	}

	// Use unique-character ratio as a cheap approximation of randomness.
	// This is deliberately not called "entropy": it is only a heuristic.
	uniqueChars := make(map[rune]struct{}, len(s))
	for _, c := range s {
		uniqueChars[c] = struct{}{}
	}

	ratio := float64(len(uniqueChars)) / float64(len([]rune(s)))
	return ratio > 0.6

}

// HighlightSyntax applies basic syntax highlighting to a code line based on
// common patterns. It returns a string with ANSI color codes for different
// token types.
//
// This is intentionally lightweight rather than a full language parser.
func HighlightSyntax(line, fileType string) string {
	if line == "" {
		return line
	}

	var result strings.Builder
	i := 0

keywordLoop:
	for i < len(line) {
		// Skip whitespace.
		if line[i] == ' ' || line[i] == '\t' {
			result.WriteByte(line[i])
			i++
			continue
		}

		// Check for comments.
		if i+1 < len(line) && line[i:i+2] == "//" {
			result.WriteString("\033[36m")
			result.WriteString(line[i:])
			result.WriteString("\033[0m")
			break
		}

		// Check for shell-style comments.
		if line[i] == '#' {
			result.WriteString("\033[36m")
			result.WriteString(line[i:])
			result.WriteString("\033[0m")
			break
		}

		// Check for strings.
		if line[i] == '"' || line[i] == '\'' {
			quote := line[i]

			result.WriteString("\033[33m")
			result.WriteByte(quote)
			i++

			for i < len(line) && line[i] != quote {
				if line[i] == '\\' && i+1 < len(line) {
					result.WriteByte(line[i])
					i++
					result.WriteByte(line[i])
					i++
					continue
				}

				result.WriteByte(line[i])
				i++
			}

			if i < len(line) {
				result.WriteByte(quote)
				i++
			}

			result.WriteString("\033[0m")
			continue
		}

		// Check for common keywords.
		remaining := line[i:]
		keywords := []string{
			"export",
			"const",
			"var",
			"func",
			"if",
			"else",
			"return",
			"import",
			"package",
			"true",
			"false",
			"nil",
		}

		for _, kw := range keywords {
			if strings.HasPrefix(remaining, kw) {
				if len(remaining) == len(kw) || !isWordChar(remaining[len(kw)]) {
					result.WriteString("\033[35m")
					result.WriteString(kw)
					result.WriteString("\033[0m")
					i += len(kw)
					continue keywordLoop
				}
			}
		}

		result.WriteByte(line[i])
		i++
	}

	return result.String()

}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '_'
}
