package report

import (
	"strings"

	"minesweep/findings"
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
//
// The C1 range (U+0080-U+009F) is escaped as well. Those code points are the
// 8-bit spelling of the same controls: U+009B is CSI, U+009D is OSC, U+0090 is
// DCS, U+0098 is SOS, U+009E is PM and U+009F is APC, so a terminal that
// accepts them accepts the same payload that an ESC would have carried. They
// also pass through a UTF-8 decoder untouched, which means neutralising only
// the 7-bit form left the injection intact. U+0085 (NEL) and the line/paragraph
// separators U+2028/U+2029 are escaped for the same reason a raw newline would
// be: they break the report into forged lines without needing any escape
// sequence at all.
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
			b.WriteByte(byte(r) + '@') //nolint:gosec // G115: guarded by r < 0x20
		case r >= 0x80 && r <= 0x9f:
			// U+0085 would otherwise act as a line break; render the C1 range
			// as caret notation with a visible marker so it cannot be confused
			// with a rendering artefact.
			b.WriteString("^[")
			b.WriteByte(byte(r) - 0x40)
		case r == 0x2028:
			b.WriteString(`\u2028`)
		case r == 0x2029:
			b.WriteString(`\u2029`)
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}

func needsEscape(r rune) bool {
	switch {
	case r == 0x2028 || r == 0x2029:
		return true
	case r == 0x7f:
		return true
	case r < 0x20:
		return r != '\n' && r != '\t'
	default:
		return r >= 0x80 && r <= 0x9f
	}
}

// SanitizeLine neutralises a value that must occupy exactly one line.
//
// SanitizeTerminal deliberately preserves \n and \t, because a context block
// genuinely needs them. That is wrong for a single field: a file name containing
// a newline, a git author name, or a commit summary carrying a line break can
// forge whole report blocks, and those strings come from the repository and from
// git metadata rather than from the scanner.
//
// Newlines, carriage returns and tabs become visible escapes, and every other
// control character is handled as SanitizeTerminal does. A path or a commit
// subject remains legible.
func SanitizeLine(s string) string {
	if !strings.ContainsFunc(s, needsLineEscape) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteString(SanitizeTerminal(string(r)))
		}
	}
	return b.String()
}

func needsLineEscape(r rune) bool {
	switch r {
	case '\n', '\r', '\t':
		return true
	default:
		return needsEscape(r)
	}
}

// CensorFinding returns a copy of f with its secret value replaced by a stable
// token, and with secrets removed from the evidence printed alongside it.
//
// Evidence is censored even when f.Value is already a token. A token proves
// only that the value field was censored; it says nothing about what the
// surrounding lines still hold, so returning early here used to disable all
// censoring of the snippet whenever the value happened to look like a token.
func CensorFinding(f findings.Finding) findings.Finding {
	// The raw value is the one secret we know for certain is in this finding's
	// evidence, so censor with it before replacing the field itself. Replacing
	// first and censoring afterwards would leave the evidence holding a value
	// that no longer exists anywhere in the finding.
	own := f.Value
	if own != "" && !findings.IsCensoredToken(own) {
		f.Value = findings.SecretToken(own)
	}
	// The engine has already censored its own known secrets out of the evidence
	// (see engine.detect), but CensorReport is also the entry point for library
	// callers that never went through the engine, so run it again here rather
	// than assume. Both passes are idempotent.
	secrets := []string{own}
	f.SourceLine = findings.CensorEvidence(f.SourceLine, secrets)
	f.Context = findings.CensorEvidence(f.Context, secrets)
	return f
}

// CensorReport returns a copy of rep with every finding censored. Reports are
// censored once, at the output boundary, so no output format can be the one
// that forgets.
func CensorReport(rep *findings.RiskReport) *findings.RiskReport {
	if rep == nil {
		return nil
	}
	out := *rep
	if len(rep.Findings) > 0 {
		out.Findings = make([]findings.Finding, len(rep.Findings))
		for i, f := range rep.Findings {
			out.Findings[i] = CensorFinding(f)
		}
	}
	return &out
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

// highlightIfEnabled applies syntax highlighting only when colour has been
// resolved on for this writer.
//
// The requested --color mode is not the answer: with the default "auto" and
// output redirected to a file or a CI log, HighlightSyntax still emitted its
// raw ANSI codes while every other colour in the report was correctly
// suppressed, leaving escape bytes in the file that a later `cat` would
// interpret as control sequences.
func highlightIfEnabled(p palette, line, fileType string) string {
	if !p.enabled {
		return line
	}
	return HighlightSyntax(line, fileType)
}
