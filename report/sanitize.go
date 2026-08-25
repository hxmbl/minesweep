package report

import (
	"strings"
)

// SanitizeTerminal neutralizes terminal control sequences embedded in
// attacker-influenced strings (file paths, secret values, context lines,
// git author names, commit summaries). Escape sequence injection can set
// window titles, clear screens, or overlay fake UI while a user reads a
// scan report.
//
// ESC is rendered visibly as \e; other C0 controls except \n and \t are
// rendered in caret notation. Newlines/tabs are preserved because report
// layout depends on them.
func SanitizeTerminal(s string) string {
	if !strings.ContainsFunc(s, needsEscape) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch {
		case r == 0x1b:
			b.WriteString(`\e`)
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == 0x7f:
			b.WriteString("^?")
		case r < 0x20:
			b.WriteByte('^')
			b.WriteRune(r + 0x40)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func needsEscape(r rune) bool {
	if r == 0x1b || r == 0x7f {
		return true
	}
	if r < 0x20 && r != '\n' && r != '\t' {
		return true
	}
	return false
}
