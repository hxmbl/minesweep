package findings

import (
	"strings"
)

// FilterRustTestModuleFindings removes findings that fall inside Rust inline
// #[cfg(test)] modules. It is a no-op when no findings or lines are provided.
//
// The detector is intentionally heuristic: it recognises the common
// `#[cfg(test)] mod ... { ... }` form and excludes everything inside the
// module's brace-delimited body. External test modules (`mod tests;`) are not
// marked because their contents live in another file.
func FilterRustTestModuleFindings(fs []Finding, lines LineLookup) []Finding {
	if len(fs) == 0 || lines == nil {
		return fs
	}
	n := lines.LineCount()
	if n == 0 {
		return fs
	}

	ranges := rustTestModuleRanges(lines, n)
	if len(ranges) == 0 {
		return fs
	}

	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		if !inTestModuleRange(f.Line, ranges) {
			out = append(out, f)
		}
	}
	return out
}

type lineRange struct {
	start int
	end   int
}

func inTestModuleRange(line int, ranges []lineRange) bool {
	for _, r := range ranges {
		if line >= r.start && line <= r.end {
			return true
		}
		if r.start > line {
			return false
		}
	}
	return false
}

func rustTestModuleRanges(lines LineLookup, n int) []lineRange {
	var ranges []lineRange
	for i := 1; i <= n; i++ {
		text := strings.TrimSpace(lines.LineText(i - 1))
		if !isCfgTestAttr(text) {
			continue
		}
		r, next := findInlineTestModule(lines, n, i)
		if r.end >= r.start {
			ranges = append(ranges, r)
			if next > i {
				i = next
			}
		}
	}
	return ranges
}

func isCfgTestAttr(line string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
		return false
	}
	compact := strings.Join(strings.Fields(trimmed), "")
	if !strings.HasPrefix(compact, "#[cfg(") {
		return false
	}
	// Match cfg(test) as a cfg predicate, but not not(test).
	if strings.Contains(compact, "not(test)") || strings.Contains(compact, "not(test,") || strings.Contains(compact, "not(test ") {
		return false
	}
	for _, tok := range []string{"(test)", "(test,", ",test)", ",test,"} {
		if strings.Contains(compact, tok) {
			return true
		}
	}
	return false
}

func findInlineTestModule(lines LineLookup, n, attrLine int) (lineRange, int) {
	// Scan forward from the attribute for a mod declaration. Allow other
	// attributes between #[cfg(test)] and the module.
	for j := attrLine; j <= n && j <= attrLine+8; j++ {
		raw := lines.LineText(j - 1)
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		hasMod := containsModDecl(trimmed)
		if strings.HasPrefix(trimmed, "#[") && !hasMod {
			continue
		}
		if !hasMod {
			return lineRange{}, attrLine
		}
		// External module: `mod tests;`
		if strings.Contains(trimmed, ";") && !strings.Contains(trimmed, "{") {
			return lineRange{}, j
		}
		// Inline module: find opening brace and track depth.
		depth := 0
		seenBrace := false
		for k := j; k <= n; k++ {
			line := lines.LineText(k - 1)
			depth += braceDelta(line)
			if strings.Contains(line, "{") {
				seenBrace = true
			}
			if seenBrace && depth <= 0 {
				return lineRange{start: attrLine, end: k}, k
			}
		}
		if seenBrace {
			return lineRange{start: attrLine, end: n}, n
		}
		return lineRange{}, j
	}
	return lineRange{}, attrLine
}

func containsModDecl(line string) bool {
	trimmed := strings.TrimSpace(line)
	return strings.HasPrefix(trimmed, "mod ") || strings.HasPrefix(trimmed, "pub mod ") ||
		strings.Contains(trimmed, " mod ") || strings.Contains(trimmed, "\tmod ")
}

func braceDelta(line string) int {
	delta := 0
	inLineComment := false
	inString := false
	inChar := false
	escape := false
	for i := 0; i < len(line); i++ {
		ch := line[i]
		if inLineComment {
			break
		}
		if escape {
			escape = false
			continue
		}
		if ch == '\\' && (inString || inChar) {
			escape = true
			continue
		}
		if inString {
			if ch == '"' {
				inString = false
			}
			continue
		}
		if inChar {
			if ch == '\'' {
				inChar = false
			}
			continue
		}
		if ch == '/' && i+1 < len(line) && line[i+1] == '/' {
			inLineComment = true
			continue
		}
		if ch == '"' {
			inString = true
			continue
		}
		if ch == '\'' {
			// Heuristic: treat as char literal only for simple cases.
			if i+2 < len(line) && line[i+2] == '\'' {
				inChar = true
				continue
			}
			if i+3 < len(line) && line[i+1] == '\\' && line[i+3] == '\'' {
				inChar = true
				continue
			}
			continue
		}
		switch ch {
		case '{':
			delta++
		case '}':
			delta--
		}
	}
	return delta
}
