package filesystem

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// lineIndex maps byte offsets in a file to 1-based line/column positions.
// It is built in a single pass and answers lookups via binary search, so
// locating thousands of matches costs O(matches * log(lines)) instead of
// rescanning the file from the start for every match.
type LineIndex struct {
	content []byte
	starts  []int
}

func NewLineIndex(content []byte) *LineIndex {
	starts := make([]int, 1, 256)
	for i, b := range content {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return &LineIndex{content: content, starts: starts}
}

// LineCol returns the 1-based line number and column of byte offset pos.
func (li *LineIndex) LineCol(pos int) (line, col int) {
	if pos > len(li.content) {
		pos = len(li.content)
	}
	i := sort.Search(len(li.starts), func(i int) bool {
		return int(li.starts[i]) > pos
	}) - 1
	if i < 0 {
		i = 0
	}
	return i + 1, pos - int(li.starts[i]) + 1
}

// LineCount returns the number of lines in the indexed content.
func (li *LineIndex) LineCount() int { return len(li.starts) }

// LineText returns the raw text of the given 0-based line index without the
// trailing newline.
func (li *LineIndex) LineText(idx int) string {
	if idx < 0 || idx >= len(li.starts) {
		return ""
	}
	start := int(li.starts[idx])
	end := len(li.content)
	if idx+1 < len(li.starts) {
		end = int(li.starts[idx+1]) - 1
		if end < start {
			end = start
		}
	}
	if end > len(li.content) {
		end = len(li.content)
	}
	return string(li.content[start:end])
}

// context renders the classic "> " highlighted context block around a
// 0-based center line, matching the previous extractContext output format.
func (li *LineIndex) Context(center, radius int) string {
	return li.ContextCapped(center, radius, 0)
}

// ContextCapped is Context with each rendered line truncated to maxLineBytes
// (0 = unlimited).
//
// The ceiling exists because "a line" is not bounded by anything: a SQLite
// database, a minified bundle or a single-line JSON blob has no newline for
// megabytes, and every finding on that line then carried the whole thing in
// its Context field — a 30 MB input produced a 60 MB report. Truncation is
// applied per line after TrimSpace so the visible head of the line is what
// survives, and it is applied on a rune boundary.
func (li *LineIndex) ContextCapped(center, radius, maxLineBytes int) string {
	start := center - radius
	if start < 0 {
		start = 0
	}
	end := center + radius + 1
	if end > len(li.starts) {
		end = len(li.starts)
	}
	var sb strings.Builder
	for i := start; i < end; i++ {
		prefix := "  "
		if i == center {
			prefix = "> "
		}
		sb.WriteString(prefix)
		sb.WriteString(CapLine(strings.TrimSpace(li.LineText(i)), maxLineBytes))
		sb.WriteString("\n")
	}
	return sb.String()
}

// CapLine truncates s to at most maxLineBytes bytes (0 = unlimited), never
// splitting a UTF-8 rune. A cap that landed mid-rune produced replacement
// characters in the middle of a security report.
func CapLine(s string, maxLineBytes int) string {
	if maxLineBytes <= 0 || len(s) <= maxLineBytes {
		return s
	}
	cut := maxLineBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}
