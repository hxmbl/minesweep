package filesystem

import (
	"sort"
	"strings"
)

// lineIndex maps byte offsets in a file to 1-based line/column positions.
// It is built in a single pass and answers lookups via binary search, so
// locating thousands of matches costs O(matches * log(lines)) instead of
// rescanning the file from the start for every match.
type LineIndex struct {
	content []byte
	starts  []int32
}

func NewLineIndex(content []byte) *LineIndex {
	starts := make([]int32, 1, 256)
	for i, b := range content {
		if b == '\n' {
			starts = append(starts, int32(i+1))
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
		sb.WriteString(strings.TrimSpace(li.LineText(i)))
		sb.WriteString("\n")
	}
	return sb.String()
}
