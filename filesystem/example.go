package filesystem

import (
	"path/filepath"
	"strings"
	"sync"
)

// ExampleContextMinConfidence is the bar a finding must clear to be reported
// from inside a documentation example.
//
// The rule this implements is: an example is held to a stricter standard than
// configuration. It is not a file-type ban.
//
// Documentation is not a coverage hole — real credentials do get pasted into
// READMEs, and the reviewer's own false positive was a `webhook_secret`
// assignment in a fenced Python block, which is precisely the shape a real
// leak would take. So the content is still scanned. What changes is how much
// certainty is required: inside a fence, a 0.60-confidence keyword-context match
// is as likely to be a documentation sample as a leak, while a 0.85-confidence
// vendor-prefixed match is almost certainly a real credential whatever the
// surrounding prose claims.
//
// That threshold keeps the two cases the reviewer cared about apart:
//
//	webhook_secret = "whsec_…"   env-password,  0.60  -> held back
//	auth_token = "ghp_…"          generic/entropy, 0.85 -> still reported
//
// The alternative — excluding *.md the way two of the generic rules already do
// — trades a false positive for a silent gap, which is the specific failure
// mode exit code 2 exists to make visible.

// ExampleContextMinConfidence is the confidence a finding must reach to be
// reported from inside a documentation example.
const ExampleContextMinConfidence = 0.80

// docExtensions are the file types whose fenced and indented blocks carry
// examples rather than configuration.
var docExtensions = map[string]bool{
	".md": true, ".markdown": true, ".mdx": true, ".rst": true,
	".txt": true, ".text": true, ".adoc": true, ".asciidoc": true,
	".textile": true, ".org": true,
}

// IsDocFile reports whether path is a documentation file, where fenced blocks
// and inline code spans carry examples.
func IsDocFile(path string) bool {
	return docExtensions[strings.ToLower(filepath.Ext(path))]
}

// exampleState memoises the per-line example map. Building it is O(lines) and
// is done at most once per file, only for documentation files, and only if a
// detector asks.
type exampleState struct {
	once  sync.Once
	lines []bool
}

// InExampleContext reports whether the 1-based line falls inside a fenced
// block, an indented code block, or an inline code span.
//
// For a non-documentation file it is always false, and it costs a map lookup:
// the fence scan is not run on code, config, or lockfiles.
func (f *File) InExampleContext(line int) bool {
	if !IsDocFile(f.Path) {
		return false
	}
	f.example.once.Do(func() { f.example.lines = buildExampleLines(f.Lines()) })
	lines := f.example.lines
	if line < 1 || line > len(lines) {
		return false
	}
	return lines[line-1]
}

// buildExampleLines marks each line of a documentation file as example context.
//
// Four shapes are recognised, which between them cover where examples actually
// live in a README:
//
//   - Fenced blocks: ``` or ~~~ runs of three or more, opened and closed. The
//     closing fence is itself example context, because the line after it is
//     prose and a stray backtick there must not unbalance the state.
//   - Indented code blocks: four spaces or a tab, the pre-f CommonMark form
//     still used for shell transcripts.
//   - Inline code spans: a backtick-delimited run on the line itself, which
//     covers the `API_KEY=your-key-here` written mid-sentence.
//   - HTML comments: an example hidden in `<!-- … -->`, which is how older
//     READMEs shipped configuration snippets.
//
// A fence marker that is indented (```) does not open a block — in CommonMark
// that opens an indented code block containing a fence, which is not what a
// README means. Treating it as a fence here would leave the state open for the
// rest of the file and suppress genuine findings in prose below it.
func buildExampleLines(li *LineIndex) []bool {
	if li == nil {
		return nil
	}
	n := li.LineCount()
	lines := make([]bool, n)
	fence := byte(0) // 0 = not inside a fenced block
	for i := 0; i < n; i++ {
		text := li.LineText(i)
		trimmed := strings.TrimLeft(text, " \t")
		indented := len(text) > 0 && (strings.HasPrefix(text, "\t") ||
			strings.HasPrefix(text, "    "))

		if fence != 0 {
			lines[i] = true
			if isClosingFence(trimmed, fence) {
				fence = 0
			}
			continue
		}
		if c, ok := openingFence(trimmed); ok && !indented {
			lines[i] = true
			fence = c
			continue
		}
		if indented {
			lines[i] = true
			continue
		}
		if hasInlineCodeSpan(trimmed) {
			lines[i] = true
			continue
		}
		if inHTMLComment(trimmed) {
			lines[i] = true
		}
	}
	return lines
}

// openingFence reports the fence character if trimmed opens a fenced block.
func openingFence(trimmed string) (byte, bool) {
	if len(trimmed) < 3 {
		return 0, false
	}
	c := trimmed[0]
	if c != '`' && c != '~' {
		return 0, false
	}
	n := 0
	for n < len(trimmed) && trimmed[n] == c {
		n++
	}
	if n < 3 {
		return 0, false
	}
	// An info string may follow a backtick fence but not a tilde fence.
	if c == '`' && strings.ContainsRune(trimmed[n:], '`') {
		return 0, false
	}
	return c, true
}

// isClosingFence reports whether trimmed closes a block opened with c. A
// closing fence must be at least as long as the opening one and carry no info
// string.
func isClosingFence(trimmed string, c byte) bool {
	if len(trimmed) < 3 || trimmed[0] != c {
		return false
	}
	return strings.Trim(trimmed, string(c)) == ""
}

// hasInlineCodeSpan reports whether the line contains a backtick-delimited run.
func hasInlineCodeSpan(trimmed string) bool {
	start := strings.IndexByte(trimmed, '`')
	if start < 0 {
		return false
	}
	// Skip the whole opening run: a double-backtick span, as used for a literal
	// that itself contains a backtick, opens with two and closes with two.
	rest := strings.TrimLeft(trimmed[start:], "`")
	return strings.IndexByte(rest, '`') >= 0
}

// inHTMLComment reports whether the line is inside an HTML comment. Multi-line
// comments are not tracked across lines; a `<!--` line and a `-->` line are each
// treated as example context, which covers the one-line form.
func inHTMLComment(trimmed string) bool {
	return strings.HasPrefix(trimmed, "<!--") || strings.HasSuffix(trimmed, "-->")
}
