package filesystem

import (
	"os"
	"path/filepath"
	"testing"
)

// linesOf is a LineIndex over literal text, for testing buildExampleLines
// without touching the filesystem.
func linesOf(text string) *LineIndex {
	return NewLineIndex([]byte(text))
}

func markedLines(li *LineIndex) []int {
	var out []int
	flags := buildExampleLines(li)
	for i, m := range flags {
		if m {
			out = append(out, i+1)
		}
	}
	return out
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The reviewer's false positive: a fenced Python block in a README holding
// `webhook_secret = "…"`, which the env-password rule matched at 0.60. The
// fence has to be recognised as example context for the stricter bar to apply.
func TestExampleContextRecognisesFencedBlocks(t *testing.T) {
	li := linesOf("# Title\n\n" +
		"Prose that mentions API_KEY casually.\n" +
		"\n" +
		"```python\n" +
		"webhook_secret = \"whsec_abc\"\n" +
		"```\n" +
		"\n" +
		"More prose.\n")

	got := markedLines(li)
	want := []int{5, 6, 7}
	if !equalInts(got, want) {
		t.Errorf("fenced lines = %v, want %v", got, want)
	}
}

// An unclosed fence must not leave the state open for the rest of the file. A
// README with a typo in its last fence would otherwise suppress genuine findings
// in every line after it.
func TestExampleContextUnclosedFenceStillBoundsIt(t *testing.T) {
	// Three lines because the content ends with a newline, so LineIndex counts
	// a final empty line.
	li := linesOf("```\nsecret = abc\n")
	got := markedLines(li)
	if !equalInts(got, []int{1, 2, 3}) {
		t.Errorf("lines = %v, want [1 2 3]", got)
	}
}

func TestExampleContextTildeFence(t *testing.T) {
	li := linesOf("~~~yaml\ntoken: abc123\n~~~\nprose\n")
	got := markedLines(li)
	if !equalInts(got, []int{1, 2, 3}) {
		t.Errorf("lines = %v, want [1 2 3]", got)
	}
}

// An info string may follow a backtick fence but not a tilde fence. Getting this
// backwards would treat a closing tilde fence with a trailing space as still
// open.
func TestExampleContextFenceInfoStringRules(t *testing.T) {
	li := linesOf("```python\nx = 1\n~~~\nnot a close\n```\ny = 2\n")
	got := markedLines(li)
	if !equalInts(got, []int{1, 2, 3, 4, 5}) {
		t.Errorf("lines = %v, want [1 2 3 4 5] — a tilde fence must not close a backtick fence", got)
	}
}

func TestExampleContextIndentedCodeBlock(t *testing.T) {
	li := linesOf("Prose:\n\n    export TOKEN=abc123\n    echo done\n\nProse again.\n")
	got := markedLines(li)
	if !equalInts(got, []int{3, 4}) {
		t.Errorf("lines = %v, want [3 4]", got)
	}
}

// A backtick line is a fence, not a fence inside an indented block. Treating it
// as a fence would leave the state open and mark the whole rest of the file.
func TestExampleContextIndentedFenceDoesNotOpenBlock(t *testing.T) {
	li := linesOf("    ```\n    token: abc\nprose after\n")
	got := markedLines(li)
	if !equalInts(got, []int{1, 2}) {
		t.Errorf("lines = %v, want [1 2]; prose must not be swallowed", got)
	}
}

// The `API_KEY=your-key-here` written mid-sentence is an example too.
func TestExampleContextInlineCodeSpan(t *testing.T) {
	li := linesOf("Set `API_KEY=your-key-here` before running.\nNothing special here.\n")
	got := markedLines(li)
	if !equalInts(got, []int{1}) {
		t.Errorf("lines = %v, want [1]", got)
	}
}

// A doubled-backtick span, used for a literal that contains a backtick, must be
// recognised rather than closing on its own opening marker.
func TestExampleContextDoubleBacktickSpan(t *testing.T) {
	li := linesOf("Use `` KEY=`x` `` as the value.\nPlain prose.\n")
	got := markedLines(li)
	if !equalInts(got, []int{1}) {
		t.Errorf("lines = %v, want [1]", got)
	}
}

func TestExampleContextHTMLComment(t *testing.T) {
	li := linesOf("<!-- password = \"hunter2hunter2\" -->\nProse.\n")
	got := markedLines(li)
	if !equalInts(got, []int{1}) {
		t.Errorf("lines = %v, want [1]", got)
	}
}

// Non-documentation files must cost nothing and mark nothing. A source file is
// not full of examples even when it contains a backtick.
func TestExampleContextOnlyAppliesToDocFiles(t *testing.T) {
	for _, name := range []string{"a.go", "a.env", "config.yaml", "package.json", "a.tf"} {
		if IsDocFile(name) {
			t.Errorf("%s classified as documentation", name)
		}
	}
	for _, name := range []string{"README.md", "guide.rst", "notes.txt", "a.mdx", "b.ADOC"} {
		if !IsDocFile(name) {
			t.Errorf("%s not classified as documentation", name)
		}
	}

	f := &File{Path: "main.go"}
	if f.InExampleContext(1) {
		t.Error("a .go file must never be example context")
	}
}

// End to end through a real file, because the memoisation lives on File and a
// stubbed LineIndex would not exercise it.
func TestInExampleContextThroughFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "README.md")
	body := "# Title\n\ntext\n\n```sh\nTOKEN=abc123def456\n```\n\nmore text\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := NewFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		line int
		want bool
	}{{1, false}, {3, false}, {5, true}, {6, true}, {8, false}, {0, false}, {999, false}} {
		if got := f.InExampleContext(tc.line); got != tc.want {
			t.Errorf("InExampleContext(%d) = %v, want %v", tc.line, got, tc.want)
		}
	}
}

// The threshold itself. These are the numbers the reviewer's two findings sat on
// either side of, and the reason the doc rule is a stricter bar rather than a
// file-type ban.
func TestExampleContextMinConfidenceKeepsRealCredentials(t *testing.T) {
	const bar = ExampleContextMinConfidence
	// Held back: the reviewer's README fence case.
	if 0.60 >= bar {
		t.Errorf("env-password at 0.60 must fall below the bar, bar is %v", bar)
	}
	// Still reported: a vendor-prefixed token, whatever the prose around it says.
	if 0.85 < bar {
		t.Errorf("a 0.85 vendor match must clear the bar, bar is %v", bar)
	}
	// Still reported: an unambiguous shape.
	if 0.95 < bar {
		t.Errorf("a 0.95 shape match must clear the bar, bar is %v", bar)
	}
}
