package detectors

import (
	"strings"

	"minesweep/filesystem"
)

// A finding on a comment-only line is held to a stricter bar, for the same
// reason a finding inside a documentation example is: the surrounding grammar
// says what the text is, and a comment is prose.
//
// This is not a rare shape. Running this tool over its own repository after the
// placeholder and grammar work, the only findings left were seven of them, every
// single one inside a comment in this package:
//
//	// `DB_PASSWORD=changeme` produced three findings (database credentials, …
//	//   - `password=secret`, `password=admin`, `password=default`. These are
//	// password = state.get("token")             -> "state.get("
//	token = state.get("token")                   -> captured whole
//
// A comment that names a credential shape is nearly always explaining one. The
// code that follows the comment is what actually runs.
//
// The bar is raised rather than the finding dropped, for the reason that decides
// every judgement in this file: a secret really can live in a comment — pasted
// for debugging, or left behind in a commented-out block — and a scanner that
// goes silent there has traded a nuisance for a gap. Unambiguous shapes clear
// CommentMinConfidence and are still reported:
//
//	AKIA…                     0.95   reported
//	-----BEGIN RSA PRIVATE…   0.95   reported
//	aws_secret_access_key …   0.95   reported
//	ghp_…                     0.95   reported
//	DB_PASSWORD=changeme      0.80   held back
//	secret = "…"              0.60   held back
//
// It is the same trade already made for documentation, applied to the other
// place where text describes configuration instead of being it.

// CommentMinConfidence is the confidence a finding must reach to be reported
// from a comment-only line. It sits above ExampleContextMinConfidence: prose
// about a secret is a weaker signal than a fenced example of one, because a
// comment has no syntax constraining it at all.
const CommentMinConfidence = 0.90

// isCommentOnlyLine reports whether text consists solely of a comment.
//
// Only unambiguous markers count, and only full-line comments are recognised.
// Both restrictions are deliberate:
//
//   - Trailing comments are not detected. Finding the start of a trailing
//     comment means recognising `//` outside string literals, and a URL is full
//     of `//` — `url = https://example.com/a#b` would lose everything after the
//     scheme. A heuristic that misreads a URL mangles evidence lines and hides
//     real findings, which is a far worse trade than reporting a comment.
//   - `#` counts as a comment only outside documentation, where it is a
//     heading. `.md` files are handled by the example-context path instead.
//
// `*` is accepted for the continuation line of a `/* … */` block. It requires
// whitespace or end-of-line after it, so `*ptr` — which cannot start a line in
// valid code anyway — does not qualify.
func isCommentOnlyLine(text string, isDoc bool) bool {
	t := strings.TrimLeft(text, " \t")
	// Tolerate a CRLF ending: a `*` continuation line would otherwise fail the
	// whitespace test below purely because of the line terminator.
	t = strings.TrimRight(t, "\r\n")
	switch {
	case strings.HasPrefix(t, "//"):
		return true
	case strings.HasPrefix(t, "<!--"):
		return true
	case strings.HasPrefix(t, "#"):
		return !isDoc
	case strings.HasPrefix(t, "*"):
		return len(t) == 1 || t[1] == ' ' || t[1] == '\t'
	}
	return false
}

// heldBackByLineContext reports whether a finding's confidence is too low for
// where it sits.
//
// It is the single place that decides this, so the two contexts cannot drift
// apart: a documentation example and a comment-only line both mean "this text
// describes a credential rather than being one", and both demand more certainty
// before interrupting anyone.
func heldBackByLineContext(file *filesystem.File, lineNum int, lineText string, confidence float64) bool {
	if file.InExampleContext(lineNum) {
		return confidence < filesystem.ExampleContextMinConfidence
	}
	if isCommentOnlyLine(lineText, filesystem.IsDocFile(file.Path)) {
		return confidence < CommentMinConfidence
	}
	return false
}
