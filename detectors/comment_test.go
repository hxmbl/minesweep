package detectors

import "testing"

// A comment that names a credential shape is nearly always explaining one. This
// is not a rare shape: scanning this repository with the placeholder and grammar
// work in place, the only findings left were seven, every one of them inside a
// comment in this package.
func TestCommentOnlyLinesAreHeldToAStricterBar(t *testing.T) {
	body := "" +
		"# token = state.get(\"token\")  -> explains the old code\n" +
		"# api_key = lookup(\"api_key\")\n" +
		"# Set AUTH_TOKEN=your-token-here before starting.\n" +
		"# DB_PASSWORD=changeme\n"

	for _, f := range scanText(t, "app.py", body) {
		t.Errorf("comment reported: rule=%s line=%d conf=%v", f.RuleID, f.Line, f.Confidence)
	}
}

// The other direction, which is the one that matters. A secret really can live
// in a comment — pasted for debugging, or left behind in a commented-out block —
// so the bar is raised rather than the finding dropped, and an unambiguous shape
// clears it.
func TestRealSecretsInCommentsAreStillReported(t *testing.T) {
	body := "" +
		"# Leftover from the postmortem, rotated but not yet removed:\n" +
		"# AWS_ACCESS_KEY_ID=\x41KIAZQ4TLN2XRH7JWBVG\n" +
		"# GITHUB_TOKEN=\x67hp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n"

	got := scanText(t, "app.py", body)
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.RuleID] = true
	}
	for _, want := range []string{"aws-access-key-id", "github-pat"} {
		if !seen[want] {
			t.Errorf("%s did not fire on a real credential in a comment; got %v", want, seen)
		}
	}
}

// A URL is full of `//` and often carries a `#`. Treating a trailing comment as
// starting there would swallow the rest of the line, hide real findings, and
// mangle evidence. Comment detection therefore only recognises a comment that
// begins the line.
func TestURLsAreNotMistakenForComments(t *testing.T) {
	body := "url = \"https://example.com/#fragment\"\n" +
		"TOKEN = \"xK9mP2Lq7vR4zW8yU1iO5pA3dF7gH0jK\"\n"

	got := scanText(t, "app.py", body)
	for _, f := range got {
		if f.Line == 1 {
			t.Errorf("the URL line was treated as a comment: rule=%s value=%q", f.RuleID, f.Value)
		}
	}
	found := false
	for _, f := range got {
		if f.Line == 2 {
			found = true
		}
	}
	if !found {
		t.Error("a real token after a URL was lost")
	}
}

// `#` is a comment in code and a heading in documentation. Treating every `#`
// line in a README as a comment would apply the wrong (looser) rule to prose.
func TestHashIsAHeadingInDocumentationNotAComment(t *testing.T) {
	if isCommentOnlyLine("# Deploy notes", true) {
		t.Error("# must not be a comment marker in a documentation file")
	}
	if !isCommentOnlyLine("# TOKEN = value", false) {
		t.Error("# must be a comment marker in a code file")
	}
}

func TestCommentMarkerRecognition(t *testing.T) {
	cases := []struct {
		text  string
		isDoc bool
		want  bool
	}{
		{"// password = abc", false, true},
		{"   // indented comment", false, true},
		{"<!-- password = abc -->", false, true},
		{" * continuation of a block comment", false, true},
		{"*\n", false, true},
		{"*ptr", false, false},
		{"token = \"abc\" // trailing", false, false},
		{"# heading", true, false},
		{"code();", false, false},
		{"", false, false},
	}
	for _, tc := range cases {
		if got := isCommentOnlyLine(tc.text, tc.isDoc); got != tc.want {
			t.Errorf("isCommentOnlyLine(%q, doc=%v) = %v, want %v", tc.text, tc.isDoc, got, tc.want)
		}
	}
}

// The bar itself. CommentMinConfidence sits above the documentation bar because
// a comment has no syntax constraining it at all.
func TestCommentBarIsStricterThanTheDocumentationBar(t *testing.T) {
	if CommentMinConfidence <= 0.80 {
		t.Errorf("the comment bar (%v) must be stricter than the documentation bar (0.80)", CommentMinConfidence)
	}
	// Shapes that must survive a comment line.
	for _, conf := range []float64{0.90, 0.95} {
		if conf < CommentMinConfidence {
			t.Errorf("a %.2f match must clear the comment bar", conf)
		}
	}
}
