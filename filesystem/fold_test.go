package filesystem

import (
	"bytes"
	fx "minesweep/internal/fixtures"
	"testing"
	"unicode"
	"unicode/utf8"
)

// TestASCIIFoldRuneOrbitMembers pins the two ASCII letters whose Unicode simple
// fold orbit escapes ASCII. These are exactly the letters for which ASCII-only
// lowercasing produced an unsound literal gate (finding #1).
func TestASCIIFoldRuneOrbitMembers(t *testing.T) {
	cases := []struct {
		r    rune
		want byte
	}{
		{'k', 'k'},
		{0x212A, 'k'}, // KELVIN SIGN
		{'K', 'k'},
		{'s', 's'},
		{0x017F, 's'}, // LATIN SMALL LETTER LONG S
		{'S', 's'},
	}
	for _, c := range cases {
		got, ok := ASCIIFoldRune(c.r)
		if !ok {
			t.Errorf("ASCIIFoldRune(%#U) reported no ASCII fold member", c.r)
			continue
		}
		if got != c.want {
			t.Errorf("ASCIIFoldRune(%#U) = %q, want %q", c.r, got, c.want)
		}
	}
}

// Every other ASCII rune must fold to its own lowercase, and any rune without an
// ASCII orbit member must be declined so callers do not guess.
func TestASCIIFoldRuneExhaustiveASCII(t *testing.T) {
	for r := rune(0); r < utf8.RuneSelf; r++ {
		got, ok := ASCIIFoldRune(r)
		if !ok {
			t.Errorf("ASCIIFoldRune(%#U) declined an ASCII rune", r)
			continue
		}
		want := byte(r)
		if r >= 'A' && r <= 'Z' {
			want += 'a' - 'A'
		}
		if got != want {
			t.Errorf("ASCIIFoldRune(%#U) = %q, want %q", r, got, want)
		}
	}
}

func TestASCIIFoldRuneDeclinesNonASCIIWithoutOrbitMember(t *testing.T) {
	// Latin-1 runes and Greek/Cyrillic runes have no ASCII fold member.
	for _, r := range []rune{0x00E9 /* é */, 0x03B1 /* α */, 0x0430 /* а */, 0x00DF /* ß */} {
		if _, ok := ASCIIFoldRune(r); ok {
			t.Errorf("ASCIIFoldRune(%#U) invented an ASCII fold member", r)
		}
	}
}

// The only ASCII letters that need a non-ASCII orbit partner must be k and s.
// If Unicode ever grows another, this fails loudly so the gate stays sound.
// Each escaping orbit is reported by all of its ASCII members, so compare
// lowercased: {k,K,s,S} collapsing to {k,s}.
func TestASCIIFoldOrbitEscapeSetIsExactlyKS(t *testing.T) {
	seen := map[rune]bool{}
	for r := rune('a'); r < utf8.RuneSelf; r++ {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f >= utf8.RuneSelf {
				seen[unicode.ToLower(r)] = true
				break
			}
		}
	}
	var escaped []rune
	for r := rune('a'); r < utf8.RuneSelf; r++ {
		if seen[r] {
			escaped = append(escaped, r)
		}
	}
	if len(escaped) != 2 || escaped[0] != 'k' || escaped[1] != 's' {
		t.Errorf("ASCII letters with non-ASCII fold orbit members = %q, want [k s]", escaped)
	}
}

func TestFoldLowerReplacesFoldOrbitEscapers(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"PASSWORD=X", "password=x"},
		{"pa\u017f\u017fword", "password"},
		{"AWS_KEY", "aws_key"},
		{"\u212A", "k"}, // KELVIN SIGN
		{"no change here", "no change here"},
		{"caf\u00e9_na\u00efve", "caf\u00e9_na\u00efve"}, // non-ASCII runes pass through
		{"AKIA/SECRET+KEY=", "akia/secret+key="},
	}
	for _, c := range cases {
		if got := string(FoldLower([]byte(c.in))); got != c.want {
			t.Errorf("FoldLower(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// FoldLower must never lose or invent content: it is a search view derived from
// the original bytes, and a detector matching against the raw content must still
// find the same ASCII substrings.
func TestFoldLowerPreservesASCIIContentExactly(t *testing.T) {
	for _, in := range []string{
		"", "a", "ABC", "the quick brown FOX jumps over 0123456789 lazy dog",
		"postgres://user:pass@host:5432/db",
		fx.AWSAccessKeyID(),
	} {
		if got := FoldLower([]byte(in)); !bytes.Equal(got, []byte(lowerBytes(in))) {
			t.Errorf("FoldLower(%q) = %q, want pure ASCII lowercase %q", in, got, lowerBytes(in))
		}
	}
}

func lowerBytes(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// Invalid UTF-8 must not panic, and must be passed through untouched rather
// than dropped: FoldLower is a search view, so rewriting bytes it cannot decode
// could only lose content.
func TestFoldLowerSurvivesInvalidUTF8(t *testing.T) {
	cases := []struct{ in, want string }{
		{"\xff\xfeAB", "\xff\xfeab"},
		{"\x80", "\x80"},
		{"\xc3", "\xc3"},                 // truncated 2-byte sequence
		{"\xed\xa0\x80", "\xed\xa0\x80"}, // surrogate half
	}
	for _, c := range cases {
		if got := string(FoldLower([]byte(c.in))); got != c.want {
			t.Errorf("FoldLower(% x) = % x, want % x", c.in, got, c.want)
		}
	}
}

// A large realistic buffer, to be sure the single pass stays linear and does not
// corrupt content while collapsing runes.
func TestFoldLowerLargeMixedContent(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < 5000; i++ {
		buf.WriteString("DB_PASSWORD=Sup3rS3cret; \u212A ")
	}
	got := FoldLower(buf.Bytes())
	// KELVIN SIGN is 3 UTF-8 bytes and collapses to 1, so 2 bytes lost per copy.
	want := buf.Len() - 2*5000
	if len(got) != want {
		t.Errorf("len(FoldLower) = %d, want %d", len(got), want)
	}
	if !bytes.Contains(got, []byte("db_password=sup3rs3cret; k ")) {
		t.Error("FoldLower mangled repeated ASCII content while collapsing")
	}
	if n := bytes.Count(got, []byte("db_password=sup3rs3cret; k ")); n != 5000 {
		t.Errorf("repeated content survived %d times, want 5000", n)
	}
}
