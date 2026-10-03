package filesystem

import (
	"unicode"
	"unicode/utf8"
)

// ASCIIFoldRune reports the ASCII lowercase letter that r case-folds to, if any.
//
// Go's regexp `(?i)` matches by Unicode simple folding, so a pattern rune and a
// content rune match when they sit in the same unicode.SimpleFold orbit. Most
// ASCII letters have an orbit that stays inside ASCII. Two do not:
//
//	'k' shares its orbit with U+212A KELVIN SIGN
//	's' shares its orbit with U+017F LATIN SMALL LETTER LONG S
//
// So `(?i)key` matches "Key" spelled with U+212A, and `(?i)secret` matches
// "ſecret". A case-insensitive literal gate therefore cannot be searched for
// with bytes.ToLower: bytes.ToLower leaves U+212A and U+017F untouched, the
// ASCII needle is absent from an input that genuinely matches, and the pattern
// is silently skipped. Mapping both sides onto the shared ASCII member keeps the
// gate sound for every letter.
//
// The second return value is false when r's orbit contains no ASCII member.
// Such a rune can never satisfy an ASCII needle, so callers must leave it alone
// rather than guess at an equivalent.
func ASCIIFoldRune(r rune) (byte, bool) {
	// The ASCII orbits are closed: 'k' only reaches U+212A and 's' only reaches
	// U+017F, and neither of those orbits contains any further member. Checked
	// against unicode.SimpleFold rather than assumed.
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < utf8.RuneSelf {
			if f >= 'A' && f <= 'Z' {
				f += 'a' - 'A'
			}
			return byte(f), true //nolint:gosec // G115: guarded by f < utf8.RuneSelf
		}
	}
	if r >= 'A' && r <= 'Z' {
		r += 'a' - 'A'
	}
	if r < utf8.RuneSelf {
		return byte(r), true //nolint:gosec // G115: guarded by r < utf8.RuneSelf
	}
	return 0, false
}

// FoldLower returns content folded for case-insensitive literal search.
//
// Every byte below utf8.RuneSelf is lowercased. A multi-byte rune is replaced by
// the single ASCII byte of its fold orbit when it has one, so that U+212A and
// U+017F become 'k' and 's' respectively — matching what ASCIIFoldRune does to a
// pattern literal. Any other multi-byte rune is copied through verbatim: it has
// no ASCII fold member, so no ASCII needle can depend on it, and copying it
// keeps this to one pass with one allocation.
//
// The result is shorter than content only by one byte per U+212A/U+017F
// replaced. It is a search view, not a positional view of the content; use Lines
// or LineCol for offsets.
func FoldLower(content []byte) []byte {
	out := make([]byte, 0, len(content))
	for i := 0; i < len(content); {
		c := content[i]
		if c < utf8.RuneSelf {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			out = append(out, c)
			i++
			continue
		}
		r, size := utf8.DecodeRune(content[i:])
		if folded, ok := ASCIIFoldRune(r); ok && size > 1 {
			out = append(out, folded)
			i += size
			continue
		}
		out = append(out, content[i:i+size]...)
		i += size
	}
	return out
}
