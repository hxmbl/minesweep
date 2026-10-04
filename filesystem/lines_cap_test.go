package filesystem

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A file with no newline at all (SQLite, a minified bundle, single-line JSON)
// made "line 1" the whole file, so every finding carried megabytes of raw
// content into its evidence. The per-line ceiling makes report size
// proportional to the finding count instead.
func TestContextCappedBoundsLineLength(t *testing.T) {
	huge := strings.Repeat("A", 200_000)
	li := NewLineIndex([]byte(huge))

	full := li.Context(0, 2)
	if len(full) < len(huge) {
		t.Fatalf("precondition failed: unbounded context should contain the whole line (%d bytes)", len(full))
	}

	capped := li.ContextCapped(0, 2, 512)
	if len(capped) > 4*(512+len("…\n")) {
		t.Fatalf("capped context is %d bytes, expected roughly 5 lines of <=512 bytes", len(capped))
	}
	if !strings.Contains(capped, "…") {
		t.Fatal("capped context does not mark the truncation")
	}
}

// Context is the unlimited form and must stay byte-identical to before.
func TestContextUnchangedWhenUncapped(t *testing.T) {
	content := []byte("one\ntwo\nthree\nfour\nfive\nsix\n")
	li := NewLineIndex(content)
	if got, want := li.Context(2, 2), li.ContextCapped(2, 2, 0); got != want {
		t.Fatalf("Context and uncapped ContextCapped differ:\n%q\n%q", got, want)
	}
	if got := li.Context(2, 2); got != "  one\n  two\n> three\n  four\n  five\n" {
		t.Fatalf("unexpected context: %q", got)
	}
}

// Truncation must land on a rune boundary; a mid-rune cut produced replacement
// characters in the middle of a security report.
func TestCapLineRespectsRuneBoundaries(t *testing.T) {
	s := strings.Repeat("é", 100)
	capped := CapLine(s, 51) // 51 is inside the 52nd rune
	if !utf8.ValidString(capped) {
		t.Fatalf("CapLine produced invalid UTF-8: %q", capped)
	}
	if !strings.HasSuffix(capped, "…") {
		t.Fatalf("CapLine did not mark truncation: %q", capped)
	}
	if len(capped) > 53 {
		t.Fatalf("CapLine exceeded its budget: %d bytes", len(capped))
	}

	wide := strings.Repeat("日", 100)
	if got := CapLine(wide, 10); !utf8.ValidString(got) {
		t.Fatalf("CapLine produced invalid UTF-8 for multi-byte runes: %q", got)
	}
	if CapLine("short", 0) != "short" {
		t.Fatal("a zero limit must mean unlimited")
	}
	within := "12345678"
	if CapLine(within, len(within)) != within {
		t.Fatal("a string exactly at the limit must be returned unchanged")
	}
}
