package report

import (
	"bytes"
	"os"
	"testing"
)

func TestParseColorMode(t *testing.T) {
	cases := []struct {
		in   string
		want ColorMode
	}{
		{"", ColorAuto},
		{"auto", ColorAuto},
		{"always", ColorAlways},
		{"never", ColorNever},
		{"ALWAYS", ColorAlways},
		{"  never ", ColorNever},
		{"garbage", ColorAuto},
	}
	for _, c := range cases {
		if got := ParseColorMode(c.in); got != c.want {
			t.Errorf("ParseColorMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestColorEnabledModes(t *testing.T) {
	var buf bytes.Buffer
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")

	if !colorEnabled(ColorAlways, &buf) {
		t.Error("always should enable color even with NO_COLOR")
	}
	if colorEnabled(ColorNever, &buf) {
		t.Error("never should disable color unconditionally")
	}
	if colorEnabled(ColorAuto, &buf) {
		t.Error("auto should respect NO_COLOR")
	}
}

func TestColorEnabledNoTerm(t *testing.T) {
	var buf bytes.Buffer
	os.Unsetenv("NO_COLOR")
	t.Setenv("TERM", "dumb")
	if colorEnabled(ColorAuto, &buf) {
		t.Error("dumb terminal should disable color in auto mode")
	}
}

func TestColorDisabledForNonTTY(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm-256color")
	var buf bytes.Buffer
	if colorEnabled(ColorAuto, &buf) {
		t.Error("buffer is not a terminal; auto should disable color")
	}
}

func TestPaletteWrapping(t *testing.T) {
	on := palette{enabled: true}
	off := palette{enabled: false}

	if got := on.red("x"); got != ansiRed+"x"+ansiReset {
		t.Errorf("on.red = %q", got)
	}
	if got := off.red("x"); got != "x" {
		t.Errorf("off.red should be passthrough, got %q", got)
	}
	if got := on.bold(""); got != "" {
		t.Errorf("empty string should not be wrapped, got %q", got)
	}
}
