package report

import (
	"io"
	"os"
	"strings"
)

type ColorMode string

const (
	ColorAuto   ColorMode = "auto"
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

func ParseColorMode(s string) ColorMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ColorAlways):
		return ColorAlways
	case string(ColorNever):
		return ColorNever
	default:
		return ColorAuto
	}
}

func colorEnabled(mode ColorMode, w io.Writer) bool {
	switch mode {
	case ColorAlways:
		return true
	case ColorNever:
		return false
	}
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	t := strings.ToLower(os.Getenv("TERM"))
	if t == "dumb" || t == "" {
		return false
	}
	return isTerminal(w)
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiGray   = "\033[90m"
)

type palette struct{ enabled bool }

func (p palette) wrap(code, s string) string {
	if !p.enabled || s == "" {
		return s
	}
	return code + s + ansiReset
}

func (p palette) bold(s string) string       { return p.wrap(ansiBold, s) }
func (p palette) dim(s string) string        { return p.wrap(ansiDim, s) }
func (p palette) red(s string) string        { return p.wrap(ansiRed, s) }
func (p palette) green(s string) string      { return p.wrap(ansiGreen, s) }
func (p palette) yellow(s string) string     { return p.wrap(ansiYellow, s) }
func (p palette) cyan(s string) string       { return p.wrap(ansiCyan, s) }
func (p palette) gray(s string) string       { return p.wrap(ansiGray, s) }
func (p palette) boldRed(s string) string    { return p.wrap("\033[1;31m", s) }
func (p palette) boldYellow(s string) string { return p.wrap("\033[1;33m", s) }
