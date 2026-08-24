// Package minesweep holds the embedded default assets (detection rules,
// default policy, and policy profiles) so the compiled binary works without
// an on-disk checkout. Disk directories take precedence when present.
package minesweep

import "embed"

//go:embed rules policy profiles
var Assets embed.FS
