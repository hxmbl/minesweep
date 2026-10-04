package findings

import (
	"fmt"
	"strconv"
	"strings"
)

// A gate has two axes and the CLI historically used one of them.
//
// --fail-on reads severity. Confidence was computed, displayed next to every
// finding, and then ignored when deciding the exit code — so a finding could
// block a commit while reporting that it was "60% confident" and the reader had
// no way to act on that.
//
// Adding a confidence floor to the gate by default is not the fix, for a reason
// this repository has already written down: a gate that silently does not gate
// is worse than one that gates too eagerly, because it is trusted. The same 0.60
// that makes `webhook_secret = "…"` in a README fence look like a sample also
// makes `password = "…"` in a config file look like one, and a threshold that
// unblocks the first blocks the second. There is no threshold that separates
// them, because the difference is not in the confidence value — it is in the
// surrounding grammar, and that belongs in the detector.
//
// So the second axis is available but not imposed. `--fail-on high@60%` reads
// "severity at least high AND confidence at least 60%"; `--fail-on high` is
// exactly what it always was. The default is unchanged, so no existing
// pipeline changes behaviour, and the compound form is self-documenting at the
// point of use.
//
// The low-confidence findings that the stricter form stops blocking are not
// silently dropped. They are reported, and the exit-code path names how many
// were held back and why, because a gate that says nothing about what it let
// through is the failure mode this is all trying to avoid.

// Gate is a parsed --fail-on value: a severity floor, and optionally a
// confidence floor.
type Gate struct {
	Severity Severity
	// MinConfidence is 0 when unset, which means "do not consider confidence".
	MinConfidence float64
}

// HasConfidenceFloor reports whether the gate constrains confidence.
func (g Gate) HasConfidenceFloor() bool { return g.MinConfidence > 0 }

// Passes reports whether f clears both axes.
func (g Gate) Passes(f Finding) bool {
	if f.Severity < g.Severity {
		return false
	}
	return !g.HasConfidenceFloor() || f.Confidence >= g.MinConfidence
}

// String renders the gate in the form it was written.
func (g Gate) String() string {
	s := g.Severity.String()
	if !g.HasConfidenceFloor() {
		return s
	}
	return s + "@" + formatConfidence(g.MinConfidence)
}

// ParseGate parses a --fail-on value: a severity, optionally followed by `@` and
// a confidence threshold written as `60%` or `0.6`.
//
// An error is returned rather than a silent fallback, because a mistyped gate is
// indistinguishable from a working one.
func ParseGate(s string) (Gate, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Gate{}, fmt.Errorf("empty gate")
	}

	sevPart, confPart, hasConf := strings.Cut(s, "@")
	sev := ParseSeverity(sevPart)
	if !IsValidSeverity(sevPart) {
		return Gate{}, fmt.Errorf("unknown severity %q", sevPart)
	}
	g := Gate{Severity: sev}
	if !hasConf {
		return g, nil
	}

	confPart = strings.TrimSpace(confPart)
	pct := strings.HasSuffix(confPart, "%")
	if pct {
		confPart = strings.TrimSpace(strings.TrimSuffix(confPart, "%"))
	}
	// A bare number is a percentage; a decimal is a fraction. `60%` and `0.6`
	// mean the same thing, and both spellings appear in the wild.
	if pct {
		n, err := strconv.ParseFloat(confPart, 64)
		if err != nil {
			return Gate{}, fmt.Errorf("invalid confidence %q", s)
		}
		g.MinConfidence = n / 100
	} else {
		n, err := strconv.ParseFloat(confPart, 64)
		if err != nil {
			return Gate{}, fmt.Errorf("invalid confidence %q", s)
		}
		g.MinConfidence = n
	}
	if g.MinConfidence < 0 || g.MinConfidence > 1 {
		return Gate{}, fmt.Errorf("confidence must be between 0%% and 100%%, got %v", g.MinConfidence*100)
	}
	return g, nil
}

// IsValidGate reports whether s is a gate this build understands.
func IsValidGate(s string) bool {
	_, err := ParseGate(s)
	return err == nil
}

// formatConfidence renders a fraction the way the report prints it.
func formatConfidence(c float64) string {
	return strconv.FormatFloat(c*ConfidenceScale, 'f', 0, 64) + "%"
}
