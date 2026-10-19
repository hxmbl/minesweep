package findings

import (
	"strings"
)

type Severity int

const (
	SeverityInfo     Severity = 1
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

const ConfidenceScale = 100.0

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityInfo
	}
}

// IsValidSeverity reports whether s names a known severity level
// (case-insensitive). Use it to reject typos instead of silently falling back.
func IsValidSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

type Action string

const (
	ActionAllow  Action = "allow"
	ActionRedact Action = "redact"
	ActionWarn   Action = "warn"
	ActionBlock  Action = "block"
)

// RiskScore is a 0-100 risk estimate for a scan. The constants name the lower
// bound of each band; they are thresholds, not the only values a score takes.
// computeRiskScore produces a continuous score, so a scan can read 83/100
// ("high") as easily as 75/100, and the bands are reachable rather than being
// fixed rungs the score snaps to.
type RiskScore int

const (
	RiskScoreNone     RiskScore = 0
	RiskScoreLow      RiskScore = 20
	RiskScoreMedium   RiskScore = 45
	RiskScoreHigh     RiskScore = 68
	RiskScoreCritical RiskScore = 85
)

func (r RiskScore) String() string {
	switch {
	case r >= RiskScoreCritical:
		return "critical"
	case r >= RiskScoreHigh:
		return "high"
	case r >= RiskScoreMedium:
		return "medium"
	case r >= RiskScoreLow:
		return "low"
	default:
		return "none"
	}
}

func (r RiskScore) Label() string {
	return r.String()
}

func RedactValue(value string, ruleName string) string {
	return "<REDACTED>"
}
