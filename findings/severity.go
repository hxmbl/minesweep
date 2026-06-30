package findings

type Severity int

const (
	SeverityInfo     Severity = 1
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

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
	switch s {
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

type Action string

const (
	ActionAllow  Action = "allow"
	ActionRedact Action = "redact"
	ActionWarn   Action = "warn"
	ActionBlock  Action = "block"
)

type RiskScore int

const (
	RiskScoreNone     RiskScore = 0
	RiskScoreLow      RiskScore = 25
	RiskScoreMedium   RiskScore = 50
	RiskScoreHigh     RiskScore = 75
	RiskScoreCritical RiskScore = 100
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
