package findings

import (
	"sort"
	"strconv"
)

type RiskReport struct {
	RiskScore    RiskScore       `yaml:"risk_score" json:"risk_score"`
	Summary      string          `yaml:"summary" json:"summary"`
	Findings     []Finding       `yaml:"findings" json:"findings"`
	Reasons      []string        `yaml:"reasons" json:"reasons"`
	SafeToShare  map[string]bool `yaml:"safe_to_share" json:"safe_to_share"`
	Boundaries   []string        `yaml:"boundaries" json:"boundaries"`
	FilesScanned int             `yaml:"files_scanned,omitempty" json:"files_scanned,omitempty"`
	DurationMs   int64           `yaml:"duration_ms,omitempty" json:"duration_ms,omitempty"`
}

func GenerateRiskReport(findings []Finding, boundaries []string) RiskReport {
	if len(findings) == 0 {
		return RiskReport{
			RiskScore:   RiskScoreNone,
			Summary:     "No secrets or sensitive data detected.",
			Findings:    nil,
			Reasons:     nil,
			SafeToShare: map[string]bool{},
			Boundaries:  boundaries,
		}
	}

	maxSeverity := SeverityInfo
	hasPrivateKey := false
	reasons := make(map[string]bool)
	typeCounts := make(map[string]int)
	criticalTypes := make(map[string]bool)

	for _, f := range findings {
		if f.Severity > maxSeverity {
			maxSeverity = f.Severity
		}
		typeCounts[f.Type]++
		if f.Severity >= SeverityCritical {
			criticalTypes[f.Type] = true
		}
		if f.Reason != "" {
			reasons[f.Reason] = true
		}
		for _, t := range f.Tags {
			if t == "private-key" {
				hasPrivateKey = true
			}
		}
	}

	riskScore := computeRiskScore(maxSeverity, hasPrivateKey)

	safeToShare := computeSafeToShare(riskScore)

	reasonList := make([]string, 0, len(reasons))
	for r := range reasons {
		reasonList = append(reasonList, r)
	}
	sort.Strings(reasonList)

	summary := buildSummary(riskScore, len(findings), typeCounts, criticalTypes)

	return RiskReport{
		RiskScore:   riskScore,
		Summary:     summary,
		Findings:    findings,
		Reasons:     reasonList,
		SafeToShare: safeToShare,
		Boundaries:  boundaries,
	}
}

func computeRiskScore(maxSev Severity, hasPrivateKey bool) RiskScore {
	switch {
	case maxSev >= SeverityCritical && hasPrivateKey:
		return RiskScoreCritical
	case maxSev >= SeverityCritical:
		return RiskScoreHigh
	case maxSev >= SeverityHigh:
		return RiskScoreHigh
	case maxSev >= SeverityMedium:
		return RiskScoreMedium
	case maxSev >= SeverityLow:
		return RiskScoreLow
	default:
		return RiskScoreNone
	}
}

func computeSafeToShare(score RiskScore) map[string]bool {
	m := map[string]bool{
		"public_github": false,
		"ai_context":    false,
		"email":         false,
		"ci_pipeline":   false,
	}
	if score <= RiskScoreLow {
		m["public_github"] = true
		m["ai_context"] = true
		m["ci_pipeline"] = true
	}
	if score <= RiskScoreMedium {
		m["email"] = true
	}
	return m
}

func buildSummary(score RiskScore, count int, typeCounts map[string]int, criticalTypes map[string]bool) string {
	if count == 0 {
		return "No secrets or sensitive data detected."
	}

	summary := "Risk Score: " + score.Label() + " (" + itoa(int(score)) + ")\n\n"
	summary += "Found " + formatCount(count, "finding") + " across " + formatCount(len(typeCounts), "type") + ".\n\n"

	if len(criticalTypes) > 0 {
		criticalList := make([]string, 0, len(criticalTypes))
		for t := range criticalTypes {
			criticalList = append(criticalList, t)
		}
		sort.Strings(criticalList)
		summary += "Critical items detected:\n"
		for _, t := range criticalList {
			summary += "  \u2022 " + t + "\n"
		}
		summary += "\n"
	}

	switch {
	case score >= RiskScoreCritical:
		summary += "Safe to share publicly? No.\nSafe to send to AI? No.\nThis file contains credentials that must be rotated and removed."
	case score >= RiskScoreHigh:
		summary += "Safe to share publicly? No.\nSafe to send to AI? No.\nReview findings before sharing this file."
	case score >= RiskScoreMedium:
		summary += "Safe to share publicly? Exercise caution.\nReview and redact sensitive values if needed."
	case score >= RiskScoreLow:
		summary += "Low risk. Verify findings before sharing."
	default:
		summary += "No issues detected."
	}

	return summary
}

func formatCount(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return itoa(n) + " " + noun + "s"
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
