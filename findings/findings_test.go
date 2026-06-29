package findings

import (
	"fmt"
	"testing"
)

func TestSeverityParsing(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"info", SeverityInfo},
		{"low", SeverityLow},
		{"medium", SeverityMedium},
		{"high", SeverityHigh},
		{"critical", SeverityCritical},
		{"unknown", SeverityInfo},
	}
	for _, tt := range tests {
		got := ParseSeverity(tt.input)
		if got != tt.want {
			t.Errorf("ParseSeverity(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestRiskScore(t *testing.T) {
	tests := []struct {
		score RiskScore
		label string
	}{
		{RiskScoreNone, "none"},
		{RiskScoreLow, "low"},
		{RiskScoreMedium, "medium"},
		{RiskScoreHigh, "high"},
		{RiskScoreCritical, "critical"},
	}
	for _, tt := range tests {
		if got := tt.score.Label(); got != tt.label {
			t.Errorf("RiskScore(%d).Label() = %q, want %q", tt.score, got, tt.label)
		}
	}
}

func TestGenerateRiskReport(t *testing.T) {
	findings := []Finding{
		{
			Type:       "AWS Access Key ID",
			Severity:   SeverityCritical,
			Confidence: 0.95,
			File:       ".env",
			Value:      "AKIAIOSFODNN7EXAMPLE",
			Reason:     "test",
			Tags:       []string{"aws", "cloud", "credentials"},
		},
		{
			Type:       "SSH Private Key",
			Severity:   SeverityCritical,
			Confidence: 0.95,
			File:       "id_rsa",
			Value:      "-----BEGIN RSA PRIVATE KEY-----",
			Reason:     "test",
			Tags:       []string{"ssh", "credentials", "private-key"},
		},
	}

	report := GenerateRiskReport(findings, []string{"public-github"})
	if report.RiskScore != RiskScoreCritical {
		t.Fatalf("expected RiskScoreCritical (%d), got %d", RiskScoreCritical, report.RiskScore)
	}
	if report.SafeToShare["public_github"] {
		t.Fatal("expected not safe for public github")
	}
}

func TestRedactValue(t *testing.T) {
	got := RedactValue("sk-abc123", "OpenAI API Key")
	want := "<REDACTED: OpenAI API Key>"
	if got != want {
		t.Fatalf("RedactValue() = %q, want %q", got, want)
	}
}

// ─── Brutal findings tests ──────────────────────────────────────────

func TestGenerateRiskReportEmpty(t *testing.T) {
	report := GenerateRiskReport(nil, nil)
	if report.RiskScore != RiskScoreNone {
		t.Fatal("expected RiskScoreNone for nil findings")
	}
	if len(report.Findings) != 0 {
		t.Fatal("expected 0 findings for nil input")
	}

	report = GenerateRiskReport([]Finding{}, nil)
	if report.RiskScore != RiskScoreNone {
		t.Fatal("expected RiskScoreNone for empty findings")
	}
}

func TestGenerateRiskReportManyDuplicates(t *testing.T) {
	var fs []Finding
	for i := 0; i < 1000; i++ {
		fs = append(fs, Finding{
			Type:       "Generic API Key",
			Severity:   SeverityMedium,
			Confidence: 0.30,
			File:       fmt.Sprintf("file_%d.txt", i),
			Line:       1,
			Reason:     "low confidence test",
			Tags:       []string{"api-key"},
		})
	}
	report := GenerateRiskReport(fs, []string{"public-github", "ai-context"})
	if report.RiskScore != RiskScoreMedium {
		t.Fatalf("expected RiskScoreMedium for medium severity findings, got %d", report.RiskScore)
	}
	if len(report.Findings) != 1000 {
		t.Fatalf("expected 1000 findings, got %d", len(report.Findings))
	}
	if report.SafeToShare["public_github"] {
		t.Fatal("medium risk should not be safe for public github")
	}
}

func TestGenerateRiskReportMixedSeverities(t *testing.T) {
	fs := []Finding{
		{Type: "Info Item", Severity: SeverityInfo, Tags: []string{"info"}},
		{Type: "Low Item", Severity: SeverityLow, Tags: []string{"low"}},
		{Type: "Medium Item", Severity: SeverityMedium, Tags: []string{"medium"}},
		{Type: "High Item", Severity: SeverityHigh, Tags: []string{"high"}},
		{Type: "Critical Item", Severity: SeverityCritical, Tags: []string{"critical"}},
	}
	report := GenerateRiskReport(fs, nil)
	// Highest severity is Critical → RiskScoreHigh (no production creds or private key)
	if report.RiskScore != RiskScoreHigh {
		t.Fatalf("expected RiskScoreHigh for critical finding without production tags, got %d", report.RiskScore)
	}
	if len(report.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(report.Findings))
	}
}

func TestSeverityComparisons(t *testing.T) {
	if SeverityInfo >= SeverityLow {
		t.Fatal("Info < Low expected")
	}
	if SeverityLow >= SeverityMedium {
		t.Fatal("Low < Medium expected")
	}
	if SeverityMedium >= SeverityHigh {
		t.Fatal("Medium < High expected")
	}
	if SeverityHigh >= SeverityCritical {
		t.Fatal("High < Critical expected")
	}
	if SeverityCritical <= SeverityHigh {
		t.Fatal("Critical > High expected")
	}
}

func TestParseSeverityEdgeCases(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"info", SeverityInfo},
		{"critical", SeverityCritical},
		{"", SeverityInfo},
		{"garbage", SeverityInfo},
		{"CRITICAL!", SeverityInfo},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseSeverity(tt.input); got != tt.want {
				t.Errorf("ParseSeverity(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestRiskScoreEdgeCases(t *testing.T) {
	tests := []struct {
		score RiskScore
		label string
	}{
		{RiskScore(-1), "none"},
		{RiskScore(0), "none"},
		{RiskScore(1), "none"},
		{RiskScore(24), "none"},
		{RiskScore(25), "low"},
		{RiskScore(49), "low"},
		{RiskScore(50), "medium"},
		{RiskScore(74), "medium"},
		{RiskScore(75), "high"},
		{RiskScore(99), "high"},
		{RiskScore(100), "critical"},
		{RiskScore(999), "critical"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.score), func(t *testing.T) {
			if got := tt.score.Label(); got != tt.label {
				t.Errorf("RiskScore(%d).Label() = %q, want %q", tt.score, got, tt.label)
			}
		})
	}
}
