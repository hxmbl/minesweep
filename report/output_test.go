package report

import (
	"bytes"
	"strings"
	"testing"

	"minesweep/findings"
)

func sampleReport() findings.RiskReport {
	return findings.GenerateRiskReport([]findings.Finding{
		{
			Type:       "AWS Access Key ID",
			Severity:   findings.SeverityCritical,
			Confidence: 0.95,
			File:       ".env",
			Line:       5,
			Value:      "AKIAIOSFODNN7EXAMPLE",
			RuleID:     "aws-access-key-id",
			Action:     findings.ActionBlock,
			Tags:       []string{"aws", "cloud", "credentials"},
		},
		{
			Type:       "Generic Password",
			Severity:   findings.SeverityMedium,
			Confidence: 0.70,
			File:       "config.yml",
			Line:       10,
			RuleID:     "generic-password",
			Action:     findings.ActionWarn,
			Tags:       []string{"credentials", "password"},
		},
	}, nil)
}

func TestWriteTextGroupsBySeverity(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	if err := WriteText(&buf, &report, TextOptions{}); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	out := buf.String()

	critIdx := strings.Index(out, "CRITICAL")
	medIdx := strings.Index(out, "MEDIUM")
	if critIdx == -1 || medIdx == -1 {
		t.Fatalf("expected severity section headers, got:\n%s", out)
	}
	if critIdx > medIdx {
		t.Error("critical section should precede medium")
	}
	if !strings.Contains(out, "1 critical") || !strings.Contains(out, "1 medium") {
		t.Errorf("expected counts line with per-severity totals, got:\n%s", out)
	}
}

func TestWriteTextNextStepsDefaults(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{})
	out := buf.String()
	if !strings.Contains(out, "Next steps") {
		t.Fatalf("expected next steps section, got:\n%s", out)
	}
	if !strings.Contains(out, "-v") {
		t.Error("expected default verbose hint")
	}
}

func TestWriteTextCustomHints(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{Hints: []string{"custom hint here"}})
	if !strings.Contains(buf.String(), "custom hint here") {
		t.Fatal("expected custom hint in output")
	}
}

func TestWriteTextNoColorByDefaultForBuffers(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{})
	if strings.Contains(buf.String(), "\033[") {
		t.Fatal("expected no ANSI escapes when writing to a non-terminal buffer")
	}
}

func TestWriteTextColorAlways(t *testing.T) {
	report := sampleReport()
	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{Color: ColorAlways})
	if !strings.Contains(buf.String(), "\033[") {
		t.Fatal("expected ANSI escapes with ColorAlways")
	}
}

func TestWriteTextVerboseShowsValueAndContext(t *testing.T) {
	rep := findings.GenerateRiskReport([]findings.Finding{
		{
			Type:     "JWT",
			Severity: findings.SeverityHigh,
			Value:    "eyJhbGciOiJIUzI1NiJ9",
			Context:  "line one\nline two",
			File:     "a.txt",
			Line:     1,
			Action:   findings.ActionBlock,
			RuleID:   "jwt-encoded",
			Tags:     []string{"jwt"},
		},
	}, nil)

	var buf bytes.Buffer
	WriteText(&buf, &rep, TextOptions{Verbose: true})
	out := buf.String()
	if !strings.Contains(out, "eyJhbGciOiJIUzI1NiJ9") {
		t.Error("expected value in verbose output")
	}
	if !strings.Contains(out, "Context:") {
		t.Error("expected context block in verbose output")
	}

	var quiet bytes.Buffer
	WriteText(&quiet, &rep, TextOptions{})
	if strings.Contains(quiet.String(), "eyJ") {
		t.Error("value should be hidden by default")
	}
}

func TestWriteTextCleanScanShowsStats(t *testing.T) {
	report := findings.RiskReport{
		RiskScore:    findings.RiskScoreNone,
		Summary:      "No secrets or sensitive data detected.",
		SafeToShare:  map[string]bool{},
		FilesScanned: 42,
		DurationMs:   800,
	}
	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{})
	out := buf.String()
	if !strings.Contains(out, "42 files") {
		t.Errorf("expected file count in clean output, got:\n%s", out)
	}
	if !strings.Contains(out, "0.8s") {
		t.Errorf("expected duration in clean output, got:\n%s", out)
	}
}
