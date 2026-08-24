package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"minesweep/findings"
)

func TestWriteText(t *testing.T) {
	report := findings.GenerateRiskReport([]findings.Finding{
		{
			Type:       "AWS Access Key ID",
			Severity:   findings.SeverityCritical,
			Confidence: 0.95,
			File:       ".env",
			Line:       1,
			Value:      "AKIAIOSFODNN7EXAMPLE",
			Reason:     "test",
			RuleID:     "aws-access-key-id",
			Tags:       []string{"aws", "cloud", "credentials"},
		},
	}, nil)

	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{})
	output := buf.String()
	if !strings.Contains(output, "AWS Access Key ID") {
		t.Fatal("expected finding in output")
	}
	if !strings.Contains(output, "Risk score") {
		t.Fatal("expected risk score in output")
	}
	if !strings.Contains(output, "Rotate this key") {
		t.Fatal("expected remediation hint in output")
	}
}

// ─── Brutal report tests ────────────────────────────────────────────

func TestWriteTextEmptyReport(t *testing.T) {
	report := findings.GenerateRiskReport(nil, nil)

	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{})
	output := buf.String()
	if !strings.Contains(output, "No secrets or sensitive data detected.") {
		t.Fatal("expected clean summary in empty report")
	}
}

func TestWriteTextVerbose(t *testing.T) {
	report := findings.GenerateRiskReport([]findings.Finding{
		{
			Type:       "Test Key",
			Severity:   findings.SeverityHigh,
			Confidence: 0.95,
			File:       "test.txt",
			Line:       1,
			Column:     5,
			Value:      "short_value",
			Reason:     "test finding",
			Tags:       []string{"test"},
		},
	}, nil)

	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{Verbose: true})
	output := buf.String()
	if !strings.Contains(output, "short_value") {
		t.Fatal("expected value in verbose output")
	}
}

func TestWriteTextVeryLongValue(t *testing.T) {
	longValue := strings.Repeat("A", 200)
	report := findings.GenerateRiskReport([]findings.Finding{
		{
			Type:       "Long Value",
			Severity:   findings.SeverityMedium,
			Confidence: 0.50,
			File:       "big.txt",
			Line:       1,
			Value:      longValue,
			Reason:     "very long value test",
			Tags:       []string{"test"},
		},
	}, nil)

	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{Verbose: true})
	output := buf.String()
	// The value should be truncated to ~60 chars in verbose output
	if strings.Contains(output, longValue) {
		t.Fatal("expected long value to be truncated")
	}
	if !strings.Contains(output, "...") {
		t.Fatal("expected truncation marker in output")
	}
}

func TestWriteTextManyFindings(t *testing.T) {
	var fs []findings.Finding
	for i := 0; i < 100; i++ {
		fs = append(fs, findings.Finding{
			Type:       fmt.Sprintf("Finding %d", i),
			Severity:   findings.SeverityLow,
			Confidence: 0.50,
			File:       fmt.Sprintf("file_%d.txt", i),
			Line:       1,
			Reason:     "mass test",
			Tags:       []string{"mass"},
		})
	}
	report := findings.GenerateRiskReport(fs, nil)

	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{})
	output := buf.String()
	if !strings.Contains(output, "Finding 0") {
		t.Fatal("expected first finding in output")
	}
	if !strings.Contains(output, "Finding 99") {
		t.Fatal("expected last finding in output")
	}
}

func TestWriteTextMultipleReasons(t *testing.T) {
	report := findings.GenerateRiskReport([]findings.Finding{
		{
			Type:     "Type A",
			Severity: findings.SeverityHigh,
			Reason:   "Reason A",
			Tags:     []string{"a"},
		},
		{
			Type:     "Type B",
			Severity: findings.SeverityHigh,
			Reason:   "Reason B",
			Tags:     []string{"b"},
		},
	}, nil)

	var buf bytes.Buffer
	WriteText(&buf, &report, TextOptions{Verbose: true})
	output := buf.String()
	if !strings.Contains(output, "Risk factors") {
		t.Fatal("expected risk factors section with multiple reasons")
	}
}

func TestWriteJSONEmptyReport(t *testing.T) {
	report := findings.GenerateRiskReport(nil, nil)

	var buf bytes.Buffer
	err := WriteJSON(&buf, &report)
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, `"risk_score"`) {
		t.Fatal("expected JSON output for empty report")
	}
	if strings.Contains(output, `"findings"`) && !strings.Contains(output, `"findings": null`) {
		t.Fatal("expected findings to be null or empty for empty report")
	}
}

func TestWriteJSON(t *testing.T) {
	report := findings.GenerateRiskReport([]findings.Finding{
		{
			Type:       "Test",
			Severity:   findings.SeverityHigh,
			Confidence: 0.9,
			File:       "test.txt",
			Line:       1,
			Reason:     "test finding",
		},
	}, nil)

	var buf bytes.Buffer
	err := WriteJSON(&buf, &report)
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, `"risk_score"`) {
		t.Fatal("expected JSON output")
	}
	if !strings.Contains(output, "Test") {
		t.Fatal("expected finding type in JSON")
	}
}
