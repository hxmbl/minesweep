package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"minesweep/findings"
)

func TestWriteSARIFEmptyReport(t *testing.T) {
	report := findings.GenerateRiskReport(nil, nil)
	var buf bytes.Buffer
	err := WriteSARIF(&buf, &report, "0.1.0")
	if err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc SARIFOutput
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %s", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(doc.Runs[0].Results))
	}
}

func TestWriteSARIFWithFindings(t *testing.T) {
	report := findings.GenerateRiskReport([]findings.Finding{
		{
			Type:       "AWS Access Key ID",
			Severity:   findings.SeverityCritical,
			Confidence: 0.95,
			File:       ".env",
			Line:       5,
			Column:     16,
			Value:      "AKIAIOSFODNN7EXAMPLE",
			Reason:     "high-entropy credential",
			RuleID:     "aws-access-key",
			Tags:       []string{"aws", "cloud"},
		},
		{
			Type:       "Generic Password",
			Severity:   findings.SeverityMedium,
			Confidence: 0.70,
			File:       "config.yml",
			Line:       10,
			Value:      "password123",
			Reason:     "password pattern",
			RuleID:     "generic-password",
			Tags:       []string{"password"},
		},
	}, nil)

	var buf bytes.Buffer
	err := WriteSARIF(&buf, &report, "0.1.0")
	if err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc SARIFOutput
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	run := doc.Runs[0]
	if len(run.Results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}

	r := run.Results[0]
	if r.RuleID != "aws-access-key" {
		t.Errorf("expected rule ID aws-access-key, got %s", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("expected level error, got %s", r.Level)
	}
	if len(r.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(r.Locations))
	}
	loc := r.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != ".env" {
		t.Errorf("expected URI .env, got %s", loc.ArtifactLocation.URI)
	}
	if loc.Region.StartLine != 5 {
		t.Errorf("expected start line 5, got %d", loc.Region.StartLine)
	}
	if loc.Region.StartColumn != 16 {
		t.Errorf("expected start column 16, got %d", loc.Region.StartColumn)
	}
}

func TestWriteSARIFSeverityMapping(t *testing.T) {
	tests := []struct {
		severity findings.Severity
		want     string
	}{
		{findings.SeverityCritical, "error"},
		{findings.SeverityHigh, "error"},
		{findings.SeverityMedium, "warning"},
		{findings.SeverityLow, "note"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("severity_%d", tt.severity), func(t *testing.T) {
			report := findings.GenerateRiskReport([]findings.Finding{
				{
					Type:     "Test",
					Severity: tt.severity,
					File:     "x",
					RuleID:   "test-rule",
					Tags:     []string{"test"},
				},
			}, nil)

			var buf bytes.Buffer
			WriteSARIF(&buf, &report, "0.1.0")

			var doc SARIFOutput
			json.Unmarshal(buf.Bytes(), &doc)

			got := doc.Runs[0].Results[0].Level
			if got != tt.want {
				t.Errorf("severity %d -> level %s, want %s", tt.severity, got, tt.want)
			}
		})
	}
}

func TestWriteSARIFValidJSON(t *testing.T) {
	report := findings.GenerateRiskReport([]findings.Finding{
		{
			Type:       "Test",
			Severity:   findings.SeverityHigh,
			Confidence: 0.9,
			File:       "test.txt",
			Line:       1,
			Value:      "secret",
			Reason:     "test",
			RuleID:     "test-rule",
			Tags:       []string{"test"},
		},
	}, nil)

	var buf bytes.Buffer
	WriteSARIF(&buf, &report, "0.1.0")

	if !json.Valid(buf.Bytes()) {
		t.Fatal("SARIF output is not valid JSON")
	}
}

func TestWriteSARIFSourceLine(t *testing.T) {
	report := findings.GenerateRiskReport([]findings.Finding{
		{
			Type:       "Test",
			Severity:   findings.SeverityHigh,
			Confidence: 0.9,
			File:       "test.txt",
			Line:       5,
			SourceLine: "password = hunter2",
			Value:      "hunter2",
			Reason:     "test",
			RuleID:     "test-rule",
			Tags:       []string{"test"},
		},
	}, nil)

	var buf bytes.Buffer
	err := WriteSARIF(&buf, &report, "0.1.0")
	if err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var doc SARIFOutput
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	// Verify finding metadata is present
	r := doc.Runs[0].Results[0]
	if r.RuleID != "test-rule" {
		t.Errorf("expected rule ID test-rule, got %s", r.RuleID)
	}
	if r.Level != "error" {
		t.Errorf("expected level error, got %s", r.Level)
	}
}

func TestWriteSARIFMetadata(t *testing.T) {
	report := findings.GenerateRiskReport(nil, nil)
	var buf bytes.Buffer
	WriteSARIF(&buf, &report, "0.1.0")

	var doc SARIFOutput
	json.Unmarshal(buf.Bytes(), &doc)

	run := doc.Runs[0]
	if run.Tool.Driver.Name != "minesweep" {
		t.Errorf("expected tool name minesweep, got %s", run.Tool.Driver.Name)
	}
	if !strings.Contains(run.Tool.Driver.Version, "0.1.0") {
		t.Errorf("expected version 0.1.0, got %s", run.Tool.Driver.Version)
	}
}
