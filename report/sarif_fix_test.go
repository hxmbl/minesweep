package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"minesweep/findings"
)

func TestSARIFCleanReportEmitsEmptyArrays(t *testing.T) {
	report := findings.GenerateRiskReport(nil, nil)

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, &report, "test"); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var parsed struct {
		Runs []struct {
			Results *[]json.RawMessage `json:"results"`
			Tool    struct {
				Driver struct {
					Rules *[]json.RawMessage `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	raw := buf.String()
	if bytes.Contains(buf.Bytes(), []byte(`"results": null`)) {
		t.Fatalf("SARIF must not emit results:null (schema-invalid):\n%s", raw)
	}
	if bytes.Contains(buf.Bytes(), []byte(`"rules": null`)) {
		t.Fatalf("SARIF must not emit rules:null (schema-invalid):\n%s", raw)
	}
}

func TestSARIFRuleIndexPresent(t *testing.T) {
	report := findings.GenerateRiskReport([]findings.Finding{
		{Type: "T", RuleID: "rule-b", Severity: findings.SeverityHigh},
	}, nil)

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, &report, "test"); err != nil {
		t.Fatal(err)
	}

	var parsed struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}

	res := parsed.Runs[0].Results[0]
	if res.RuleID != "rule-b" || res.RuleIndex != 0 {
		t.Errorf("ruleIndex not wired correctly: %+v", res)
	}
}
