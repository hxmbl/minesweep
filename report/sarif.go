package report

import (
	"encoding/json"
	"fmt"
	"io"

	"minesweep/findings"
)

type SARIFOutput struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	Rules          []SARIFRule `json:"rules,omitempty"`
	InformationURI string      `json:"informationUri"`
}

type SARIFRule struct {
	ID                   string       `json:"id"`
	Name                 string       `json:"name"`
	Description          SARIFMessage `json:"description"`
	HelpURI              string       `json:"helpUri,omitempty"`
	DefaultConfiguration SARIFConfig  `json:"defaultConfiguration"`
}

type SARIFConfig struct {
	Level string `json:"level"`
}

type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations"`
	RuleIndex *int            `json:"ruleIndex,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

func WriteSARIF(w io.Writer, report *findings.RiskReport, toolVersion string) error {
	rules := make(map[string]SARIFRule)
	var ruleList []SARIFRule

	for _, f := range report.Findings {
		if _, exists := rules[f.RuleID]; !exists {
			rule := SARIFRule{
				ID:          f.RuleID,
				Name:        f.Type,
				Description: SARIFMessage{Text: f.Reason},
				DefaultConfiguration: SARIFConfig{
					Level: severityToSARIFLevel(f.Severity),
				},
			}
			rules[f.RuleID] = rule
			ruleList = append(ruleList, rule)
		}
	}

	var sarifResults []SARIFResult
	for _, f := range report.Findings {
		idx := findRuleIndex(ruleList, f.RuleID)
		var ruleIdx *int
		if idx >= 0 {
			ruleIdx = &idx
		}
		result := SARIFResult{
			RuleID: f.RuleID,
			Level:  severityToSARIFLevel(f.Severity),
			Message: SARIFMessage{
				Text: fmt.Sprintf("%s: %s (confidence: %.0f%%)", f.Type, f.Reason, f.Confidence*findings.ConfidenceScale),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: f.File},
						Region: SARIFRegion{
							StartLine:   f.Line,
							StartColumn: f.Column,
						},
					},
				},
			},
			RuleIndex: ruleIdx,
		}
		sarifResults = append(sarifResults, result)
	}

	output := SARIFOutput{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "minesweep",
						Version:        toolVersion,
						Rules:          ruleList,
						InformationURI: "https://github.com/minesweep/minesweep",
					},
				},
				Results: sarifResults,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func severityToSARIFLevel(sev findings.Severity) string {
	switch sev {
	case findings.SeverityCritical, findings.SeverityHigh:
		return "error"
	case findings.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func findRuleIndex(rules []SARIFRule, ruleID string) int {
	for i, r := range rules {
		if r.ID == ruleID {
			return i
		}
	}
	return -1
}
