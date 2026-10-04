package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"minesweep/findings"
)

type SARIFOutput struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`
	Properties  *SARIFRunProps    `json:"properties,omitempty"`
}

// SARIFInvocation records whether the scan that produced this log completed.
//
// Without it a truncated scan is indistinguishable from a complete one in the
// uploaded artifact. The exit code carries the truth, but a consumer reading
// results.sarif — which is how code-scanning dashboards consume it — does not
// see it, and the repository's own workflow uploads that file with
// `continue-on-error: true` under `if: always()`.
type SARIFInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []SARIFNotification `json:"toolExecutionNotifications,omitempty"`
}

// SARIFNotification carries a reason the run was not a complete answer.
type SARIFNotification struct {
	Level   string       `json:"level"`
	Message SARIFMessage `json:"message"`
}

// SARIFRunProps carries counters that are not expressible as results.
type SARIFRunProps struct {
	ScanComplete       bool     `json:"scanComplete"`
	IncompleteReasons  []string `json:"incompleteReasons,omitempty"`
	FilesScanned       int      `json:"filesScanned,omitempty"`
	FilesFailed        int      `json:"filesFailed,omitempty"`
	FindingsSuppressed int      `json:"findingsSuppressed,omitempty"`
	FindingsDiscarded  int      `json:"findingsDiscarded,omitempty"`
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
	// The SARIF schema requires arrays (or absent keys); "null" is invalid
	// and gets rejected by consumers such as GitHub code scanning.
	rules := make(map[string]int)
	ruleList := []SARIFRule{}

	for _, f := range report.Findings {
		if _, exists := rules[f.RuleID]; !exists {
			rules[f.RuleID] = len(ruleList)
			ruleList = append(ruleList, SARIFRule{
				ID:          f.RuleID,
				Name:        f.Type,
				Description: SARIFMessage{Text: SanitizeTerminalInline(f.Reason)},
				DefaultConfiguration: SARIFConfig{
					Level: severityToSARIFLevel(f.Severity),
				},
			})
		}
	}

	sarifResults := []SARIFResult{}
	for _, f := range report.Findings {
		result := SARIFResult{
			RuleID: f.RuleID,
			Level:  severityToSARIFLevel(f.Severity),
			Message: SARIFMessage{
				Text: fmt.Sprintf("%s: %s (confidence: %.0f%%)", SanitizeTerminalInline(f.Type), SanitizeTerminalInline(f.Reason), f.Confidence*findings.ConfidenceScale),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: sarifURI(f.File)},
						Region: SARIFRegion{
							StartLine:   f.Line,
							StartColumn: f.Column,
						},
					},
				},
			},
		}
		if idx, ok := rules[f.RuleID]; ok {
			ruleIdx := idx
			result.RuleIndex = &ruleIdx
		}
		sarifResults = append(sarifResults, result)
	}

	invocation := SARIFInvocation{ExecutionSuccessful: !report.Incomplete}
	for _, reason := range report.IncompleteReasons {
		invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications,
			SARIFNotification{Level: "error", Message: SARIFMessage{Text: SanitizeTerminalInline(reason)}})
	}
	if report.Incomplete && len(invocation.ToolExecutionNotifications) == 0 {
		invocation.ToolExecutionNotifications = []SARIFNotification{{
			Level:   "error",
			Message: SARIFMessage{Text: "the scan did not cover the whole target; these results are partial"},
		}}
	}

	output := SARIFOutput{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "minesweep",
						Version:        toolVersion,
						Rules:          ruleList,
						InformationURI: informationURI,
					},
				},
				Results:     sarifResults,
				Invocations: []SARIFInvocation{invocation},
				Properties: &SARIFRunProps{
					ScanComplete:       !report.Incomplete,
					IncompleteReasons:  report.IncompleteReasons,
					FilesScanned:       report.FilesScanned,
					FilesFailed:        report.FilesFailed,
					FindingsSuppressed: report.FindingsSuppressed,
					FindingsDiscarded:  report.FindingsDiscarded,
				},
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

// informationURI is the project's repository. It previously pointed at a
// `minesweep/minesweep` path that does not exist.
const informationURI = "https://github.com/hxmbl/minesweep"

// sarifURI renders a finding path as a SARIF artifact URI.
//
// SARIF expects a URI relative to the scan root. Reported paths already are, but
// they are percent-encoded here so a path containing a space, a comma or a
// control character cannot be misread — and control characters are neutralised
// first, since the path comes from the scanned tree.
func sarifURI(path string) string {
	return (&url.URL{Path: SanitizeTerminalInline(path)}).EscapedPath()
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
