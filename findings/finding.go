package findings

import "fmt"

// BinaryEvidence is the Context/SourceLine value used in place of raw content
// for a finding in a file that was classified as binary.
//
// Binary content cannot be meaningfully redacted: the censoring heuristics work
// on credential-shaped text and pass arbitrary bytes straight through, which
// meant a SQLite database or any other undetected binary format put its entire
// first "line" — and therefore its credentials — into the report verbatim.
// Withholding the bytes is the only guarantee that holds for every format.
func BinaryEvidence(size int) string {
	if size <= 0 {
		return "<binary content withheld: size unknown>"
	}
	return fmt.Sprintf("<binary content withheld: %d bytes>", size)
}

// TruncatedEvidenceSuffix marks evidence that was clipped at the per-line
// ceiling. A file with no newlines at all (many database and archive formats)
// otherwise put an arbitrarily large line into every finding.
const TruncatedEvidenceSuffix = "… (line truncated)"

type Finding struct {
	Type       string   `yaml:"type" json:"type"`
	Severity   Severity `yaml:"severity" json:"severity"`
	Confidence float64  `yaml:"confidence" json:"confidence"`
	File       string   `yaml:"file" json:"file"`
	Line       int      `yaml:"line" json:"line"`
	Column     int      `yaml:"column" json:"column"`
	Value      string   `yaml:"value,omitempty" json:"value,omitempty"`
	Reason     string   `yaml:"reason" json:"reason"`
	RuleID     string   `yaml:"rule_id" json:"rule_id"`
	Tags       []string `yaml:"tags" json:"tags"`
	Action     Action   `yaml:"action" json:"action"`
	Context    string   `yaml:"context,omitempty" json:"context,omitempty"`
	SourceLine string   `yaml:"source_line,omitempty" json:"source_line,omitempty"`
	// History attribution (populated only in --history mode).
	Commit        string `yaml:"commit,omitempty" json:"commit,omitempty"`
	Author        string `yaml:"author,omitempty" json:"author,omitempty"`
	Date          string `yaml:"date,omitempty" json:"date,omitempty"`
	CommitSummary string `yaml:"commit_summary,omitempty" json:"commit_summary,omitempty"`
}
