package findings

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
}
