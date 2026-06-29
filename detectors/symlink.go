package detectors

import (
	"minesweep/filesystem"
	"minesweep/findings"
)

type SymlinkDetector struct{}

func NewSymlinkDetector() *SymlinkDetector {
	return &SymlinkDetector{}
}

func (d *SymlinkDetector) Name() string {
	return "symlink"
}

func (d *SymlinkDetector) Detect(file *filesystem.File) []findings.Finding {
	if !file.IsSymlink {
		return nil
	}

	var fResults []findings.Finding

	fResults = append(fResults, findings.Finding{
		Type:       "Symlink",
		Severity:   findings.SeverityInfo,
		Confidence: 1.0,
		File:       file.Path,
		Line:       1,
		Column:     1,
		Value:      file.SymlinkTarget,
		Reason:     "Symbolic link detected",
		RuleID:     "symlink-detected",
		Tags:       []string{"symlink", "filesystem"},
	})

	return fResults
}
