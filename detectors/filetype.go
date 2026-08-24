package detectors

import (
	"minesweep/filesystem"
	"minesweep/findings"
)

type FileTypeDetector struct{}

func NewFileTypeDetector() *FileTypeDetector {
	return &FileTypeDetector{}
}

func (d *FileTypeDetector) Name() string {
	return "filetype"
}

func (d *FileTypeDetector) Detect(file *filesystem.File) []findings.Finding {
	var fResults []findings.Finding

	// IsBinary is computed during content load; touch the content so this
	// detector is correct no matter which order detectors run in. The call
	// is cheap once any other detector has loaded the file.
	_, _ = file.GetContent()

	if file.IsBinary {
		fResults = append(fResults, findings.Finding{
			Type:       "Binary File",
			Severity:   findings.SeverityInfo,
			Confidence: 1.0,
			File:       file.Path,
			Line:       1,
			Column:     1,
			Reason:     "Binary file detected",
			RuleID:     "binary-file-detected",
			Tags:       []string{"filetype", "binary"},
		})
	}

	if file.IsExecutable() {
		fResults = append(fResults, findings.Finding{
			Type:       "Executable File",
			Severity:   findings.SeverityInfo,
			Confidence: 1.0,
			File:       file.Path,
			Line:       1,
			Column:     1,
			Reason:     "Executable file detected",
			RuleID:     "executable-file-detected",
			Tags:       []string{"filetype", "executable"},
		})
	}

	return fResults
}
