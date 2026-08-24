package detectors

import (
	"minesweep/filesystem"
	"minesweep/findings"
)

// maxMatchesPerPattern caps matches per pattern per file to avoid pathological
// memory use on large files with repetitive content.
const maxMatchesPerPattern = 10000

type Detector interface {
	Detect(file *filesystem.File) []findings.Finding
	Name() string
}
