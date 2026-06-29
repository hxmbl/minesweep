package detectors

import (
	"minesweep/filesystem"
	"minesweep/findings"
)

type Detector interface {
	Detect(file *filesystem.File) []findings.Finding
	Name() string
}
