package detectors

import (
	"minesweep/filesystem"
	"minesweep/findings"
)

// DetectorFactory defines an interface for creating detectors
// This allows for dependency injection and mocking in tests
type DetectorFactory interface {
	Create(name string, config interface{}) (Detector, error)
}

// DefaultDetectorFactory is the default factory that creates real detectors
type DefaultDetectorFactory struct {
	rulesDir string
}

// Create creates a detector by name
func (f *DefaultDetectorFactory) Create(name string, config interface{}) (Detector, error) {
	switch name {
	case "regex":
		return NewRegexDetector(f.rulesDir)
	case "filetype":
		return NewFileTypeDetector(), nil
	case "symlink":
		return NewSymlinkDetector(), nil
	case "entropy":
		return NewEntropyDetector(), nil
	case "base64":
		return NewBase64Detector(f.rulesDir)
	case "database":
		return NewDatabaseDetector(), nil
	case "oauth":
		return NewOAuthDetector(), nil
	default:
		return nil, nil
	}
}

// DetectorConfig holds configuration for detectors
type DetectorConfig struct {
	RulesDir string
	// Add other configuration as needed
}

// NewDetectorFactory creates a new default detector factory
func NewDetectorFactory(rulesDir string) *DefaultDetectorFactory {
	return &DefaultDetectorFactory{
		rulesDir: rulesDir,
	}
}

// MockDetector is a mock detector for testing
type MockDetector struct {
	name       string
	findings   []findings.Finding
	shouldErr  bool
	err        error
}

// Detect implements the Detector interface
func (m *MockDetector) Detect(file *filesystem.File) []findings.Finding {
	if m.shouldErr {
		// In a real mock, you might want to return an error differently
		// For now, we just return the configured findings
	}
	return m.findings
}

// Name implements the Detector interface
func (m *MockDetector) Name() string {
	return m.name
}

// SetFindings sets the findings to return
func (m *MockDetector) SetFindings(findings []findings.Finding) {
	m.findings = findings
}

// SetError sets whether the detector should return an error
func (m *MockDetector) SetError(err error) {
	m.shouldErr = true
	m.err = err
}

// NewMockDetector creates a new mock detector
func NewMockDetector(name string) *MockDetector {
	return &MockDetector{
		name:     name,
		findings: []findings.Finding{},
	}
}
