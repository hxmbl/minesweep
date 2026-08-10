package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	"minesweep/detectors"
	"minesweep/filesystem"
	"minesweep/findings"
	"minesweep/policy"
)

type Config struct {
	RulesDir                 string
	ProfilesDir              string
	PolicyDir                string
	Profile                  string
	PolicyFile               string
	Verbose                  bool
	Boundaries               []string
	SkipExtensions           []string
	FailOn                   string
	MinConfidence            float64
	DiffMode                 bool
	DiffBase                 string
	StagedOnly               bool
	BaselineFile             string
	UpdateBaseline           bool
	MinSeverity              string
	Tags                     []string
	Workers                  int
	SuppressFile             string
	IncludeTestFiles         bool
	DisableInlineSuppression bool
	// Resource limits
	MaxFiles       int   // Maximum number of files to scan (0 = unlimited)
	MemoryLimitMB   int   // Maximum memory usage in MB (0 = unlimited)
	MaxFileSizeMB   int64 // Maximum file size in MB to scan (0 = use default)
	// Concurrency limits
	MaxConcurrentReads int // Maximum concurrent file reads (0 = use Workers)
}

type Engine struct {
	config    Config
	detectors []detectors.Detector
	policies  []policy.PolicyRule
	// Semaphore for limiting concurrent file reads
	readSemaphore chan struct{}
}

func New(cfg Config) (*Engine, error) {
	if cfg.RulesDir == "" {
		cfg.RulesDir = "rules"
	}
	if cfg.ProfilesDir == "" {
		cfg.ProfilesDir = "profiles"
	}
	if cfg.PolicyDir == "" {
		cfg.PolicyDir = "policy"
	}

	regexDetector, err := detectors.NewRegexDetector(cfg.RulesDir)
	if err != nil {
		return nil, fmt.Errorf("load regex detector: %w", err)
	}

	detList := []detectors.Detector{
		regexDetector,
		detectors.NewFileTypeDetector(),
		detectors.NewSymlinkDetector(),
		detectors.NewEntropyDetector(),
		detectors.NewBase64Detector(cfg.RulesDir),
		detectors.NewDatabaseDetector(),
		detectors.NewOAuthDetector(),
	}

	var policies []policy.PolicyRule
	switch {
	case cfg.Profile != "":
		if cfg.PolicyFile != "" {
			fmt.Fprintf(os.Stderr, "warning: both --profile and --policy set; --profile (%q) takes precedence\n", cfg.Profile)
		}
		policies, err = policy.ResolveProfile(cfg.ProfilesDir, cfg.Profile)
		if err != nil {
			return nil, fmt.Errorf("resolve profile %q: %w", cfg.Profile, err)
		}
	case cfg.PolicyFile != "":
		policies, err = policy.LoadPolicyFile(cfg.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("load policy file: %w", err)
		}
	default:
		defaultPath := filepath.Join(cfg.PolicyDir, "default.yml")
		policies, err = policy.LoadPolicyFile(defaultPath)
		if err != nil {
			return nil, fmt.Errorf("load default policy: %w", err)
		}
	}

	// Initialize semaphore for concurrent reads
	maxReads := cfg.MaxConcurrentReads
	if maxReads <= 0 {
		maxReads = cfg.Workers
	}
	if maxReads <= 0 {
		maxReads = runtime.NumCPU()
	}
	if maxReads < 1 {
		maxReads = 1
	}
	
	return &Engine{
		config:        cfg,
		detectors:     detList,
		policies:      policies,
		readSemaphore: make(chan struct{}, maxReads),
	}, nil
}


// applyBaseline applies baseline filtering to a report
func (e *Engine) applyBaseline(report *findings.RiskReport) (*findings.RiskReport, error) {
	if e.config.BaselineFile == "" || report == nil {
		return report, nil
	}
	baseline, err := findings.LoadBaseline(e.config.BaselineFile)
	if err != nil {
		return nil, fmt.Errorf("load baseline: %w", err)
	}
	if report.Findings == nil {
		report.Findings = []findings.Finding{}
	}
	newFindings := findings.FilterNewFindings(report.Findings, baseline)
	if newFindings == nil {
		newFindings = []findings.Finding{}
	}
	report.Findings = newFindings
	newReport := findings.GenerateRiskReport(newFindings, e.config.Boundaries)
	return &newReport, nil
}

// applySuppressions applies suppression filtering to a report
func (e *Engine) applySuppressions(report *findings.RiskReport) (*findings.RiskReport, error) {
	if e.config.SuppressFile == "" || report == nil {
		return report, nil
	}
	suppressions, err := findings.LoadSuppressions(e.config.SuppressFile)
	if err != nil {
		return nil, fmt.Errorf("load suppressions: %w", err)
	}
	if report.Findings == nil {
		report.Findings = []findings.Finding{}
	}
	filtered := findings.FilterSuppressed(report.Findings, suppressions)
	if filtered == nil {
		filtered = []findings.Finding{}
	}
	report.Findings = filtered
	newReport := findings.GenerateRiskReport(filtered, e.config.Boundaries)
	return &newReport, nil
}

// updateBaseline updates the baseline file with new findings
func (e *Engine) updateBaseline(baseline *findings.Baseline, newFindings []findings.Finding) error {
	if !e.config.UpdateBaseline {
		return nil
	}
	findings.UpdateBaseline(baseline, newFindings)
	return findings.SaveBaseline(e.config.BaselineFile, baseline)
}
func (e *Engine) Run(path string) (*findings.RiskReport, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat path: %w", err)
	}

	if !info.IsDir() {
		return e.runSingleFile(path)
	}

	if e.config.DiffMode || e.config.StagedOnly {
		return e.runDiff(path)
	}

	report, err := e.runDirectory(path)
	if err != nil {
		return nil, err
	}

	if report == nil {
		return nil, nil
	}

	report, err = e.applyBaseline(report)
	if err != nil {
		return nil, err
	}

	report, err = e.applySuppressions(report)
	if err != nil {
		return nil, err
	}
		if filtered == nil {
			filtered = []findings.Finding{}
		}
		report.Findings = filtered
		newReport := findings.GenerateRiskReport(filtered, e.config.Boundaries)
		report = &newReport
	}

	return report, nil
}

func (e *Engine) runDiff(root string) (*findings.RiskReport, error) {
	var diffFiles []string
	var err error
	if e.config.StagedOnly {
		diffFiles, err = filesystem.GetStagedFiles(root)
	} else {
		diffFiles, err = filesystem.GetDiffFiles(root, e.config.DiffBase)
	}
	if err != nil {
		return nil, fmt.Errorf("get diff files: %w", err)
	}

	var files []*filesystem.File
	for _, relPath := range diffFiles {
		absPath := filepath.Join(root, relPath)
		file, err := filesystem.NewFileWithRoot(absPath, root)
		if err != nil {
			continue
		}
		if err := file.LoadContent(); err != nil {
			continue
		}
		if err != nil {
			continue
		}
		files = append(files, file)
	}

	allFindings := e.detectParallel(files)

	evaluated := e.evaluate(allFindings)
	reportVal := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	report := &reportVal

	if report == nil {
		return nil, nil
	}

	if e.config.BaselineFile != "" {
		baseline, err := findings.LoadBaseline(e.config.BaselineFile)
		if err != nil {
			return nil, fmt.Errorf("load baseline: %w", err)
		}

		if report == nil {
		return nil, nil
	}
	if report.Findings == nil {
		report.Findings = []findings.Finding{}
	}
	newFindings := findings.FilterNewFindings(report.Findings, baseline)
		if newFindings == nil {
			newFindings = []findings.Finding{}
		}
		report.Findings = newFindings
		newReport := findings.GenerateRiskReport(newFindings, e.config.Boundaries)
		report = &newReport

		if e.config.UpdateBaseline {
			findings.UpdateBaseline(baseline, newFindings)
			if err := findings.SaveBaseline(e.config.BaselineFile, baseline); err != nil {
				return nil, fmt.Errorf("save baseline: %w", err)
			}
		}
	}

	return report, nil
}

func (e *Engine) runSingleFile(path string) (*findings.RiskReport, error) {
	file, err := filesystem.NewFileWithRoot(path, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err := file.LoadContent(); err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	allFindings := e.detect(file)
	evaluated := e.evaluate(allFindings)
	singleReport := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	report := &singleReport

	if report == nil {
		return nil, nil
	}

	if e.config.BaselineFile != "" {
		baseline, err := findings.LoadBaseline(e.config.BaselineFile)
		if err != nil {
			return nil, fmt.Errorf("load baseline: %w", err)
		}

		if report == nil {
		return nil, nil
	}
	if report.Findings == nil {
		report.Findings = []findings.Finding{}
	}
	newFindings := findings.FilterNewFindings(report.Findings, baseline)
		if newFindings == nil {
			newFindings = []findings.Finding{}
		}
		report.Findings = newFindings
		newReport := findings.GenerateRiskReport(newFindings, e.config.Boundaries)
		report = &newReport

		if e.config.UpdateBaseline {
			findings.UpdateBaseline(baseline, newFindings)
			if err := findings.SaveBaseline(e.config.BaselineFile, baseline); err != nil {
				return nil, fmt.Errorf("save baseline: %w", err)
			}
		}
	}

	return report, nil
}

func (e *Engine) runDirectory(root string) (*findings.RiskReport, error) {
	// Calculate max file size for walker
	maxFileSize := filesystem.DefaultMaxFileSize
	if e.config.MaxFileSizeMB > 0 {
		maxFileSize = e.config.MaxFileSizeMB * 1024 * 1024
	}

	files, err := filesystem.WalkWithOptions(root, filesystem.WalkOption{
		MaxFileSize:      maxFileSize,
		SkipExtensions:   e.config.SkipExtensions,
		IncludeTestFiles: e.config.IncludeTestFiles,
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	// Apply max files limit
	if e.config.MaxFiles > 0 && len(files) > e.config.MaxFiles {
		files = files[:e.config.MaxFiles]
		fmt.Fprintf(os.Stderr, "warning: reached max files limit (%d), scanning first %d files\n", e.config.MaxFiles, e.config.MaxFiles)
	}

	allFindings := e.detectParallel(files)

	evaluated := e.evaluate(allFindings)
	report := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	return &report, nil
}

func (e *Engine) detect(file *filesystem.File) []findings.Finding {
	if file == nil {
		return nil
	}

	// Acquire semaphore for file read
	if e.readSemaphore != nil {
		e.readSemaphore <- struct{}{}
		defer func() { <-e.readSemaphore }()
	}

	var all []findings.Finding
	for _, d := range e.detectors {
		fResults := d.Detect(file)
		all = append(all, fResults...)
	}

	var filtered []findings.Finding
	for _, f := range all {
		if e.config.MinConfidence > 0 && f.Confidence < e.config.MinConfidence {
			continue
		}

		if e.config.MinSeverity != "" {
			minSev := findings.ParseSeverity(e.config.MinSeverity)
			if f.Severity < minSev {
				continue
			}
		}

		if len(e.config.Tags) > 0 && !hasAnyTag(f.Tags, e.config.Tags) {
			continue
		}

		filtered = append(filtered, f)
	}

	if !e.config.DisableInlineSuppression {
		filtered = findings.FilterInlineSuppressions(filtered, string(file.Content))
	}

	return filtered
}

func (e *Engine) detectParallel(files []*filesystem.File) []findings.Finding {
	workers := e.config.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers > len(files) {
		workers = len(files)
	}
	if workers < 1 {
		workers = 1
	}

	type result struct {
		findings []findings.Finding
	}

	fileCh := make(chan *filesystem.File, len(files))
	resultCh := make(chan result, len(files))

	var filesScanned atomic.Int64
	var findingsFound atomic.Int64

	totalFiles := int64(len(files))

	// Track memory usage if limit is set
	var memStats runtime.MemStats
	if e.config.MemoryLimitMB > 0 {
		runtime.ReadMemStats(&memStats)
	}
	initialAlloc := memStats.Alloc

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "panic in detector goroutine: %v\n", r)
				}
			}()
			defer wg.Done()
			for file := range fileCh {
				// Check memory limit
				if e.config.MemoryLimitMB > 0 {
					runtime.ReadMemStats(&memStats)
					limit := uint64(e.config.MemoryLimitMB) * 1024 * 1024
					if memStats.Alloc-initialAlloc > limit {
						// Memory limit exceeded, stop processing
						close(fileCh)
						return
					}
				}

				fResults := e.detect(file)
				findingsFound.Add(int64(len(fResults)))
				filesScanned.Add(1)
				resultCh <- result{findings: fResults}

				if e.config.Verbose && filesScanned.Load()%100 == 0 {
					fmt.Fprintf(os.Stderr, "\rScanning: %d/%d files (%d findings)", filesScanned.Load(), totalFiles, findingsFound.Load())
				}
			}
		}()
	}

	for _, file := range files {
		fileCh <- file
	}
	close(fileCh)

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var allFindings []findings.Finding
	for r := range resultCh {
		allFindings = append(allFindings, r.findings...)
	}

	if e.config.Verbose && totalFiles > 100 {
		fmt.Fprintf(os.Stderr, "\rScanning complete: %d files, %d findings\n", totalFiles, len(allFindings))
	}

	return allFindings
}

func hasAnyTag(findingTags, filterTags []string) bool {
	for _, ft := range filterTags {
		for _, ftag := range findingTags {
			if ftag == ft {
				return true
			}
		}
	}
	return false
}

func (e *Engine) evaluate(fs []findings.Finding) []findings.Finding {
	var evaluated []findings.Finding
	for _, f := range fs {
		action := policy.Evaluate(f, e.policies)
		f.Action = action
		f.Reason = string(action) + ": " + f.Reason
		if action == findings.ActionRedact {
			f.Value = findings.RedactValue(f.Value, f.Type)
		}
		evaluated = append(evaluated, f)
	}
	return evaluated
}

func (e *Engine) Detectors() []detectors.Detector {
	return e.detectors
}

func (e *Engine) Policies() []policy.PolicyRule {
	return e.policies
}
