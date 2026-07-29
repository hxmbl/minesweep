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
}

type Engine struct {
	config    Config
	detectors []detectors.Detector
	policies  []policy.PolicyRule
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

	return &Engine{
		config:    cfg,
		detectors: detList,
		policies:  policies,
	}, nil
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

	if e.config.BaselineFile != "" {
		baseline, err := findings.LoadBaseline(e.config.BaselineFile)
		if err != nil {
			return nil, fmt.Errorf("load baseline: %w", err)
		}

		newFindings := findings.FilterNewFindings(report.Findings, baseline)
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

	if e.config.SuppressFile != "" {
		suppressions, err := findings.LoadSuppressions(e.config.SuppressFile)
		if err != nil {
			return nil, fmt.Errorf("load suppressions: %w", err)
		}

		filtered := findings.FilterSuppressed(report.Findings, suppressions)
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
		file, err := filesystem.NewFile(absPath)
		if err != nil {
			continue
		}
		files = append(files, file)
	}

	allFindings := e.detectParallel(files)

	evaluated := e.evaluate(allFindings)
	reportVal := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	report := &reportVal

	if e.config.BaselineFile != "" {
		baseline, err := findings.LoadBaseline(e.config.BaselineFile)
		if err != nil {
			return nil, fmt.Errorf("load baseline: %w", err)
		}

		newFindings := findings.FilterNewFindings(report.Findings, baseline)
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
	file, err := filesystem.NewFile(path)
	if err != nil {
		return nil, err
	}
	allFindings := e.detect(file)
	evaluated := e.evaluate(allFindings)
	singleReport := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	report := &singleReport

	if e.config.BaselineFile != "" {
		baseline, err := findings.LoadBaseline(e.config.BaselineFile)
		if err != nil {
			return nil, fmt.Errorf("load baseline: %w", err)
		}

		newFindings := findings.FilterNewFindings(report.Findings, baseline)
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
	files, err := filesystem.WalkWithOptions(root, filesystem.WalkOption{
		MaxFileSize:      filesystem.DefaultMaxFileSize,
		SkipExtensions:   e.config.SkipExtensions,
		IncludeTestFiles: e.config.IncludeTestFiles,
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	allFindings := e.detectParallel(files)

	evaluated := e.evaluate(allFindings)
	report := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	return &report, nil
}

func (e *Engine) detect(file *filesystem.File) []findings.Finding {
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

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for file := range fileCh {
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
