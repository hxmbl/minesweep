package engine

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"minesweep/detectors"
	"minesweep/filesystem"
	"minesweep/findings"
	"minesweep/git"
	"minesweep/policy"

	"minesweep"
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
	MaxFiles      int   // Maximum number of files to scan (0 = unlimited)
	MemoryLimitMB int   // Maximum memory usage in MB (0 = unlimited)
	MaxFileSizeMB int64 // Maximum file size in MB to scan (0 = use default)
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
		detectors.NewBase64DetectorWithRegex(regexDetector),
		detectors.NewDatabaseDetector(),
		detectors.NewOAuthDetector(),
	}

	policies, err := resolvePolicies(cfg)
	if err != nil {
		return nil, err
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

// resolvePolicies loads policy rules from, in order of precedence:
//  1. an explicit profile (from disk profiles dir if present, else embedded)
//  2. an explicit policy file (must exist on disk)
//  3. <policy-dir>/default.yml from disk if that dir exists, else embedded
func resolvePolicies(cfg Config) ([]policy.PolicyRule, error) {
	switch {
	case cfg.Profile != "":
		if cfg.PolicyFile != "" {
			fmt.Fprintf(os.Stderr, "warning: both --profile and --policy set; --profile (%q) takes precedence\n", cfg.Profile)
		}
		fsys, embedded := dirOrEmbedded(cfg.ProfilesDir, "profiles")
		if embedded && cfg.Verbose {
			fmt.Fprintf(os.Stderr, "minesweep: profiles dir %q not found; using built-in profiles\n", cfg.ProfilesDir)
		}
		policies, err := policy.ResolveProfileFS(fsys, cfg.Profile)
		if err != nil {
			return nil, fmt.Errorf("resolve profile %q: %w", cfg.Profile, err)
		}
		return policies, nil

	case cfg.PolicyFile != "":
		policies, err := policy.LoadPolicyFile(cfg.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("load policy file: %w", err)
		}
		return policies, nil

	default:
		if info, err := os.Stat(cfg.PolicyDir); err == nil && info.IsDir() {
			defaultPath := filepath.Join(cfg.PolicyDir, "default.yml")
			policies, err := policy.LoadPolicyFile(defaultPath)
			if err != nil {
				return nil, fmt.Errorf("load default policy: %w", err)
			}
			return policies, nil
		}
		policyFS, err := fs.Sub(minesweep.Assets, "policy")
		if err != nil {
			return nil, err
		}
		if cfg.Verbose {
			fmt.Fprintf(os.Stderr, "minesweep: policy dir %q not found; using built-in default policy\n", cfg.PolicyDir)
		}
		policies, err := policy.LoadPolicyFileFS(policyFS, "default.yml")
		if err != nil {
			return nil, fmt.Errorf("load default policy: %w", err)
		}
		return policies, nil
	}
}

// dirOrEmbedded returns an fs.FS for a directory if it exists on disk,
// otherwise a subtree of the embedded assets. The second return value reports
// whether the embedded fallback was used.
func dirOrEmbedded(dir, embeddedSubtree string) (fs.FS, bool) {
	if dir != "" {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return os.DirFS(dir), false
		}
	}
	sub, err := fs.Sub(minesweep.Assets, embeddedSubtree)
	if err != nil {
		// Embedded subtree names are compile-time constants; this cannot fail.
		panic(fmt.Sprintf("embedded asset subtree %q: %v", embeddedSubtree, err))
	}
	return sub, true
}

// finalize runs the post-detection pipeline: baseline filtering, suppression
// filtering, policy evaluation, and report generation. Filtering deliberately
// happens BEFORE evaluation so that baselines and suppression patterns match
// raw secret values, not redacted ones.
func (e *Engine) finalize(allFindings []findings.Finding) (*findings.RiskReport, error) {
	filtered, err := e.filterBaseline(allFindings)
	if err != nil {
		return nil, err
	}

	filtered, err = e.filterSuppressions(filtered)
	if err != nil {
		return nil, err
	}

	evaluated := e.evaluate(filtered)
	rep := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	return &rep, nil
}

// filterBaseline removes findings already recorded in the baseline file.
func (e *Engine) filterBaseline(fs []findings.Finding) ([]findings.Finding, error) {
	if e.config.BaselineFile == "" {
		return fs, nil
	}
	baseline, err := findings.LoadBaseline(e.config.BaselineFile)
	if err != nil {
		return nil, fmt.Errorf("load baseline: %w", err)
	}
	newFindings := findings.FilterNewFindings(fs, baseline)

	if err := e.updateBaseline(baseline, newFindings); err != nil {
		return nil, fmt.Errorf("save baseline: %w", err)
	}
	return newFindings, nil
}

// filterSuppressions removes findings matching the suppression file.
func (e *Engine) filterSuppressions(fs []findings.Finding) ([]findings.Finding, error) {
	if e.config.SuppressFile == "" {
		return fs, nil
	}
	suppressions, err := findings.LoadSuppressions(e.config.SuppressFile)
	if err != nil {
		return nil, fmt.Errorf("load suppressions: %w", err)
	}
	return findings.FilterSuppressed(fs, suppressions), nil
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
	return report, nil
}

func (e *Engine) runDiff(root string) (*findings.RiskReport, error) {
	var diffFiles []string
	var err error
	if e.config.StagedOnly {
		diffFiles, err = git.GetStagedFiles(root)
	} else {
		diffFiles, err = git.GetDiffFiles(root, e.config.DiffBase)
	}
	if err != nil {
		return nil, fmt.Errorf("get diff files: %w", err)
	}

	// Git reports paths relative to the repository top level; resolve them
	// there and keep only files inside the requested scan root.
	top := git.TopLevel(root)
	if top == "" {
		top = root
	}

	var files []*filesystem.File
	for _, relPath := range diffFiles {
		absPath := filepath.Join(top, relPath)
		if !withinDir(absPath, root) {
			continue // changed file outside the requested scan root
		}
		file, err := filesystem.NewFileWithRoot(absPath, root)
		if err != nil {
			continue
		}
		if err := file.LoadContent(); err != nil {
			continue
		}
		files = append(files, file)
	}

	allFindings := e.detectParallel(files)
	return e.finalize(allFindings)
}

func (e *Engine) runSingleFile(path string) (*findings.RiskReport, error) {
	file, err := filesystem.NewFileWithRoot(path, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err := file.LoadContent(); err != nil {
		return nil, err
	}

	allFindings := e.detect(file)
	return e.finalize(allFindings)
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
	return e.finalize(allFindings)
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
		content, err := file.GetContent()
		if err == nil {
			filtered = findings.FilterInlineSuppressions(filtered, string(content))
		}
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

	// Cancelling ctx stops processing of remaining files without closing fileCh,
	// which is owned by the producer below (closing it from a worker would risk
	// a send-on-closed-channel panic).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const memCheckInterval = 64

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
			processed := 0
			for file := range fileCh {
				// Check memory limit periodically
				if e.config.MemoryLimitMB > 0 && processed%memCheckInterval == 0 {
					runtime.ReadMemStats(&memStats)
					limit := uint64(e.config.MemoryLimitMB) * 1024 * 1024 //nolint:gosec // guarded by > 0 check above
					if memStats.Alloc-initialAlloc > limit {
						cancel()
					}
				}
				processed++

				if ctx.Err() != nil {
					continue // drain the channel without processing
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

// withinDir reports whether absPath is located inside (or equal to) dir.
// Both sides are symlink-resolved first: e.g. git reports /private/tmp/... on
// macOS while filepath.Abs yields /tmp/..., which are otherwise unrelated.
func withinDir(absPath, dir string) bool {
	if rp, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = rp
	}
	if rd, err := filepath.EvalSymlinks(dir); err == nil {
		dir = rd
	}
	rel, err := filepath.Rel(dir, absPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
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
