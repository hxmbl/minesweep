package engine

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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
	HistoryMode              bool
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
	// Number of files and bytes examined during the most recent Run
	filesScanned atomic.Int64
	bytesScanned atomic.Int64
	filesSkipped atomic.Int64
	filesFailed  atomic.Int64
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

// finalize runs the post-detection pipeline: deduplication, baseline
// filtering, suppression filtering, policy evaluation, and report generation.
// Filtering deliberately happens BEFORE evaluation so that baselines and
// suppression patterns match raw secret values, not redacted ones.
func (e *Engine) finalize(root string, allFindings []findings.Finding) (*findings.RiskReport, error) {
	allFindings = relativizeFindings(root, allFindings)
	// Several detectors can independently raise the same finding (regex,
	// entropy, decoded base64 wrapping the same rule). Collapse identical
	// ones before baselines and suppression so counts and hashes stay stable.
	allFindings = dedupFindings(allFindings)
	filtered, err := e.filterBaseline(allFindings)
	if err != nil {
		return nil, err
	}

	filtered, err = e.filterSuppressions(filtered)
	if err != nil {
		return nil, err
	}

	evaluated := e.evaluate(filtered)
	sortFindings(evaluated)
	rep := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	return &rep, nil
}

// dedupFindings removes duplicate findings sharing the same location, rule,
// and value, keeping the first (detectors run in a stable order).
func dedupFindings(fs []findings.Finding) []findings.Finding {
	seen := make(map[string]struct{}, len(fs))
	out := make([]findings.Finding, 0, len(fs))
	for _, f := range fs {
		key := f.File + "\x00" + strconv.Itoa(f.Line) + "\x00" + strconv.Itoa(f.Column) +
			"\x00" + f.RuleID + "\x00" + f.Value
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

// sortFindings orders findings deterministically so identical scans produce
// byte-identical reports regardless of worker scheduling.
func sortFindings(fs []findings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Value < b.Value
	})
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
	e.filesScanned.Store(0)
	e.bytesScanned.Store(0)
	e.filesSkipped.Store(0)
	e.filesFailed.Store(0)
	start := time.Now()
	rep, err := e.run(path)
	if rep != nil {
		rep.FilesScanned = int(e.filesScanned.Load())
		rep.BytesScanned = e.bytesScanned.Load()
		rep.FilesSkipped = int(e.filesSkipped.Load())
		rep.FilesFailed = int(e.filesFailed.Load())
		rep.DurationMs = time.Since(start).Milliseconds()
	}
	return rep, err
}

func (e *Engine) run(path string) (*findings.RiskReport, error) {
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

	if e.config.HistoryMode {
		return e.runHistory(path)
	}

	report, err := e.runDirectory(path)
	if err != nil {
		return nil, err
	}
	return report, nil
}

func (e *Engine) runDiff(root string) (*findings.RiskReport, error) {
	isStaged := e.config.StagedOnly
	var diffFiles []string
	var err error
	if isStaged {
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

	maxFileSize := filesystem.DefaultMaxFileSize
	if e.config.MaxFileSizeMB > 0 {
		maxFileSize = e.config.MaxFileSizeMB * 1024 * 1024
	}
	// Diff/staged scans apply the exact same filters as a directory walk:
	// skip dirs, extensions, test files (unless enabled), .minesweepignore,
	// and the file-size ceiling. Loading every changed file regardless made
	// scoped scans diverge from full scans.
	checker := filesystem.NewSkipChecker(root, filesystem.WalkOption{
		SkipExtensions:   e.config.SkipExtensions,
		IncludeTestFiles: e.config.IncludeTestFiles,
		MaxFileSize:      maxFileSize,
	})

	var files []*filesystem.File
	var skipped int
	for _, relPath := range diffFiles {
		absPath := filepath.Join(top, relPath)
		if !withinDir(absPath, root) {
			continue // changed file outside the requested scan root
		}
		if e.config.MaxFiles > 0 && len(files) >= e.config.MaxFiles {
			break
		}
		rev := "HEAD"
		if isStaged {
			rev = ""
		}
		contentLoader := func(rp, r string) func() ([]byte, error) {
			return func() ([]byte, error) {
				return git.GetFileContent(top, filepath.ToSlash(rp), r)
			}
		}(relPath, rev)

		file, err := filesystem.NewFileWithRoot(absPath, root)
		if err != nil {
			// Path added to the index/HEAD but removed from the working
			// tree: the stat fails, yet the blob still exists and must be
			// scanned. A fresh loader-backed file has no on-disk state.
			file = filesystem.NewBlobFile(absPath, 0, contentLoader)
			if checker.ShouldSkip(absPath) {
				skipped++
				continue
			}
			files = append(files, file)
			continue
		}
		if checker.ShouldSkip(absPath) || checker.ShouldSkipSize(file.Size) {
			skipped++
			continue
		}
		// Serve committed or staged content, never the working tree: a
		// pre-commit scan must flag exactly what would be committed,
		// including deletions and unstaged edits.
		file.UseLoader(contentLoader)
		files = append(files, file)
	}
	if skipped > 0 {
		e.filesSkipped.Add(int64(skipped))
	}

	e.filesScanned.Store(int64(len(files)))
	bytesTotal, failed := e.countContent(files)
	e.bytesScanned.Store(bytesTotal)
	e.filesFailed.Add(failed)
	allFindings := e.detectParallel(files)
	return e.finalize(root, allFindings)
}

// countContent sums the loaded content bytes and counts files whose content
// could not be produced (deleted between walk and read, failed blob fetch),
// so coverage gaps surface in the report instead of vanishing silently.
func (e *Engine) countContent(files []*filesystem.File) (bytesTotal int64, failed int64) {
	for _, file := range files {
		content, err := file.GetContent()
		if err != nil {
			failed++
			continue
		}
		bytesTotal += int64(len(content))
	}
	return bytesTotal, failed
}

func (e *Engine) runSingleFile(path string) (*findings.RiskReport, error) {
	file, err := filesystem.NewFileWithRoot(path, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err := file.LoadContent(); err != nil {
		return nil, err
	}

	e.filesScanned.Store(1)
	e.bytesScanned.Store(file.Size)
	allFindings := e.detect(file)
	return e.finalize(filepath.Dir(path), allFindings)
}

// runHistory scans every unique blob reachable from all refs. Cost scales
// with content diversity, not commit count: each object is fetched and
// scanned exactly once, then findings are attributed to the commit that
// introduced them.
func (e *Engine) runHistory(root string) (*findings.RiskReport, error) {
	maxFileSize := filesystem.DefaultMaxFileSize
	if e.config.MaxFileSizeMB > 0 {
		maxFileSize = e.config.MaxFileSizeMB * 1024 * 1024
	}

	objects, err := git.ListHistoryObjects(root)
	if err != nil {
		return nil, fmt.Errorf("list history objects: %w", err)
	}
	if e.config.MaxFiles > 0 && len(objects) > e.config.MaxFiles {
		// rev-list ordering is tied to git internals and unrelated to secret
		// density, so scanning the first N would systematically miss blobs.
		// Sort by object name and stride evenly: every run and every machine
		// scans the same deterministic, representative sample.
		sort.Slice(objects, func(i, j int) bool {
			if objects[i].SHA != objects[j].SHA {
				return objects[i].SHA < objects[j].SHA
			}
			return objects[i].Path < objects[j].Path
		})
		step := float64(len(objects)) / float64(e.config.MaxFiles)
		sampled := make([]git.HistoryObject, 0, e.config.MaxFiles)
		for i := 0; i < e.config.MaxFiles; i++ {
			idx := int(float64(i) * step)
			if idx >= len(objects) {
				idx = len(objects) - 1
			}
			sampled = append(sampled, objects[idx])
		}
		objects = sampled
		fmt.Fprintf(os.Stderr, "warning: reached max files limit (%d), scanning a deterministic sample of %d history objects\n",
			e.config.MaxFiles, e.config.MaxFiles)
	}

	fetcher, err := git.NewBlobFetcher(root)
	if err != nil {
		return nil, fmt.Errorf("start blob fetcher: %w", err)
	}
	defer fetcher.Close()

	files := make([]*filesystem.File, 0, len(objects))
	displaySHA := make(map[string]string, len(objects))
	var bytesTotal int64
	var skippedOversize int
	for _, obj := range objects {
		obj := obj
		if obj.Path == "" {
			continue
		}
		if obj.Size > maxFileSize {
			skippedOversize++
			continue
		}
		bytesTotal += obj.Size

		display := fmt.Sprintf("%s@%s", obj.Path, shortSHA(obj.SHA))
		displaySHA[display] = obj.SHA
		files = append(files, filesystem.NewBlobFile(display, obj.Size, func() ([]byte, error) {
			return fetcher.Fetch(obj.SHA)
		}))
	}
	if skippedOversize > 0 {
		fmt.Fprintf(os.Stderr, "minesweep: note: %d history objects larger than %d MB were not scanned\n",
			skippedOversize, maxFileSize/1024/1024)
		e.filesSkipped.Add(int64(skippedOversize))
	}

	e.filesScanned.Store(int64(len(files)))
	e.bytesScanned.Store(bytesTotal)
	allFindings := e.detectParallel(files)

	// Blob fetches can fail mid-scan (pack corruption, torn object database);
	// those files silently produced zero findings, so surface the gap.
	fetchFailed := int64(0)
	for _, file := range files {
		if _, err := file.GetContent(); err != nil {
			fetchFailed++
		}
	}
	e.filesFailed.Add(fetchFailed)

	attributed := e.attributeHistory(root, allFindings, displaySHA)
	return e.finalize(root, attributed)
}

// attributeHistory resolves the introducing commit for each flagged blob.
// Queries run once per unique SHA — typically a handful — never per finding.
func (e *Engine) attributeHistory(root string, fs []findings.Finding, displaySHA map[string]string) []findings.Finding {
	shas := make(map[string]bool)
	for _, f := range fs {
		if sha, ok := displaySHA[f.File]; ok && !shas[sha] {
			shas[sha] = true
		}
	}

	infos := make(map[string]*git.CommitInfo, len(shas))
	for sha := range shas {
		info, err := git.FindOriginCommit(root, sha)
		if err != nil {
			if e.config.Verbose {
				fmt.Fprintf(os.Stderr, "minesweep: attribution failed for %s: %v\n", shortSHA(sha), err)
			}
			continue
		}
		infos[sha] = info
	}

	out := make([]findings.Finding, len(fs))
	copy(out, fs)
	for i := range out {
		sha, ok := displaySHA[out[i].File]
		if !ok {
			continue
		}
		info := infos[sha]
		if info == nil {
			continue
		}
		out[i].Commit = info.SHA
		out[i].Author = info.Author
		out[i].Date = info.Date
		out[i].CommitSummary = info.Summary
	}
	return out
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func (e *Engine) runDirectory(root string) (*findings.RiskReport, error) {
	// Calculate max file size for walker
	maxFileSize := filesystem.DefaultMaxFileSize
	if e.config.MaxFileSizeMB > 0 {
		maxFileSize = e.config.MaxFileSizeMB * 1024 * 1024
	}

	var stats filesystem.WalkStats
	files, err := filesystem.WalkWithOptions(root, filesystem.WalkOption{
		MaxFileSize:      maxFileSize,
		SkipExtensions:   e.config.SkipExtensions,
		IncludeTestFiles: e.config.IncludeTestFiles,
		Stats:            &stats,
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}
	e.filesSkipped.Store(int64(stats.TotalSkipped()))

	// Apply max files limit
	if e.config.MaxFiles > 0 && len(files) > e.config.MaxFiles {
		files = files[:e.config.MaxFiles]
		fmt.Fprintf(os.Stderr, "warning: reached max files limit (%d), scanning first %d files\n", e.config.MaxFiles, e.config.MaxFiles)
	}

	e.filesScanned.Store(int64(len(files)))
	bytesTotal, failed := e.countContent(files)
	e.bytesScanned.Store(bytesTotal)
	e.filesFailed.Add(failed)
	allFindings := e.detectParallel(files)
	return e.finalize(root, allFindings)
}

// relativizeFindings rewrites finding paths relative to the scanned root so
// output is stable regardless of where the repository lives on disk, and so
// baselines match across machines and across working-tree/history modes.
func relativizeFindings(root string, fs []findings.Finding) []findings.Finding {
	rootWithSep := root
	if !strings.HasSuffix(root, string(filepath.Separator)) {
		rootWithSep += string(filepath.Separator)
	}
	for i := range fs {
		if fs[i].File == root {
			fs[i].File = filepath.Base(fs[i].File)
			continue
		}
		fs[i].File = strings.TrimPrefix(fs[i].File, rootWithSep)
	}
	return fs
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

	var minSev findings.Severity
	if e.config.MinSeverity != "" {
		minSev = findings.ParseSeverity(e.config.MinSeverity)
	}

	var filtered []findings.Finding
	for _, f := range all {
		if e.config.MinConfidence > 0 && f.Confidence < e.config.MinConfidence {
			continue
		}

		if minSev > 0 && f.Severity < minSev {
			continue
		}

		if len(e.config.Tags) > 0 && !hasAnyTag(f.Tags, e.config.Tags) {
			continue
		}

		filtered = append(filtered, f)
	}

	if len(filtered) > 0 && !e.config.DisableInlineSuppression {
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

	// Cancelling ctx stops processing of remaining files without closing fileCh,
	// which is owned by the producer below (closing it from a worker would risk
	// a send-on-closed-channel panic).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var memCancelWarned atomic.Bool
	if e.config.MemoryLimitMB > 0 {
		// One coordinator measures heap growth on a slow ticker. Measuring
		// from inside each worker forced runtime.ReadMemStats (a full
		// stop-the-world) on every worker on every interval. Reading it once
		// here is both cheaper and equally accurate for a soft early-exit.
		initialAlloc := e.allocBytes()
		monitorStop := make(chan struct{})
		var monitorWG sync.WaitGroup
		monitorWG.Add(1)
		go func() {
			defer monitorWG.Done()
			limit := uint64(e.config.MemoryLimitMB) * 1024 * 1024 //nolint:gosec // guarded by > 0 check above
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if e.allocBytes() > initialAlloc+limit {
						if memCancelWarned.CompareAndSwap(false, true) {
							fmt.Fprintf(os.Stderr, "warning: memory limit (%d MB) reached; stopping scan early, results are incomplete\n", e.config.MemoryLimitMB)
						}
						cancel()
						return
					}
				case <-ctx.Done():
					return
				case <-monitorStop:
					return
				}
			}
		}()
		defer func() {
			close(monitorStop)
			monitorWG.Wait()
		}()
	}

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
				if ctx.Err() != nil {
					continue // drain the channel without processing
				}

				func() {
					defer func() {
						if r := recover(); r != nil {
							fmt.Fprintf(os.Stderr, "panic in detector for %s: %v\n", file.Path, r)
							e.filesFailed.Add(1)
						}
					}()
					fResults := e.detect(file)
					findingsFound.Add(int64(len(fResults)))
					filesScanned.Add(1)
					resultCh <- result{findings: fResults}
				}()

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

// allocBytes reads the current heap allocation, used by the coordinated
// memory-limit monitor.
func (e *Engine) allocBytes() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.Alloc
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
		if action == findings.ActionRedact && f.Value != "" {
			raw := f.Value
			f.Value = findings.RedactValue(raw, f.Type)
			// The captured value also appears verbatim in the surrounding
			// evidence; a redaction that leaves the secret sitting in
			// source_line/context is not a redaction.
			mask := findings.RedactValue("", "")
			f.SourceLine = strings.ReplaceAll(f.SourceLine, raw, mask)
			f.Context = strings.ReplaceAll(f.Context, raw, mask)
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
