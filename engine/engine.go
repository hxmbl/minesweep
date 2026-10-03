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

// DefaultConfidenceFloor is the minimum confidence a finding must reach to be
// reported. Detectors emit speculative low-confidence hits, and almost all of
// them are noise; dropping them at the source also means they never occupy
// memory. Override with --min-confidence, or set it to 0 to keep everything.
const DefaultConfidenceFloor = 0.05

// DefaultMaxFindings bounds how many findings a single scan retains. Four
// megabytes of a repeated key pattern used to produce a hundred thousand
// findings and hundreds of megabytes of heap; safety beats pathological
// completeness here, and the truncation is reported rather than hidden.
// Override with --max-findings; 0 disables the cap.
const DefaultMaxFindings = 25000

// perFileFindingBudget caps how many findings any one file may produce, however
// many matches its content contains. It exists so a single pathological input
// cannot allocate hundreds of thousands of findings: a 13 MB file of one
// repeated secret line matched ~210,000 times.
const perFileFindingBudget = 1000

// Reasons a scan may be incomplete. Every one of these must reach the report
// and the exit code: a scan that did not finish must never read as clean.
const (
	ReasonMemoryLimit = "memory limit reached; scan stopped early"
	ReasonFindingCap  = "finding cap reached; some findings were dropped"
	ReasonFileBudget  = "a file produced more findings than its budget allowed"
	ReasonWorkerPanic = "a detector panicked; files it had not reached were not scanned"
	ReasonMaxFiles    = "max files limit reached; only part of the tree was scanned"
	ReasonUnreadable  = "some paths could not be read; their contents were not scanned"
	ReasonSizeCeiling = "a reduced max file size meant some files were not read"
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
	// IncludeLowConfidence disables the DefaultConfidenceFloor, reporting
	// even the speculative hits detectors emit.
	IncludeLowConfidence bool
	// NoIgnore disables .minesweepignore/.msignore in every scan mode. It is
	// the deliberate override; the default is to honor the ignore files.
	NoIgnore bool
	// Resource limits
	MaxFiles      int   // Maximum number of files to scan (0 = unlimited)
	MemoryLimitMB int   // Maximum memory usage in MB (0 = unlimited)
	MaxFileSizeMB int64 // Maximum file size in MB to scan (0 = use default)
	// MaxFindings bounds retained findings (0 = unlimited). Defaults to
	// DefaultMaxFindings when unset; use -1 to mean "unlimited" explicitly.
	MaxFindings int

	// DangerouslyShowSecrets keeps raw secret values in the report. It is
	// presentation-only and deliberately not honoured from a config file.
	DangerouslyShowSecrets bool
	// ShowIgnored retains every skipped path in the report breakdown instead
	// of a bounded sample. Useful when hunting for a dropped secret.
	ShowIgnored bool
	// Concurrency limits
	MaxConcurrentReads int // Maximum concurrent file reads (0 = use Workers)
}

type Engine struct {
	config    Config
	detectors []detectors.Detector
	// regex is held separately so a per-Run step can add discovered rules
	// (see loadDiscoveredGitleaks).
	regex    *detectors.RegexDetector
	policies []policy.PolicyRule
	// Semaphore for limiting concurrent file reads
	readSemaphore chan struct{}
	// Number of files and bytes examined during the most recent Run
	filesScanned atomic.Int64
	bytesScanned atomic.Int64
	filesSkipped atomic.Int64
	filesFailed  atomic.Int64
	// findingsKept tracks the running total so the per-file budget can be
	// derived from what is actually left, rather than a guess up front.
	findingsKept    atomic.Int64
	findingsDropped atomic.Int64
	// incompleteReasons records why a scan did not finish. Guarded by mu
	// because workers and the memory monitor both append.
	mu                sync.Mutex
	incompleteReasons []string
	// skipStats mirrors the walker's coverage accounting into the report.
	skipStatsMu sync.Mutex
	skipStats   *filesystem.WalkStats
	// discoveredRules guards the one-shot .gitleaks.toml discovery so repeated
	// internal dispatches within a single Run cannot add the same rules twice.
	discoveredRules bool
}

// maxFindings returns the effective finding cap, or 0 for unlimited.
func (e *Engine) maxFindings() int {
	switch {
	case e.config.MaxFindings < 0:
		return 0
	case e.config.MaxFindings == 0:
		return DefaultMaxFindings
	default:
		return e.config.MaxFindings
	}
}

// noteIncomplete records why the scan is not a complete answer. Repeated calls
// with the same reason collapse to one entry.
func (e *Engine) noteIncomplete(reason string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, r := range e.incompleteReasons {
		if r == reason {
			return
		}
	}
	e.incompleteReasons = append(e.incompleteReasons, reason)
}

func (e *Engine) incomplete() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.incompleteReasons) == 0 {
		return nil
	}
	out := make([]string, len(e.incompleteReasons))
	copy(out, e.incompleteReasons)
	return out
}

// prepareSkipStats returns a WalkStats configured for this scan's reporting
// preferences (full path retention when --show-ignored is set).
func (e *Engine) prepareSkipStats() *filesystem.WalkStats {
	st := &filesystem.WalkStats{}
	if e.config.ShowIgnored {
		st.MaxExamples = -1
	}
	e.setSkipStats(st)
	return st
}

func (e *Engine) setSkipStats(s *filesystem.WalkStats) {
	e.skipStatsMu.Lock()
	defer e.skipStatsMu.Unlock()
	e.skipStats = s
}

func (e *Engine) getSkipStats() *filesystem.WalkStats {
	e.skipStatsMu.Lock()
	defer e.skipStatsMu.Unlock()
	return e.skipStats
}

func New(cfg Config) (*Engine, error) {
	// RulesDir and PolicyDir deliberately have no implicit default; see the
	// comments below. A path that is not there is not an error either: the
	// embedded rules and policy are always the base signal.
	if cfg.ProfilesDir == "" {
		cfg.ProfilesDir = "profiles"
	}
	// PolicyDir deliberately has no implicit default. It used to default to
	// "policy", which main.go then resolved against the working directory, so
	// merely running `minesweep /some/unrelated/target` from a checkout that
	// happened to contain ./policy/default.yml silently applied that policy to a
	// tree it has nothing to do with -- and a policy whose only rule was
	// `tags: ["*"], action: allow` turned a blocked finding into a clean exit 0.
	//
	// A policy now applies only when it is named: --policy, --policy-dir or
	// --profile. Otherwise the built-in policy is used. That matches how the
	// rules directory already behaves, and it is the same trust boundary as not
	// honouring a repo-supplied .gitleaks.toml allowlist.

	regexDetector, err := detectors.NewRegexDetector(cfg.RulesDir)
	if err != nil {
		return nil, fmt.Errorf("load regex detector: %w", err)
	}

	// Gitleaks discovery is deliberately absent from New: it needs the scan root,
	// which is only known per Run. See loadDiscoveredGitleaks.

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
		regex:         regexDetector,
		policies:      policies,
		readSemaphore: make(chan struct{}, maxReads),
	}, nil
}

// loadDiscoveredGitleaks adds the rules from a gitleaks config found in the tree
// being scanned (#20).
//
// Nothing read a repo-local .gitleaks.toml. The README says to drop one in your
// rules directory "or pass -r", which reads as if the ecosystem config were
// picked up, but only ~/.config/minesweep/rules was automatic. Combined with the
// fact that a --rules FILE argument was silently dropped (#23), a user migrating
// from gitleaks got neither their rules nor their allowlist, silently.
//
// Only RULES are loaded. An allowlist supplied by the tree under inspection
// would let that tree suppress its own findings -- the same trust class as the
// max_file_size_mb hole, and the same reasoning as not picking up an ambient
// ./policy. A config named explicitly with --rules keeps its allowlist, because
// then the user is the one making the trust decision.
//
// Skipped entirely when --rules was given: an explicit rule source should not be
// silently augmented from the target.
func (e *Engine) loadDiscoveredGitleaks(root string) {
	if e.regex == nil || e.config.RulesDir != "" {
		return
	}
	e.mu.Lock()
	already := e.discoveredRules
	e.mu.Unlock()
	if already {
		return
	}
	path := detectors.FindGitleaksConfig(root)
	if path == "" {
		return
	}
	e.mu.Lock()
	e.discoveredRules = true
	e.mu.Unlock()
	// G304: path came from detectors.FindGitleaksConfig, which only ever returns
	// ".gitleaks.toml" or "gitleaks.toml" inside the scan root.
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "minesweep: warning: %s: %v\n", path, err)
		return
	}
	rules, err := detectors.LoadGitleaksRules(data, filepath.Base(path), false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "minesweep: warning: ignoring %s: %v\n", path, err)
		return
	}
	if len(rules) == 0 {
		fmt.Fprintf(os.Stderr, "minesweep: warning: %s contains no usable rules\n", path)
		return
	}
	e.regex.AddRules(rules)
	fmt.Fprintf(os.Stderr, "minesweep: loaded %d rule(s) from %s\n", len(rules), filepath.Base(path))
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

	// Loading and filtering happen here; WRITING happens at the end. A baseline
	// has to describe what was actually reported, and at this point suppression
	// and the finding cap have not been applied yet.
	baseline, err := e.loadBaseline()
	if err != nil {
		return nil, err
	}
	if baseline != nil {
		allFindings = findings.FilterNewFindings(allFindings, baseline)
	}

	filtered, err := e.filterSuppressions(allFindings)
	if err != nil {
		return nil, err
	}

	// The per-file budget can overshoot the global cap by up to one file's
	// worth per worker, so trim here too. When a scan is truncated, the
	// highest-confidence findings are the ones worth keeping.
	filtered, dropped := trimToConfidenceCap(filtered, e.maxFindings())
	if dropped > 0 {
		e.findingsDropped.Add(int64(dropped))
		e.noteIncomplete(ReasonFindingCap)
	}

	// Record only what survived both filters. Recording the pre-filter set was
	// two bugs at once: a run capped at 10 findings wrote all 300 to the
	// baseline, and suppressed findings were baselined too, so deleting the
	// suppression file did not bring them back.
	if baseline != nil {
		if err := e.saveBaseline(baseline, filtered); err != nil {
			return nil, err
		}
	}

	evaluated := e.evaluate(filtered)
	sortFindings(evaluated)
	rep := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	return &rep, nil
}

// findingOrder is the total order used both to decide which findings survive the
// cap and to present them.
//
// It must not fall back on input order. Input order is detectParallel's
// result-channel completion order, which depends on worker scheduling, so a tie
// broken on it made --max-findings select a different subset depending on
// --workers: the same tree scanned with --workers 1 and --workers 32 produced
// two different sets of "the 100 most confident findings". That also defeats a
// baseline, because a baseline recorded from one worker count does not describe
// the next run's survivor set.
func findingOrder(a, b findings.Finding) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
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
	if a.Severity != b.Severity {
		return a.Severity > b.Severity
	}
	return a.Value < b.Value
}

// trimToConfidenceCap keeps the cap highest-confidence findings under the
// canonical order, so the choice is independent of worker scheduling.
// Returns the kept findings and how many were dropped.
func trimToConfidenceCap(fs []findings.Finding, cap int) ([]findings.Finding, int) {
	if cap <= 0 || len(fs) <= cap {
		return fs, 0
	}
	order := make([]int, len(fs))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		return findingOrder(fs[order[a]], fs[order[b]])
	})
	keep := make(map[int]struct{}, cap)
	for _, i := range order[:cap] {
		keep[i] = struct{}{}
	}
	out := make([]findings.Finding, 0, cap)
	for i, f := range fs {
		if _, ok := keep[i]; ok {
			out = append(out, f)
		}
	}
	return out, len(fs) - cap
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

// sortFindings orders findings by the canonical order so identical scans produce
// byte-identical reports regardless of worker scheduling.
func sortFindings(fs []findings.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		return findingOrder(fs[i], fs[j])
	})
}

// loadBaseline reads the configured baseline, or returns nil when none is in
// use. It never writes: recording what was reported is a separate, later step.
func (e *Engine) loadBaseline() (*findings.Baseline, error) {
	if e.config.BaselineFile == "" {
		return nil, nil
	}
	baseline, err := findings.LoadBaseline(e.config.BaselineFile)
	if err != nil {
		return nil, fmt.Errorf("load baseline: %w", err)
	}
	return baseline, nil
}

// saveBaseline records the reported findings, if --update-baseline was asked
// for. It is called with the set that actually survived suppression and the
// finding cap, never with the raw detection output.
func (e *Engine) saveBaseline(baseline *findings.Baseline, reported []findings.Finding) error {
	if !e.config.UpdateBaseline {
		return nil
	}
	findings.UpdateBaseline(baseline, reported)
	if err := findings.SaveBaseline(e.config.BaselineFile, baseline); err != nil {
		return fmt.Errorf("save baseline: %w", err)
	}
	return nil
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

func (e *Engine) Run(path string) (*findings.RiskReport, error) {
	e.filesScanned.Store(0)
	e.bytesScanned.Store(0)
	e.filesSkipped.Store(0)
	e.filesFailed.Store(0)
	e.findingsKept.Store(0)
	e.findingsDropped.Store(0)
	e.mu.Lock()
	e.incompleteReasons = nil
	e.mu.Unlock()
	e.setSkipStats(nil)

	// Discovered rules are per-scan state, so reset before adding them: a second
	// Run over a different tree must not inherit the first tree's config.
	e.mu.Lock()
	e.discoveredRules = false
	e.mu.Unlock()

	start := time.Now()
	e.loadDiscoveredGitleaks(path)
	rep, err := e.run(path)
	if rep != nil {
		// Counters are incremented where the work actually happened, so
		// these are measurements, not predictions.
		rep.FilesScanned = int(e.filesScanned.Load())
		rep.BytesScanned = e.bytesScanned.Load()
		rep.FilesSkipped = int(e.filesSkipped.Load())
		rep.FilesFailed = int(e.filesFailed.Load())
		rep.DurationMs = time.Since(start).Milliseconds()
		rep.FindingsDropped = int(e.findingsDropped.Load())
		rep.IncompleteReasons = e.incomplete()
		rep.Incomplete = len(rep.IncompleteReasons) > 0
		if st := e.getSkipStats(); st != nil {
			rep.SkippedBy = st.Summary()
		}
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

	// filepath.WalkDir does not follow a symlinked root: it treats the link as
	// a single non-directory entry, which is then marked unsafe and read as
	// empty. Scanning a symlinked project directory therefore found nothing,
	// scored 0/100 and exited clean. Resolve the root first so that stat, the
	// walk, the symlink guard and relativisation all agree on one path.
	//
	// --diff/--staged/--history already resolved symlinks on their own, which is
	// why the three modes disagreed about the same tree.
	if resolved, rerr := filepath.EvalSymlinks(path); rerr == nil && resolved != path {
		path = resolved
		info, err = os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("stat path: %w", err)
		}
		if !info.IsDir() {
			return e.runSingleFile(path)
		}
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

	// Diff/staged scans apply the exact same filters as a directory walk:
	// skip dirs, extensions, test files (unless enabled), .minesweepignore
	// and .msignore, and the file-size ceiling.
	checker, err := filesystem.NewSkipChecker(root, filesystem.WalkOption{
		SkipExtensions:   e.config.SkipExtensions,
		IncludeTestFiles: e.config.IncludeTestFiles,
		MaxFileSize:      e.maxFileSize(),
		NoIgnore:         e.config.NoIgnore,
	})
	if err != nil {
		return nil, fmt.Errorf("load ignore configuration: %w", err)
	}
	stats := e.prepareSkipStats()
	checker.WithStats(stats)

	var files []*filesystem.File
	var skipped int
	for _, relPath := range diffFiles {
		absPath := filepath.Join(top, relPath)
		if !withinDir(absPath, root) {
			continue // changed file outside the requested scan root
		}
		if e.config.MaxFiles > 0 && len(files) >= e.config.MaxFiles {
			e.noteIncomplete(ReasonMaxFiles)
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
			file.MaxContentBytes = checker.MaxSize()
			files = append(files, file)
			continue
		}
		if checker.ShouldSkip(absPath) || checker.ShouldSkipSize(file.Size, absPath) {
			skipped++
			continue
		}
		// Serve committed or staged content, never the working tree: a
		// pre-commit scan must flag exactly what would be committed,
		// including deletions and unstaged edits.
		file.UseLoader(contentLoader)
		file.MaxContentBytes = checker.MaxSize()
		files = append(files, file)
	}
	if skipped > 0 {
		e.filesSkipped.Add(int64(skipped))
	}
	e.noteReducedSizeCeiling()

	allFindings := e.detectParallel(files)
	return e.finalize(root, allFindings)
}

// noteReducedSizeCeiling marks the scan incomplete when files were dropped for
// size because the ceiling was set below the built-in default.
//
// With the default ceiling the limit is a documented, visible property of the
// tool and the drops already show up in skipped_by. A ceiling somebody chose is
// a decision to look at less, and "I looked at less" must not be reported the
// same way as "I looked and found nothing". This is the second half of the fix
// for the config-trust hole: max_file_size_mb is now secure:true so a discovered
// config cannot set it at all, and a ceiling that does come from a trusted flag
// or config still cannot produce a clean exit.
func (e *Engine) noteReducedSizeCeiling() {
	if e.maxFileSize() >= filesystem.DefaultMaxFileSize {
		return
	}
	if st := e.getSkipStats(); st != nil && st.ByReason[filesystem.SkipReasonLarge] > 0 {
		e.noteIncomplete(ReasonSizeCeiling)
	}
}

func (e *Engine) maxFileSize() int64 {
	if e.config.MaxFileSizeMB > 0 {
		return e.config.MaxFileSizeMB * 1024 * 1024
	}
	return filesystem.DefaultMaxFileSize
}

// runSingleFile scans a path the user named explicitly. It still honors
// .minesweepignore: an ignore file that quietly stops working when a file is
// named directly is not a source of truth. --no-ignore is the override.
func (e *Engine) runSingleFile(path string) (*findings.RiskReport, error) {
	dir := filepath.Dir(path)
	if !e.config.NoIgnore {
		checker, err := filesystem.NewSkipChecker(dir, filesystem.WalkOption{
			SkipExtensions:   e.config.SkipExtensions,
			IncludeTestFiles: e.config.IncludeTestFiles,
			MaxFileSize:      e.maxFileSize(),
		})
		if err != nil {
			return nil, fmt.Errorf("load ignore configuration: %w", err)
		}
		if reason, skip := checker.Classify(path); skip {
			return nil, fmt.Errorf("%s is excluded by ignore rules (%s); pass --no-ignore to scan it anyway",
				path, reason)
		}
	}

	file, err := filesystem.NewFileWithRoot(path, dir)
	if err != nil {
		return nil, err
	}
	file.MaxContentBytes = e.maxFileSize()

	allFindings := e.detect(file)
	return e.finalize(dir, allFindings)
}

// runHistory scans every unique blob reachable from all refs. Cost scales
// with content diversity, not commit count: each object is fetched and
// scanned exactly once, then findings are attributed to the commit that
// introduced them.
func (e *Engine) runHistory(root string) (*findings.RiskReport, error) {
	maxFileSize := e.maxFileSize()

	// History mode applies the same coverage filters as a working-tree scan.
	// It previously applied only the size ceiling, so skip-dirs, test files,
	// and the ignore files were all bypassed — in the one mode where a
	// committed-then-ignored secret is most likely to be sitting there.
	// History object paths are relative to the repository top level, so the
	// filters are rooted there rather than at the requested scan path.
	top := git.TopLevel(root)
	if top == "" {
		top = root
	}
	checker, err := filesystem.NewSkipChecker(top, filesystem.WalkOption{
		SkipExtensions:   e.config.SkipExtensions,
		IncludeTestFiles: e.config.IncludeTestFiles,
		MaxFileSize:      maxFileSize,
		NoIgnore:         e.config.NoIgnore,
	})
	if err != nil {
		return nil, fmt.Errorf("load ignore configuration: %w", err)
	}
	stats := e.prepareSkipStats()

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
		e.noteIncomplete(ReasonMaxFiles)
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
	var skippedOversize, skippedFiltered int
	for _, obj := range objects {
		obj := obj
		if obj.Path == "" {
			continue
		}
		// History paths are repository-relative with no filesystem entry, so
		// the same filter set is applied to them directly.
		if reason, skip := checker.ClassifyRel(obj.Path); skip {
			stats.Note(reason, obj.Path)
			skippedFiltered++
			continue
		}
		if obj.Size > maxFileSize {
			stats.Note(filesystem.SkipReasonLarge, obj.Path)
			skippedOversize++
			continue
		}

		display := fmt.Sprintf("%s@%s", obj.Path, shortSHA(obj.SHA))
		displaySHA[display] = obj.SHA
		bf := filesystem.NewBlobFile(display, obj.Size, func() ([]byte, error) {
			return fetcher.Fetch(obj.SHA)
		})
		bf.MaxContentBytes = maxFileSize
		files = append(files, bf)
	}
	total := skippedOversize + skippedFiltered
	if total > 0 {
		fmt.Fprintf(os.Stderr, "minesweep: note: %d of %d history objects were not scanned (%d by ignore/skip rules, %d larger than %d MB)\n",
			total, len(objects), skippedFiltered, skippedOversize, maxFileSize/1024/1024)
		e.filesSkipped.Add(int64(total))
	}

	allFindings := e.detectParallel(files)
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
	stats := e.prepareSkipStats()
	files, err := filesystem.WalkWithOptions(root, filesystem.WalkOption{
		MaxFileSize:      e.maxFileSize(),
		SkipExtensions:   e.config.SkipExtensions,
		IncludeTestFiles: e.config.IncludeTestFiles,
		NoIgnore:         e.config.NoIgnore,
		Stats:            stats,
		// OnError was declared and invoked at three places in the walker but
		// never set by any caller, so an unreadable subtree vanished with no
		// files_failed, no SkippedBy and no Incomplete: a directory of live
		// credentials behind chmod 000 still produced a clean exit.
		OnError: e.onWalkError,
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}
	e.filesSkipped.Store(int64(stats.Total()))
	e.noteReducedSizeCeiling()

	// Apply max files limit
	if e.config.MaxFiles > 0 && len(files) > e.config.MaxFiles {
		files = files[:e.config.MaxFiles]
		e.noteIncomplete(ReasonMaxFiles)
		fmt.Fprintf(os.Stderr, "warning: reached max files limit (%d), scanning first %d files\n", e.config.MaxFiles, e.config.MaxFiles)
	}

	allFindings := e.detectParallel(files)
	return e.finalize(root, allFindings)
}

// onWalkError records a path the walk could not inspect. Such a path is a
// coverage gap, not a clean result: anything in it is unscanned, so the scan has
// to say so rather than exit 0 on the strength of what it did manage to read.
func (e *Engine) onWalkError(path string, err error) {
	e.filesFailed.Add(1)
	e.noteIncomplete(ReasonUnreadable)
	if e.config.Verbose {
		fmt.Fprintf(os.Stderr, "minesweep: not inspected: %s: %v\n", path, err)
	}
}

// relativizeFindings rewrites finding paths relative to the scanned root so
// output is stable regardless of where the repository lives on disk, and so
// baselines match across machines and across working-tree/history modes.
//
// The root is resolved first. git rev-parse --show-toplevel returns the resolved
// path, so a lexical prefix trim against an unresolved root silently matched
// nothing and published an absolute local path into SARIF
// artifactLocation.uri, into ::error annotations, and into the baseline file --
// making a baseline machine-specific and a SARIF upload point nowhere.
func relativizeFindings(root string, fs []findings.Finding) []findings.Finding {
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
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

// detect runs every detector over one file, then filters, then attaches
// evidence to the survivors.
//
// The order matters for memory. Content is loaded here and nowhere else, the
// file is released before returning, and the surrounding source lines — the
// largest field on a finding — are built only for findings that survive
// filtering. Doing evidence first and filtering afterwards meant allocating
// context blocks for the ~99% of findings that were about to be discarded.
func (e *Engine) detect(file *filesystem.File) []findings.Finding {
	if file == nil {
		return nil
	}
	// The file is finished with once detect returns. Releasing here is what
	// keeps peak memory proportional to the worker count rather than to the
	// total size of the tree.
	defer file.Release()

	// Accounting lives here, where the content is already in hand. A separate
	// pre-pass would force every file resident before detection began,
	// defeating lazy loading outright.
	// Concurrency is limited around the whole read-and-detect, not just the
	// detect. The semaphore used to be acquired after GetContent, so
	// --max-concurrent-reads bounded nothing about reads: with
	// --workers 32 --max-concurrent-reads 1, thirty-two files were read into
	// memory simultaneously and the flag did nothing. Measured on 32 x 2.6 MB
	// files: 1585 MB with the old order against 171 MB with this one.
	if e.readSemaphore != nil {
		e.readSemaphore <- struct{}{}
		defer func() { <-e.readSemaphore }()
	}

	content, err := file.GetContent()
	if err != nil {
		e.filesFailed.Add(1)
		if e.config.Verbose {
			fmt.Fprintf(os.Stderr, "minesweep: %s: %v\n", file.Path, err)
		}
		return nil
	}
	e.filesScanned.Add(1)
	e.bytesScanned.Add(int64(len(content)))

	// Bound what one file can contribute. This is a fixed per-file ceiling, not
	// a share of the global --max-findings remaining.
	//
	// Deriving it from the global remainder made the candidate set depend on
	// worker scheduling: room := cap - findingsKept is read before any worker has
	// reported, so with --workers 32 many files each see the full cap while with
	// --workers 1 the first file consumes it. The same tree then produced a
	// different set of "the cap most confident findings" per worker count, which
	// also invalidates a baseline recorded from a different run.
	//
	// A fixed ceiling makes the candidate set a pure function of the tree: every
	// file independently yields at most this many findings, so trimming by the
	// canonical order afterwards is deterministic at any worker count.
	file.SetFindingBudget(perFileFindingBudget)

	var all []findings.Finding
	for _, d := range e.detectors {
		all = append(all, d.Detect(file)...)
	}
	if file.FindingBudgetHit {
		e.noteIncomplete(ReasonFileBudget)
	}

	minSev := findings.Severity(0)
	if e.config.MinSeverity != "" {
		minSev = findings.ParseSeverity(e.config.MinSeverity)
	}
	minConf := e.config.MinConfidence
	if minConf == 0 && !e.config.IncludeLowConfidence {
		minConf = DefaultConfidenceFloor
	}

	filtered := all[:0]
	for _, f := range all {
		if minConf > 0 && f.Confidence < minConf {
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

	if !e.config.DisableInlineSuppression && len(filtered) > 0 {
		// The LineIndex is used directly rather than splitting the content
		// into a []string: that split copied the whole file and allocated a
		// string header per line, for every file that had any finding.
		if li := file.Lines(); li != nil {
			filtered = findings.FilterInlineSuppressionsLines(filtered, li)
		}
	}

	// Evidence last: only for findings that are actually reported.
	attachEvidence(file, filtered)

	// Every secret this file produced, including ones filtered out above: a
	// value that fell below the confidence floor is still a credential, and it
	// is still sitting in the evidence of the findings that survived. Without
	// this, snippet output prints a neighbouring key in full because the rule
	// that found it was filtered out of the report while its bytes stayed in the
	// context block of a different finding.
	//
	// Known secrets are censored by exact match, so this costs nothing in
	// readability. Secrets no rule matched cannot be known here at all; those
	// are caught by the heuristic pass at the output boundary.
	if !e.config.DangerouslyShowSecrets {
		redactFileSecrets(filtered, collectFileSecrets(all))
	}

	e.findingsKept.Add(int64(len(filtered)))
	return filtered
}

// collectFileSecrets returns the distinct raw values in fs, longest first.
//
// Longest first so that a value containing another value is censored as a whole
// rather than leaving its own fragment behind. detect runs one goroutine per
// file, so no synchronisation is needed here.
func collectFileSecrets(fs []findings.Finding) []string {
	if len(fs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(fs))
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		if f.Value == "" || findings.IsCensoredToken(f.Value) {
			continue
		}
		if _, dup := seen[f.Value]; dup {
			continue
		}
		seen[f.Value] = struct{}{}
		out = append(out, f.Value)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// redactFileSecrets censors every known secret of the file out of the evidence
// attached to the findings that survived filtering.
func redactFileSecrets(fs []findings.Finding, secrets []string) {
	if len(fs) == 0 || len(secrets) == 0 {
		return
	}
	for i := range fs {
		fs[i].SourceLine = findings.CensorEvidence(fs[i].SourceLine, secrets)
		fs[i].Context = findings.CensorEvidence(fs[i].Context, secrets)
	}
}

// attachEvidence fills in Context and SourceLine from the file's line index.
func attachEvidence(file *filesystem.File, fs []findings.Finding) {
	if len(fs) == 0 {
		return
	}
	li := file.Lines()
	if li == nil {
		return
	}
	for i := range fs {
		if fs[i].Line <= 0 {
			continue
		}
		fs[i].Context = li.Context(fs[i].Line-1, 2)
		fs[i].SourceLine = strings.TrimSpace(li.LineText(fs[i].Line - 1))
	}
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

	// Progress-display only. The authoritative counts live on the Engine and
	// are incremented where the work actually happened.
	var filesProcessed atomic.Int64
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
							fmt.Fprintf(os.Stderr, "warning: memory limit (%d MB) reached; stopping scan early\n", e.config.MemoryLimitMB)
						}
						e.noteIncomplete(ReasonMemoryLimit)
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
			defer wg.Done()
			// A panic must not take the worker down silently. Whatever the
			// worker had not reached when it died was never scanned, so that
			// is counted and reported rather than folded into a clean result.
			defer func() {
				if r := recover(); r != nil {
					fmt.Fprintf(os.Stderr, "panic in detector goroutine: %v\n", r)
					e.noteIncomplete(ReasonWorkerPanic)
				}
			}()
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
					filesProcessed.Add(1)
					resultCh <- result{findings: fResults}
				}()

				if e.config.Verbose && filesProcessed.Load()%100 == 0 {
					fmt.Fprintf(os.Stderr, "\rScanning: %d/%d files (%d findings)", filesProcessed.Load(), totalFiles, findingsFound.Load())
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

// evaluate applies the policy to each finding and records the resulting action.
//
// It deliberately does not rewrite f.Value, even for a redaction action. An
// earlier version replaced the value with a constant here, which meant the
// engine decided disclosure before the output layer knew whether the user had
// passed --dangerously-show-secrets, so that flag revealed the literal string
// "<REDACTED>" instead of the secret. It also collapsed every high-severity
// finding onto one identical token, destroying the ability to tell two findings
// apart or correlate one across runs.
//
// Leaving the value intact does not weaken redaction: the evidence has already
// been stripped of every known secret by detect, and CensorReport at the output
// boundary replaces the value with a per-secret token unless the user explicitly
// asked for the raw value.
func (e *Engine) evaluate(fs []findings.Finding) []findings.Finding {
	evaluated := make([]findings.Finding, 0, len(fs))
	for _, f := range fs {
		action := policy.Evaluate(f, e.policies)
		f.Action = action
		f.Reason = string(action) + ": " + f.Reason
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
