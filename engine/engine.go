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

// Reasons a scan may be incomplete. Every one of these must reach the report
// and the exit code: a scan that did not finish must never read as clean.
const (
	ReasonMemoryLimit = "memory limit reached; scan stopped early"
	ReasonFindingCap  = "finding cap reached; some findings were dropped"
	ReasonFileBudget  = "a file produced more findings than its budget allowed"
	ReasonWorkerPanic = "a detector panicked; files it had not reached were not scanned"
	ReasonMaxFiles    = "max files limit reached; only part of the tree was scanned"
	// ReasonUnreadable records paths the walk could not open. A path that could
	// not be read was not inspected, so the scan does not know what it holds.
	ReasonUnreadable = "one or more paths could not be read; their contents were not inspected"
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
	policies  []policy.PolicyRule
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
	// inlineSuppressed counts findings removed by an inline suppression
	// comment in the scanned content.
	inlineSuppressed atomic.Int64
	// suppressionsApplied counts findings removed by the suppression file.
	suppressionsApplied atomic.Int64
	// baseline/baselineNew hold the loaded baseline and the findings that were
	// new against it, so the save can happen after the report is final.
	// suppressErr defers a suppression-file read failure to finalize's caller
	// rather than reporting findings the user believes they silenced. Both are
	// guarded by mu: Run resets them, and an Engine may be reused concurrently.
	baseline    *findings.Baseline
	baselineNew []findings.Finding
	suppressErr error
	// findingsDiscarded counts findings detectors dropped because a file's
	// per-file budget was exhausted, plus findings dropped because the global
	// budget was already spent when a file started.
	findingsDiscarded atomic.Int64
	// incompleteReasons records why a scan did not finish. Guarded by mu
	// because workers and the memory monitor both append.
	mu                sync.Mutex
	incompleteReasons []string
	// unreadablePaths is a bounded sample of paths the walk could not open,
	// and unreadableSeen de-duplicates the walker's double report of an
	// unreadable directory.
	unreadablePaths []string
	unreadableSeen  map[string]bool
	// skipStats mirrors the walker's coverage accounting into the report.
	skipStatsMu sync.Mutex
	skipStats   *filesystem.WalkStats
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

// fileBudgetFor returns how many findings a single file may contribute when the
// scan covers nFiles files.
//
// The share is a deterministic function of the cap and the file count, and is
// uniform across files.
//
// This replaced a shared atomic pool that workers raced to draw from. A pool is
// attractive — it never under-fills the cap — but "which files were admitted
// before the pool ran dry" is a function of goroutine scheduling, so every
// counter derived from it varied between identical runs of the same tree: the
// retained finding set, the dropped count, and the number of files skipped.
// With a pool, some files were also skipped wholesale, which is a coverage gap
// no report described.
//
// The trade-off is explicit and deliberate: on a tree with many files each file
// is capped at cap/nFiles, so a wide tree can under-fill the cap and a single
// very noisy file is truncated. Total materialised findings stay bounded by the
// cap, no file is ever skipped, and every reported number is reproducible.
// `--max-findings 0` removes the cap entirely.
func (e *Engine) fileBudgetFor(nFiles int) int {
	limit := e.maxFindings()
	if limit <= 0 {
		return filesystem.FindingBudgetUnlimited
	}
	if nFiles <= 1 {
		return limit
	}
	share := (limit + nFiles - 1) / nFiles // ceiling division
	if share < 1 {
		share = 1
	}
	return share
}

// noteBudgetDiscard records findings a detector had to drop because the file's
// budget was spent. Without this the report understated how much was lost: the
// per-file discard happened before trimToConfidenceCap ever saw the findings,
// so it was counted nowhere.
func (e *Engine) noteBudgetDiscard(file *filesystem.File, before int) {
	if !file.FindingBudgetHit {
		return
	}
	e.noteIncomplete(ReasonFileBudget)
	if dropped := before - file.RemainingFindingBudget(); dropped > 0 {
		e.findingsDiscarded.Add(int64(dropped))
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

// onWalkError records a path the walk could not inspect.
//
// WalkOption.OnError was declared and invoked at three sites in the walker but
// no caller ever set it, so an unreadable directory vanished with no
// files_skipped, no files_failed, no coverage line and no Incomplete flag: a
// tree containing `chmod 000 secrets/` reported "No secrets or sensitive data
// detected" and exited 0. The walker's own contract — "a file that was not
// inspected is a coverage gap, and a security scanner should make 'clean' hard
// to reach by accident" — was not upheld by any of its callers.
//
// An unreadable path is now counted as a failed file and marks the scan
// incomplete, so it exits 2 rather than reading as clean.
//
// The walker reports the same path twice for an unreadable directory — once for
// the entry error and once for the failed directory read — so paths are
// de-duplicated and counted once each.
// walkErrorReporter returns an OnError callback bound to one scan's root, so
// that walk failures are labelled relative to it. The root is captured rather
// than stored because an Engine may have more than one scan in flight.
func (e *Engine) walkErrorReporter(root string) func(string, error) {
	return func(path string, err error) { e.onWalkError(root, path, err) }
}

func (e *Engine) onWalkError(root, path string, err error) {
	label := relativeToRoot(root, path)
	if e.recordUnreadable(label) {
		e.filesFailed.Add(1)
		e.noteIncomplete(ReasonUnreadable)
	}
	if e.config.Verbose {
		fmt.Fprintf(os.Stderr, "minesweep: cannot inspect %s: %v\n", label, err)
	}
}

// recordUnreadable notes a path that could not be inspected and reports whether
// it was not already recorded. The walker reports the same directory twice (an
// entry error and a failed read) and the same file can fail in more than one
// place, so de-duplication happens here rather than at each call site.
func (e *Engine) recordUnreadable(label string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.unreadableSeen == nil {
		e.unreadableSeen = make(map[string]bool)
	}
	if e.unreadableSeen[label] {
		return false
	}
	e.unreadableSeen[label] = true
	if len(e.unreadablePaths) < maxRecordedUnreadable {
		e.unreadablePaths = append(e.unreadablePaths, label)
	}
	return true
}

// relativeToRoot renders a walked path the way every other skip reason is
// rendered: relative to the scan root, so the report is stable across machines
// and does not disclose the local directory layout.
func relativeToRoot(root, path string) string {
	if root == "" {
		return filepath.Base(path)
	}
	if rel, err := filepath.Rel(root, path); err == nil && rel != "" &&
		rel != "." && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.Base(path)
}

// mustRel returns the slash-separated path of target relative to base, falling
// back to the base name if the two are unrelated.
func mustRel(base, target string) string {
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return filepath.Base(target)
	}
	return rel
}

// maxRecordedUnreadable bounds how many unreadable paths are remembered for
// the report. A hostile or damaged tree can make the count arbitrarily large.
const maxRecordedUnreadable = 10

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
//
// Filtering deliberately happens BEFORE evaluation so that baselines and
// suppression patterns match raw secret values, not redacted ones.
//
// The baseline is the last thing written, and only after the result is
// final. Recording it earlier meant a truncated scan, or one with findings
// suppressed, wrote hashes for findings the user had never actually seen
// triaged: --update-baseline --max-findings 5 reported 5 findings and wrote
// 400 hashes, after which every run reported the tree clean.
func (e *Engine) finalize(root string, allFindings []findings.Finding) (*findings.RiskReport, error) {
	allFindings = relativizeFindings(root, allFindings)
	// Several detectors can independently raise the same finding (regex,
	// entropy, decoded base64 wrapping the same rule). Collapse identical
	// ones before baselines and suppression so counts and hashes stay stable.
	allFindings = dedupFindings(allFindings)

	filtered, err := e.filterBaselineLoad(allFindings)
	if err != nil {
		return nil, err
	}

	filtered = e.filterSuppressionsInPlace(filtered)
	e.mu.Lock()
	suppressErr := e.suppressErr
	e.mu.Unlock()
	if suppressErr != nil {
		return nil, suppressErr
	}

	// Establish a total order BEFORE trimming. trimToConfidenceCap breaks ties
	// on input order, and the input order was the order in which workers
	// finished, which is not a function of the input: three identical runs of
	// one tree over the cap produced three different result sets.
	sortFindings(filtered)

	// The per-file budget can overshoot the global cap by up to one file's
	// worth per worker, so trim here too. When a scan is truncated, the
	// highest-confidence findings are the ones worth keeping.
	filtered, dropped := trimToConfidenceCap(filtered, e.maxFindings())
	if dropped > 0 {
		e.findingsDropped.Add(int64(dropped))
		e.noteIncomplete(ReasonFindingCap)
	}

	if err := e.filterBaselineSave(filtered); err != nil {
		return nil, err
	}

	evaluated := e.evaluate(filtered)
	sortFindings(evaluated)
	rep := findings.GenerateRiskReport(evaluated, e.config.Boundaries)
	return &rep, nil
}

// trimToConfidenceCap keeps the cap highest-confidence findings, preserving
// input order among equal confidences so the result stays deterministic.
// Returns the kept findings and how many were dropped.
//
// Callers must sortFindings first: the tie-break here is positional, so the
// caller's order is part of the result.
func trimToConfidenceCap(fs []findings.Finding, cap int) ([]findings.Finding, int) {
	if cap <= 0 || len(fs) <= cap {
		return fs, 0
	}
	order := make([]int, len(fs))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		ia, ib := order[a], order[b]
		if fs[ia].Confidence != fs[ib].Confidence {
			return fs[ia].Confidence > fs[ib].Confidence
		}
		return ia < ib
	})
	keep := make([]bool, len(fs))
	for _, i := range order[:cap] {
		keep[i] = true
	}
	out := make([]findings.Finding, 0, cap)
	for i, f := range fs {
		if keep[i] {
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

// sortFindings orders findings deterministically so identical scans produce
// byte-identical reports regardless of worker scheduling.
//
// This must be a total order: two findings that agree on every field compared
// here but differ elsewhere would still be ordered arbitrarily, and that
// arbitrariness is what leaks worker scheduling into the output. Confidence is
// not part of the key because it is the primary sort key of
// trimToConfidenceCap, which runs after this and would otherwise have to
// re-establish the order.
func sortFindings(fs []findings.Finding) {
	sort.Slice(fs, func(i, j int) bool {
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
		if a.Value != b.Value {
			return a.Value < b.Value
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if len(a.Tags) != len(b.Tags) {
			return len(a.Tags) < len(b.Tags)
		}
		for k := range a.Tags {
			if a.Tags[k] != b.Tags[k] {
				return a.Tags[k] < b.Tags[k]
			}
		}
		if a.Reason != b.Reason {
			return a.Reason < b.Reason
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Context != b.Context {
			return a.Context < b.Context
		}
		return a.SourceLine < b.SourceLine
	})
}

// filterBaselineLoad removes findings already recorded in the baseline file and
// remembers the loaded baseline for the later save.
func (e *Engine) filterBaselineLoad(fs []findings.Finding) ([]findings.Finding, error) {
	if e.config.BaselineFile == "" {
		return fs, nil
	}
	baseline, err := findings.LoadBaseline(e.config.BaselineFile)
	if err != nil {
		return nil, fmt.Errorf("load baseline: %w", err)
	}
	e.mu.Lock()
	e.baseline = baseline
	e.baselineNew = findings.FilterNewFindings(fs, baseline)
	out := e.baselineNew
	e.mu.Unlock()
	return out, nil
}

// filterBaselineSave records the findings that are actually being reported.
//
// It refuses to write when the scan is incomplete. A baseline written from a
// truncated or partially-unreadable scan permanently blesses findings nobody
// reviewed: the next full scan then reports the tree clean, which is the exact
// outcome the baseline feature exists to prevent.
func (e *Engine) filterBaselineSave(reported []findings.Finding) error {
	if e.config.BaselineFile == "" || !e.config.UpdateBaseline {
		return nil
	}
	e.mu.Lock()
	baseline := e.baseline
	e.mu.Unlock()
	if baseline == nil {
		return nil
	}
	if reasons := e.incomplete(); len(reasons) > 0 {
		return fmt.Errorf("refusing to update the baseline: this scan is incomplete (%s); "+
			"re-run without the limits that truncated it, or without --update-baseline",
			strings.Join(reasons, "; "))
	}
	findings.UpdateBaseline(baseline, reported)
	if err := findings.SaveBaseline(e.config.BaselineFile, baseline); err != nil {
		return fmt.Errorf("save baseline: %w", err)
	}
	return nil
}

// filterSuppressionsInPlace removes findings matching the suppression file.
func (e *Engine) filterSuppressionsInPlace(fs []findings.Finding) []findings.Finding {
	if e.config.SuppressFile == "" {
		return fs
	}
	suppressions, err := findings.LoadSuppressions(e.config.SuppressFile)
	if err != nil {
		// A suppression file that cannot be read is a hard error. Silently
		// ignoring it would report findings the user believes they silenced,
		// and — worse, historically — baseline them.
		e.mu.Lock()
		e.suppressErr = fmt.Errorf("load suppressions: %w", err)
		e.mu.Unlock()
		return fs
	}
	out := findings.FilterSuppressed(fs, suppressions)
	if n := len(fs) - len(out); n > 0 {
		e.suppressionsApplied.Add(int64(n))
	}
	return out
}

func (e *Engine) Run(path string) (*findings.RiskReport, error) {
	e.filesScanned.Store(0)
	e.bytesScanned.Store(0)
	e.filesSkipped.Store(0)
	e.filesFailed.Store(0)
	e.findingsKept.Store(0)
	e.findingsDropped.Store(0)
	e.findingsDiscarded.Store(0)
	e.inlineSuppressed.Store(0)
	e.suppressionsApplied.Store(0)
	e.mu.Lock()
	e.baseline = nil
	e.baselineNew = nil
	e.suppressErr = nil
	e.incompleteReasons = nil
	e.unreadablePaths = nil
	e.unreadableSeen = make(map[string]bool)
	e.mu.Unlock()
	e.setSkipStats(nil)

	start := time.Now()
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
		rep.FindingsDiscarded = int(e.findingsDiscarded.Load())
		rep.FindingsSuppressed = int(e.inlineSuppressed.Load()) + int(e.suppressionsApplied.Load())
		rep.IncompleteReasons = e.incomplete()
		rep.Incomplete = len(rep.IncompleteReasons) > 0
		if len(e.unreadablePaths) > 0 {
			rep.UnreadablePaths = append([]string(nil), e.unreadablePaths...)
		}
		if st := e.getSkipStats(); st != nil {
			rep.SkippedBy = st.Summary()
		}
	}
	return rep, err
}

func (e *Engine) run(path string) (*findings.RiskReport, error) {
	// Resolve the scan root once, up front, and use the resolved form for
	// everything downstream: the walk, the containment checks, and the
	// relativization of reported paths.
	//
	// os.Stat follows symlinks but filepath.WalkDir does not: it Lstats the
	// root and hands a symlinked root to the walk function as a single
	// non-directory entry. The tree was therefore never descended — scanning a
	// symlinked directory reported one info-level "Symlink" finding, exit 0,
	// and no secrets. `--diff`, `--staged` and `--history` resolve symlinks
	// (via git rev-parse), so the four modes disagreed about the same tree.
	//
	// Canonicalising here is also what keeps reported paths stable: git
	// reports the toplevel with symlinks resolved, so a root left unresolved
	// produced absolute paths in every --staged report (and machine-specific
	// baseline entries) whenever any ancestor was a symlink. That is H2, fixed
	// at the same layer, because it is the same asymmetry.
	resolved, err := filesystem.ResolveRoot(path)
	if err != nil {
		return nil, err
	}
	path = resolved

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat path: %w", err)
	}

	// The scan mode is decided BEFORE the directory check. It used to be
	// decided after, so any single-file path bypassed --staged, --diff and
	// --history entirely and silently scanned the working tree instead. In a
	// pre-commit scan that reads the wrong content in both directions: it
	// reported unstaged edits as if they were staged, and — with the index
	// holding a secret that the working tree no longer has — it reported
	// nothing at all and exited 0.
	// Per-run state is passed down rather than stored on the Engine: an Engine
	// may legitimately have Run called on it more than once, including
	// concurrently, so nothing about one scan may live in a field.
	scope := ""
	if !info.IsDir() {
		scope = path
	}

	if e.config.DiffMode || e.config.StagedOnly {
		return e.runScopedDiff(path, scope)
	}
	if e.config.HistoryMode {
		if scope != "" {
			return e.runHistory(filepath.Dir(scope), scope)
		}
		return e.runHistory(path, "")
	}

	if !info.IsDir() {
		return e.runSingleFile(path)
	}

	report, err := e.runDirectory(path)
	if err != nil {
		return nil, err
	}
	return report, nil
}

// runScopedDiff handles --staged/--diff against a target that may be a single
// file.
//
// git needs a directory to answer rev-parse, so for a file target the git
// operations run from the containing directory and the result is narrowed to
// the file. Narrowing happens after the git queries rather than before, so
// `--staged ./f` still sees the same index the full scan would.
func (e *Engine) runScopedDiff(target, scope string) (*findings.RiskReport, error) {
	if scope == "" {
		return e.runDiff(target, "")
	}
	return e.runDiff(filepath.Dir(scope), scope)
}

func (e *Engine) runDiff(root, scopeFile string) (*findings.RiskReport, error) {
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
		if scopeFile != "" && absPath != scopeFile {
			continue // a single file was named; only it is in scope
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

	allFindings := e.detectParallel(files)
	return e.finalize(root, allFindings)
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
//
// It is only reachable when no git-scoped mode is set; --staged/--diff on a
// single file is routed through runDiff so the index, not the working tree, is
// what gets scanned.
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

	allFindings := e.detect(file, e.fileBudgetFor(1))
	return e.finalize(dir, allFindings)
}

// runHistory scans every unique blob reachable from all refs. Cost scales
// with content diversity, not commit count: each object is fetched and
// scanned exactly once, then findings are attributed to the commit that
// introduced them.
func (e *Engine) runHistory(root, scopeFile string) (*findings.RiskReport, error) {
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
		if scopeFile != "" {
			// A single file was named. History object paths are
			// repository-relative and have no filesystem entry, so compare
			// against the named file's path relative to the repository.
			want := filepath.ToSlash(mustRel(top, scopeFile))
			if obj.Path != want {
				continue
			}
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
		OnError:          e.walkErrorReporter(root),
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}
	e.filesSkipped.Store(int64(stats.Total()))

	// Apply max files limit
	if e.config.MaxFiles > 0 && len(files) > e.config.MaxFiles {
		files = files[:e.config.MaxFiles]
		e.noteIncomplete(ReasonMaxFiles)
		fmt.Fprintf(os.Stderr, "warning: reached max files limit (%d), scanning first %d files\n", e.config.MaxFiles, e.config.MaxFiles)
	}

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

// detect runs every detector over one file, then filters, then attaches
// evidence to the survivors.
//
// budget is how many findings this file may contribute; see fileBudgetFor.
//
// The order matters for memory. Content is loaded here and nowhere else, the
// file is released before returning, and the surrounding source lines — the
// largest field on a finding — are built only for findings that survive
// filtering. Doing evidence first and filtering afterwards meant allocating
// context blocks for the ~99% of findings that were about to be discarded.
func (e *Engine) detect(file *filesystem.File, budget int) []findings.Finding {
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
	content, err := file.GetContent()
	if err != nil {
		// A file that could not be read was not inspected. Nothing is known
		// about what it holds, so the scan cannot claim to be complete. This
		// also covers content delivered by a loader — a git blob whose path
		// git quoted, for instance — which fails the same way.
		e.filesFailed.Add(1)
		e.noteIncomplete(ReasonUnreadable)
		e.recordUnreadable(file.Path)
		if e.config.Verbose {
			fmt.Fprintf(os.Stderr, "minesweep: %s: %v\n", file.Path, err)
		}
		return nil
	}
	e.filesScanned.Add(1)
	e.bytesScanned.Add(int64(len(content)))

	file.SetFindingBudget(budget)
	defer e.noteBudgetDiscard(file, budget)

	if e.readSemaphore != nil {
		e.readSemaphore <- struct{}{}
		defer func() { <-e.readSemaphore }()
	}

	var all []findings.Finding
	for _, d := range e.detectors {
		all = append(all, d.Detect(file)...)
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
			kept := findings.FilterInlineSuppressionsLines(filtered, li)
			// A finding removed by an inline suppression is a coverage gap
			// like any other: it was detected and then deliberately not
			// reported. It is counted so the report can say so, rather than
			// vanishing without trace.
			if n := len(filtered) - len(kept); n > 0 {
				e.inlineSuppressed.Add(int64(n))
			}
			filtered = kept
		}
	}

	// Evidence last: only for findings that are actually reported.
	attachEvidence(file, filtered)

	e.findingsKept.Add(int64(len(filtered)))
	return filtered
}

// attachEvidence fills in Context and SourceLine from the file's line index.
//
// Two guarantees are enforced here rather than at the output boundary, because
// the output boundary is not the only consumer and it cannot undo an allocation
// that has already been made:
//
//   - Binary content is never copied into a finding. Arbitrary bytes defeat
//     every redaction heuristic in report/, and findings without a Value (the
//     file-type and symlink detectors) bypass the heuristic pass entirely, so a
//     SQLite database used to land its credentials in the report verbatim.
//   - Every rendered line is capped. "A line" is not bounded by anything: a
//     database, a minified bundle or a single-line JSON blob has no newline for
//     megabytes.
func attachEvidence(file *filesystem.File, fs []findings.Finding) {
	if len(fs) == 0 {
		return
	}
	if file.IsBinary {
		note := findings.BinaryEvidence(int(file.Size))
		for i := range fs {
			fs[i].Context = note
			fs[i].SourceLine = note
		}
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
		fs[i].Context = li.ContextCapped(fs[i].Line-1, evidenceRadius, maxEvidenceLineBytes)
		fs[i].SourceLine = clampEvidenceLine(strings.TrimSpace(li.LineText(fs[i].Line - 1)))
	}
}

const (
	// evidenceRadius is the number of lines of context rendered either side
	// of a finding.
	evidenceRadius = 2
	// maxEvidenceLineBytes caps one rendered evidence line. 512 keeps a
	// credential assignment and its neighbours readable while making the
	// report size proportional to the finding count, not to the file size.
	maxEvidenceLineBytes = 512
)

// clampEvidenceLine truncates one evidence line to maxEvidenceLineBytes,
// marking the cut so a reader can tell the line was clipped rather than short.
func clampEvidenceLine(s string) string {
	capped := filesystem.CapLine(s, maxEvidenceLineBytes)
	if capped == s {
		return s
	}
	return capped + " " + findings.TruncatedEvidenceSuffix
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

	// One deterministic allowance for every file, so the run is reproducible
	// and no file is skipped outright. See fileBudgetFor.
	budget := e.fileBudgetFor(len(files))

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
					fResults := e.detect(file, budget)
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
