package filesystem

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// IgnoreFileNames are the accepted ignore-file names. The two are fully
// equivalent; when both exist in one directory their rules are merged, and
// rules later in the merged order win, so a tie is broken deterministically.
var IgnoreFileNames = []string{".minesweepignore", ".msignore"}

// ignoreRule is one normalized line of an ignore file.
type ignoreRule struct {
	pattern string // no leading or trailing separator
	negate  bool   // "!pattern" — re-include
	dirOnly bool   // trailing "/" — directories only
	// anchored means the pattern must match from the base directory rather
	// than any basename at any depth. A pattern is anchored if it carried a
	// leading or interior separator.
	anchored bool
}

// IgnorePattern is an ordered rule set. Last match wins, so a later rule
// overrides an earlier one and a later negation re-includes.
type IgnorePattern struct {
	rules []ignoreRule
}

func NewIgnorePattern(patterns []string) *IgnorePattern {
	ip := &IgnorePattern{}
	for _, line := range patterns {
		rule, ok := parseIgnoreRule(line)
		if !ok {
			continue
		}
		ip.rules = append(ip.rules, rule)
	}
	return ip
}

func parseIgnoreRule(line string) (ignoreRule, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ignoreRule{}, false
	}
	var rule ignoreRule
	if strings.HasPrefix(line, "!") {
		rule.negate = true
		line = strings.TrimSpace(line[1:])
	}
	// A trailing separator marks a directory-only pattern.
	if strings.HasSuffix(line, "/") {
		rule.dirOnly = true
		line = strings.TrimSuffix(line, "/")
	}
	// A leading separator anchors the pattern to the base directory. Any
	// other interior separator anchors it too, matching git.
	anchored := strings.HasPrefix(line, "/") || strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")
	if line == "" {
		return ignoreRule{}, false
	}
	rule.pattern = filepath.ToSlash(line)
	rule.anchored = anchored
	return rule, true
}

func (r ignoreRule) String() string {
	s := r.pattern
	if r.negate {
		s = "!" + s
	}
	if r.dirOnly {
		s += "/"
	}
	return s
}

// matches reports whether the rule excludes the given slash-separated path,
// which is relative to the directory the rule was declared in.
func (r ignoreRule) matches(rel string) bool {
	if r.anchored {
		// Either the path itself, or any ancestor directory: a rule that
		// matches a directory covers everything beneath it, which is what
		// makes `test/fixtures` exclude `test/fixtures/e.env`.
		if !r.dirOnly && globMatch(r.pattern, rel) {
			return true
		}
		for _, anc := range ancestorDirs(rel) {
			if globMatch(r.pattern, anc) {
				return true
			}
		}
		return false
	}
	// Unanchored: match the basename of the path or of any ancestor, so
	// `node_modules` covers `a/node_modules/pkg.js`.
	if !r.dirOnly && globMatch(r.pattern, pathBase(rel)) {
		return true
	}
	for _, anc := range ancestorDirs(rel) {
		if globMatch(r.pattern, pathBase(anc)) {
			return true
		}
	}
	return false
}

// decide returns whether rel is ignored and whether any rule matched at all.
// The second value lets a nested ignore file override a shallower one, which
// is what git does for files below a subdirectory.
func (ip *IgnorePattern) decide(rel string) (ignored bool, matched bool) {
	if ip == nil || len(ip.rules) == 0 {
		return false, false
	}
	rel = filepath.ToSlash(rel)
	for _, r := range ip.rules {
		if r.matches(rel) {
			ignored = !r.negate
			matched = true
		}
	}
	return ignored, matched
}

// Ignored reports whether rel is excluded by this rule set.
func (ip *IgnorePattern) Ignored(rel string) bool {
	ignored, _ := ip.decide(rel)
	return ignored
}

// Rules exposes the parsed rules, for diagnostics.
func (ip *IgnorePattern) Rules() []string {
	if ip == nil {
		return nil
	}
	out := make([]string, 0, len(ip.rules))
	for _, r := range ip.rules {
		out = append(out, r.String())
	}
	return out
}

// ancestorDirs returns every proper ancestor of a slash-separated path,
// shallowest first: "a/b/c.env" yields "a", "a/b".
func ancestorDirs(rel string) []string {
	var out []string
	for i := 0; i < len(rel); i++ {
		if rel[i] == '/' {
			out = append(out, rel[:i])
		}
	}
	return out
}

func pathBase(rel string) string {
	if i := strings.LastIndex(rel, "/"); i >= 0 {
		return rel[i+1:]
	}
	return rel
}

// relUnder returns the portion of rel below dir, and whether rel is inside
// dir at all.
func relUnder(dir, rel string) (string, bool) {
	if dir == "" {
		return rel, true
	}
	if rel == dir {
		return "", false
	}
	if strings.HasPrefix(rel, dir+"/") {
		return rel[len(dir)+1:], true
	}
	return "", false
}

// globMatch matches a slash-separated pattern against a slash-separated path,
// with `**` spanning any number of path segments.
func globMatch(pattern, path string) bool {
	return matchGlobParts(strings.Split(pattern, "/"), strings.Split(path, "/"))
}

func matchGlobParts(pattern, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}
	if len(path) == 0 {
		return false
	}

	if pattern[0] == "**" {
		if matchGlobParts(pattern[1:], path) {
			return true
		}
		return matchGlobParts(pattern, path[1:])
	}

	m, _ := filepath.Match(pattern[0], path[0])
	if !m {
		return false
	}
	return matchGlobParts(pattern[1:], path[1:])
}

// IgnoreSet is the complete ignore configuration for a scan: the rule set
// discovered from the scan root and its ancestors, plus any rule sets found
// in subdirectories during traversal. Nested sets are applied after the base
// set, shallowest first, so the nearest declaration wins.
type IgnoreSet struct {
	base   *IgnorePattern
	nested map[string]*IgnorePattern
}

// NewIgnoreSet builds a set from an explicit base rule set.
func NewIgnoreSet(base *IgnorePattern) *IgnoreSet {
	if base == nil {
		base = NewIgnorePattern(nil)
	}
	return &IgnoreSet{base: base}
}

// EmptyIgnoreSet is a set that excludes nothing.
func EmptyIgnoreSet() *IgnoreSet { return NewIgnoreSet(NewIgnorePattern(nil)) }

// LoadIgnoreFile reads one ignore file's lines. A missing file yields no
// lines and no error; an unreadable or malformed one is an error, because
// silently scanning with fewer rules than the user wrote is a false negative
// wearing a success message.
func LoadIgnoreFile(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // reading an ignore file the caller named
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open ignore file %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only handle

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read ignore file %q: %w", path, err)
	}
	return lines, nil
}

// LoadIgnoreForDir merges every ignore file present in dir. It returns nil
// when the directory has none.
func LoadIgnoreForDir(dir string) (*IgnorePattern, error) {
	var lines []string
	found := false
	for _, name := range IgnoreFileNames {
		ls, err := LoadIgnoreFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if len(ls) > 0 {
			found = true
			lines = append(lines, ls...)
		}
	}
	if !found {
		return nil, nil
	}
	return NewIgnorePattern(lines), nil
}

// LoadMinesweepIgnore loads a single ignore file by path. It is the
// single-file form of LoadIgnoreForDir; a missing file yields an empty rule
// set rather than an error.
func LoadMinesweepIgnore(path string) (*IgnorePattern, error) {
	lines, err := LoadIgnoreFile(path)
	if err != nil {
		return nil, err
	}
	return NewIgnorePattern(lines), nil
}

// ignoreSearchDirs lists the directories to search for ignore files when
// discovering configuration for start, outermost first.
//
// Discovery stops at the enclosing git repository root, or at the filesystem
// root when start is not in a repository. Bounding the walk at the repository
// keeps a stray ~/.minesweepignore from silently narrowing every scan on the
// machine, which would remove coverage nobody asked to remove.
func ignoreSearchDirs(start string) []string {
	dir, err := filepath.Abs(start)
	if err != nil {
		return nil
	}
	// Walk up to the repository root, if any.
	stop := ""
	if top, err := runGitTopLevel(dir); err == nil && top != "" {
		stop = top
	}
	var chain []string
	for {
		chain = append(chain, dir)
		if stop != "" && sameDir(dir, stop) {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		if stop != "" && !isWithin(parent, stop) {
			// Reached the filesystem root without hitting the repo root.
			chain = append(chain, parent)
			break
		}
		dir = parent
	}
	// Reverse to outermost-first.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

func sameDir(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 != nil {
		ra = a
	}
	if err2 != nil {
		rb = b
	}
	return filepath.Clean(ra) == filepath.Clean(rb)
}

func isWithin(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func runGitTopLevel(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--show-toplevel") //nolint:gosec // fixed arguments
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// DiscoverIgnore builds the ignore set for a scan rooted at root: every
// ignore file from the outermost relevant ancestor down to root, merged in
// that order so nearer declarations win.
func DiscoverIgnore(root string) (*IgnoreSet, error) {
	var lines []string
	seen := make(map[string]bool)
	for _, dir := range ignoreSearchDirs(root) {
		for _, name := range IgnoreFileNames {
			p := filepath.Join(dir, name)
			key := p
			if abs, err := filepath.Abs(p); err == nil {
				key = abs
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			ls, err := LoadIgnoreFile(p)
			if err != nil {
				return nil, err
			}
			lines = append(lines, ls...)
		}
	}
	return NewIgnoreSet(NewIgnorePattern(lines)), nil
}

// AddNested registers the rule set found in a subdirectory, so it applies to
// paths beneath it. dir is relative to the scan root.
func (s *IgnoreSet) AddNested(dir string, p *IgnorePattern) {
	if p == nil || len(p.rules) == 0 {
		return
	}
	if s.nested == nil {
		s.nested = make(map[string]*IgnorePattern)
	}
	key := strings.Trim(filepath.ToSlash(dir), "/")
	if key == "" {
		// An ignore file at the scan root is already the base set.
		s.base = mergePatterns(s.base, p)
		return
	}
	if existing := s.nested[key]; existing != nil {
		s.nested[key] = mergePatterns(existing, p)
		return
	}
	s.nested[key] = p
}

// Ignored reports whether rel (relative to the scan root) is excluded. Base
// rules are applied first, then each nested rule set from shallowest to
// deepest, so the nearest declaration has the final say.
func (s *IgnoreSet) Ignored(rel string) bool {
	if s == nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	ignored, _ := s.base.decide(rel)
	if len(s.nested) == 0 {
		return ignored
	}
	for _, dir := range ancestorDirs(rel) {
		p := s.nested[dir]
		if p == nil {
			continue
		}
		sub, ok := relUnder(dir, rel)
		if !ok {
			continue
		}
		if v, matched := p.decide(sub); matched {
			ignored = v
		}
	}
	return ignored
}

// Base exposes the root-level rule set.
func (s *IgnoreSet) Base() *IgnorePattern {
	if s == nil {
		return nil
	}
	return s.base
}

func mergePatterns(a, b *IgnorePattern) *IgnorePattern {
	combined := make([]ignoreRule, 0, len(a.rules)+len(b.rules))
	combined = append(combined, a.rules...)
	combined = append(combined, b.rules...)
	return &IgnorePattern{rules: combined}
}

var DefaultSkipExtensions = []string{
	".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
	".mp4", ".avi", ".mov", ".mkv",
	".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib", ".class", ".pyc",
	".DS_Store", ".DS_Store?",
	".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
	".woff", ".woff2", ".ttf", ".eot",
	".min.js", ".min.css",
	".lock", ".sum",
}

var DefaultSkipDirs = []string{
	".git", ".svn", ".hg",
	"node_modules", "vendor", "dist", "build", "target", "out",
	".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache",
	".idea", ".vscode", ".eclipse", ".project",
	"coverage", ".nyc_output",
	"tmp", "temp", ".tmp",
	".gradle", ".m2",
	"Pods", ".cocoapods",
	".terraform", ".terraform.lock.hcl",
	"elm-stuff", ".dart_tool",
}

const DefaultMaxFileSize int64 = 50 * 1024 * 1024 // 50MB

// SkipReason names why a file was excluded from a scan. Every reason is
// reported back to the user: a file that was not inspected is a coverage gap,
// and a security scanner should make "clean" hard to reach by accident.
type SkipReason string

const (
	SkipReasonIgnore  SkipReason = "ignore-file"
	SkipReasonExt     SkipReason = "extension"
	SkipReasonTest    SkipReason = "test-file"
	SkipReasonLarge   SkipReason = "size"
	SkipReasonSkipDir SkipReason = "skip-dir"
	SkipReasonVCS     SkipReason = "vcs-internals"
)

// SkipReasons is the fixed reporting order, most- to least-common by default.
var SkipReasons = []SkipReason{
	SkipReasonExt,
	SkipReasonSkipDir,
	SkipReasonIgnore,
	SkipReasonTest,
	SkipReasonLarge,
	SkipReasonVCS,
}

// WalkStats records what the walk chose not to include, so callers can
// surface coverage gaps instead of skipping silently.
type WalkStats struct {
	SkippedIgnore  int
	SkippedExt     int
	SkippedTest    int
	SkippedLarge   int
	SkippedSymlink int
	SkippedVendor  int // files under pruned dirs (node_modules, vendor, ...)
	Kept           int

	// ByReason breaks the counts above down by cause, and Examples keeps a
	// bounded sample of the actual paths so a report can name what was
	// dropped rather than only counting it. MaxExamples caps the sample
	// (default 8); set to -1 to retain every path (--show-ignored).
	ByReason    map[SkipReason]int
	Examples    map[SkipReason][]string
	MaxExamples int
}

const skipExampleLimit = 8

func (ws *WalkStats) exampleLimit() int {
	if ws.MaxExamples < 0 {
		return int(^uint(0) >> 1) // unlimited
	}
	if ws.MaxExamples > 0 {
		return ws.MaxExamples
	}
	return skipExampleLimit
}

// Note records that path was skipped for the given reason, keeping a bounded
// sample of examples.
func (ws *WalkStats) Note(reason SkipReason, path string) {
	if ws.ByReason == nil {
		ws.ByReason = make(map[SkipReason]int)
		ws.Examples = make(map[SkipReason][]string)
	}
	ws.ByReason[reason]++
	ex := ws.Examples[reason]
	if len(ex) < ws.exampleLimit() {
		ws.Examples[reason] = append(ex, path)
	}
}

// Total returns the number of files excluded, by reason.
func (ws *WalkStats) Total() int {
	n := 0
	for _, r := range SkipReasons {
		n += ws.ByReason[r]
	}
	if n == 0 {
		return ws.TotalSkipped()
	}
	return n
}

// Summary renders a one-line-per-cause breakdown suitable for a report, with
// example paths. Only causes that actually dropped something are listed.
func (ws *WalkStats) Summary() []string {
	if len(ws.ByReason) == 0 {
		return nil
	}
	out := make([]string, 0, len(SkipReasons))
	for _, r := range SkipReasons {
		n := ws.ByReason[r]
		if n == 0 {
			continue
		}
		line := fmt.Sprintf("%d %s", n, r)
		if ex := ws.Examples[r]; len(ex) > 0 {
			joined := strings.Join(ex, ", ")
			if len(ex) < n {
				line += " (e.g. " + joined + ")"
			} else {
				line += ": " + joined
			}
		}
		out = append(out, line)
	}
	return out
}

func (ws *WalkStats) TotalSkipped() int {
	return ws.SkippedIgnore + ws.SkippedExt + ws.SkippedTest + ws.SkippedLarge +
		ws.SkippedSymlink + ws.SkippedVendor
}

type WalkOption struct {
	Stats            *WalkStats
	Ignore           *IgnorePattern
	IgnoreFilePath   string
	MaxFileSize      int64
	OnError          func(path string, err error)
	SkipExtensions   []string
	SkipDirs         []string
	IncludeTestFiles bool
	// NoIgnore disables .minesweepignore/.msignore entirely, including
	// nested files. It is the deliberate override, not the default.
	NoIgnore bool
	// ignoreRoot is where ignore-file discovery starts. It is set
	// internally so the walker and SkipChecker resolve configuration
	// identically.
	ignoreRoot string
}

// ResolveRoot returns the canonical absolute form of a scan target.
//
// Symlinks are resolved as far as they exist and the missing tail of a
// not-yet-created path is re-attached, so the result is stable for both
// existing and not-yet-existing targets. A path that cannot be resolved at all
// falls back to the lexical absolute form, which is the best answer available.
func ResolveRoot(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve path %q: %w", path, err)
	}
	if resolved, rErr := filepath.EvalSymlinks(abs); rErr == nil {
		return resolved, nil
	}
	dir, tail := abs, ""
	for range 256 { // bounded: a path this deep is pathological
		parent := filepath.Dir(dir)
		if parent == dir {
			return abs, nil
		}
		tail = filepath.Join(filepath.Base(dir), tail)
		dir = parent
		if resolved, rErr := filepath.EvalSymlinks(dir); rErr == nil {
			return filepath.Join(resolved, tail), nil
		}
	}
	return abs, nil
}

func Walk(root string, ignore *IgnorePattern, ignoreFilePath string) ([]*File, error) {
	return WalkWithOptions(root, WalkOption{
		Ignore:         ignore,
		IgnoreFilePath: ignoreFilePath,
		MaxFileSize:    DefaultMaxFileSize,
	})
}

func WalkWithOptions(root string, opts WalkOption) ([]*File, error) {
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}
	return walkWithOptions(root, opts)
}

// resolveIgnoreSet produces the ignore set for a scan. An explicit Ignore in
// the options is honored as-is; otherwise the set is discovered from the scan
// root and its ancestors. A malformed or unreadable ignore file is an error:
// proceeding with fewer rules than the user wrote would report a clean scan
// while silently skipping what they asked to skip, which is the failure mode
// this tool exists to prevent.
func resolveIgnoreSet(root string, opts WalkOption) (*IgnoreSet, error) {
	if opts.NoIgnore {
		return EmptyIgnoreSet(), nil
	}
	if opts.Ignore != nil {
		return NewIgnoreSet(opts.Ignore), nil
	}
	if opts.IgnoreFilePath != "" {
		lines, err := LoadIgnoreFile(opts.IgnoreFilePath)
		if err != nil {
			return nil, err
		}
		return NewIgnoreSet(NewIgnorePattern(lines)), nil
	}
	return DiscoverIgnore(root)
}

func walkWithOptions(root string, opts WalkOption) ([]*File, error) {
	// Resolve the root before walking. filepath.WalkDir Lstats the root, so a
	// symlinked root is handed to the walk function as a single non-directory
	// entry and the tree is never descended — the walk "succeeds", reports
	// nothing, and the caller concludes the target was clean. Resolving here
	// makes the function safe to call directly, not only through the engine.
	if resolved, err := ResolveRoot(root); err == nil {
		root = resolved
	}
	opts.ignoreRoot = root
	fs, err := newFilterSet(opts)
	if err != nil {
		return nil, err
	}
	ip := fs.ignore

	// .git alone is pruned during traversal (its contents are not project
	// data); other skip-dirs are DESCENDED so their files can be counted,
	// keeping the skipped-coverage number honest.
	gitDir := filepath.Join(root, ".git") + string(filepath.Separator)

	// Only directories WITHIN the scan root count: an ancestor segment
	// that happens to share a name with a skip dir (/tmp scanning, a
	// ~/go/src checkout, ...) must not nuke the whole walk.
	isInSkipDir := func(rel string) bool {
		segs := strings.Split(rel, string(filepath.Separator))
		if len(segs) < 2 {
			return false
		}
		for _, seg := range segs[:len(segs)-1] {
			if fs.skipDirSet[seg] {
				return true
			}
		}
		return false
	}

	var files []*File
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			return nil
		}
		if d.IsDir() {
			// Prune only VCS internals; everything else is descended so
			// its files are counted as skipped rather than vanishing.
			if name := d.Name(); name == ".git" || name == ".hg" || name == ".svn" {
				return filepath.SkipDir
			}
			// Attempt to open the directory; if we cannot, this is a genuine
			// coverage gap, not a config error.
			if _, err := os.ReadDir(path); err != nil {
				if opts.OnError != nil {
					opts.OnError(path, err)
				}
				return nil // Skip this subtree entirely
			}
			// A nested ignore file scopes to its own directory, so record
			// it against the path relative to the scan root. The root's own
			// file is already part of the discovered base set.
			if !opts.NoIgnore {
				if nested, nerr := LoadIgnoreForDir(path); nerr != nil {
					// An unreadable ignore file is a real source of confusion
					// (it claims to exist but cannot be parsed), so treat it as
					// an error that aborts the whole scan.
					return nerr
				} else if nested != nil {
					relDir, rerr := filepath.Rel(root, path)
					if rerr == nil {
						ip.AddNested(relDir, nested)
					}
				}
			}
			return nil
		}

		if strings.HasPrefix(path, gitDir) {
			return nil
		}

		rel, _ := filepath.Rel(root, path)

		// Directory-component check first, then the rest of the shared
		// filter set. isInSkipDir and fs.reason both work off the relative
		// path, so the walker and SkipChecker stay in lockstep.
		if isInSkipDir(rel) {
			if opts.Stats != nil {
				opts.Stats.SkippedVendor++
				opts.Stats.Note(SkipReasonSkipDir, rel)
			}
			return nil
		}

		if reason, skip := fs.reasonExcludingSkipDir(rel); skip {
			if opts.Stats != nil {
				switch reason {
				case SkipReasonIgnore:
					opts.Stats.SkippedIgnore++
				case SkipReasonExt:
					opts.Stats.SkippedExt++
				case SkipReasonTest:
					opts.Stats.SkippedTest++
				}
				opts.Stats.Note(reason, rel)
			}
			return nil
		}

		// Build the File before deciding on size. For a symlink, f.Size is
		// the RESOLVED target size, not the length of the link path — so
		// checking d.Info().Size() here let a symlink to an arbitrarily
		// large file walk straight through the ceiling and then get read in
		// full. Constructing first also means a d.Info() failure is reported
		// rather than silently admitting an unchecked file.
		f, err := newFileFromDirEntry(path, d, root)
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			return nil
		}

		if f.Size > fs.maxSize {
			if opts.Stats != nil {
				opts.Stats.SkippedLarge++
				opts.Stats.Note(SkipReasonLarge, rel)
			}
			return nil
		}
		// Re-assert the ceiling on the read itself. A file can grow between
		// the directory read and the content load, and the ceiling is only
		// real if it holds against the bytes actually delivered.
		f.MaxContentBytes = fs.maxSize

		// Content is loaded lazily by the scan workers so that file reads,
		// binary detection, and any hashing happen concurrently instead of
		// serializing the entire walk on disk I/O.
		if opts.Stats != nil {
			opts.Stats.Kept++
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

// testSourceExts are the extensions for which a `.test` or `.spec` segment
// denotes a test file. `secrets.test.json` is not one: Terraform tfvars and
// fixture files routinely carry live credentials under exactly that name, and
// skipping them was a false negative with a plausible real-world trigger.
var testSourceExts = map[string]bool{
	".go": true, ".js": true, ".jsx": true, ".ts": true, ".tsx": true,
	".mjs": true, ".cjs": true, ".rb": true, ".py": true, ".rs": true,
	".java": true, ".kt": true, ".swift": true, ".cs": true, ".c": true,
	".cc": true, ".cpp": true, ".h": true, ".hpp": true, ".php": true,
	".scala": true, ".dart": true, ".ex": true, ".exs": true,
}

// isTestFile reports whether path is a test file.
//
// The `_test`/`_spec` forms apply to any extension, matching the conventions of
// the languages that use them. The `.test`/`.spec` segment forms apply only to
// known test-source extensions: filepath.Ext returns the suffix from the last
// dot, so `foo.test` and `foo.spec` did not match at all (dead code), while
// `prod.test.tfvars` and `secrets.test.json` did.
func isTestFile(path string) bool {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if strings.HasSuffix(name, "_test") || strings.HasSuffix(name, "_spec") {
		return true
	}
	if strings.HasSuffix(name, ".test") || strings.HasSuffix(name, ".spec") {
		return testSourceExts[strings.ToLower(ext)]
	}
	return false
}

// filterSet holds the resolved per-file filters shared by the walker and the
// SkipChecker, so a scoped scan cannot drift from a full one.
type filterSet struct {
	ignore     *IgnoreSet
	skipExtSet map[string]bool
	skipSfx    []string
	skipDirSet map[string]bool
	includeT   bool
	maxSize    int64
}

func newFilterSet(opts WalkOption) (*filterSet, error) {
	fs := &filterSet{includeT: opts.IncludeTestFiles}
	var err error
	fs.ignore, err = resolveIgnoreSet(opts.ignoreRoot, opts)
	if err != nil {
		return nil, err
	}
	skipDirs := opts.SkipDirs
	if skipDirs == nil {
		skipDirs = DefaultSkipDirs
	}
	fs.skipDirSet = make(map[string]bool, len(skipDirs))
	for _, d := range skipDirs {
		fs.skipDirSet[d] = true
	}
	skipExts := opts.SkipExtensions
	if skipExts == nil {
		skipExts = DefaultSkipExtensions
	}
	fs.maxSize = opts.MaxFileSize
	if fs.maxSize <= 0 {
		fs.maxSize = DefaultMaxFileSize
	}
	fs.skipExtSet = make(map[string]bool, len(skipExts))
	for _, e := range skipExts {
		if e == "" {
			// An empty entry used to reach e[1:] and panic with
			// "slice bounds out of range [1:0]". Go exits 2 on panic, which is
			// the same code the tool reserves for "this scan is incomplete",
			// so a one-character typo in a config file reported itself as a
			// truncated scan.
			continue
		}
		// Normalise a leading dot: an entry such as "env" could never match,
		// because filepath.Ext always returns a dot-prefixed suffix.
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		if strings.Contains(e[1:], ".") {
			// An interior dot means the entry is a suffix pattern
			// (".min.js"), not a plain extension.
			fs.skipSfx = append(fs.skipSfx, e)
		} else {
			fs.skipExtSet[strings.ToLower(e)] = true
		}
	}
	return fs, nil
}

// reason reports why rel is excluded, or ok=false when it is not. Directory,
// extension, ignore-file, and test-file reasons are all considered.
func (fs *filterSet) reason(rel string) (SkipReason, bool) {
	rel = filepath.ToSlash(rel)
	segs := strings.Split(rel, "/")
	if len(segs) > 1 {
		for _, seg := range segs[:len(segs)-1] {
			if fs.skipDirSet[seg] {
				return SkipReasonSkipDir, true
			}
		}
	}
	return fs.reasonExcludingSkipDir(rel)
}

// reasonExcludingSkipDir is reason() without the skip-dir component check, so
// the walker can account for that bucket separately without double-counting.
func (fs *filterSet) reasonExcludingSkipDir(rel string) (SkipReason, bool) {
	base := pathBase(filepath.ToSlash(rel))
	if fs.ignore.Ignored(filepath.ToSlash(rel)) {
		return SkipReasonIgnore, true
	}
	if fs.skipExtSet[strings.ToLower(filepath.Ext(base))] {
		return SkipReasonExt, true
	}
	for _, sfx := range fs.skipSfx {
		if strings.HasSuffix(base, sfx) {
			return SkipReasonExt, true
		}
	}
	if !fs.includeT && isTestFile(base) {
		return SkipReasonTest, true
	}
	return "", false
}

// SkipChecker applies the same filters a directory walk uses to individual
// files, so diff, staged, and history scans honor identical coverage rules —
// including .minesweepignore/.msignore. It is not a traversal; callers resolve
// each path and ask.
type SkipChecker struct {
	root  string
	fs    *filterSet
	stats *WalkStats
}

// NewSkipChecker builds a per-file filter mirroring WalkWithOptions defaults.
// It returns an error when an ignore file cannot be read: an unreadable
// .minesweepignore must not degrade into "scan everything and call it clean".
func NewSkipChecker(root string, opts WalkOption) (*SkipChecker, error) {
	opts.ignoreRoot = root
	fs, err := newFilterSet(opts)
	if err != nil {
		return nil, err
	}
	return &SkipChecker{root: root, fs: fs}, nil
}

// WithStats attaches skip accounting, so a scoped scan reports the same
// coverage gaps a full scan does.
func (sc *SkipChecker) WithStats(stats *WalkStats) *SkipChecker {
	sc.stats = stats
	return sc
}

// Classify reports why absPath is excluded, without recording stats.
func (sc *SkipChecker) Classify(absPath string) (SkipReason, bool) {
	return sc.classify(absPath)
}

// ClassifyRel is Classify for a path already relative to the checker's root.
// It is how history mode filters repository-relative object paths, which have
// no filesystem entry to resolve.
func (sc *SkipChecker) ClassifyRel(rel string) (SkipReason, bool) {
	rel = filepath.ToSlash(rel)
	for _, vcs := range []string{".git", ".svn", ".hg"} {
		if rel == vcs || strings.HasPrefix(rel, vcs+"/") {
			return SkipReasonVCS, true
		}
	}
	return sc.fs.reason(rel)
}

// ShouldSkip reports whether the file at absPath should be excluded from a
// scoped scan.
func (sc *SkipChecker) ShouldSkip(absPath string) bool {
	reason, skip := sc.classify(absPath)
	if skip && sc.stats != nil {
		sc.stats.Note(reason, sc.relLabel(absPath))
	}
	return skip
}

func (sc *SkipChecker) classify(absPath string) (SkipReason, bool) {
	// Resolve both paths: git reports the toplevel with symlinks resolved
	// (e.g. /private/var/... for /var/... on macOS), so comparisons must
	// happen on a canonical form or every file looks external to the root.
	if rp, err := filepath.EvalSymlinks(sc.root); err == nil {
		sc.root = rp
	} else if rp, err := filepath.Abs(sc.root); err == nil {
		sc.root = rp
	}
	if rp, err := filepath.EvalSymlinks(absPath); err == nil {
		absPath = rp
	}
	for _, vcs := range []string{".git", ".svn", ".hg"} {
		if strings.HasPrefix(absPath, filepath.Join(sc.root, vcs)+string(filepath.Separator)) {
			return SkipReasonVCS, true
		}
	}
	rel, err := filepath.Rel(sc.root, absPath)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return SkipReasonVCS, true
	}
	return sc.fs.reason(filepath.ToSlash(rel))
}

// ShouldSkipSize reports whether the file exceeds the scan's size ceiling.
// path is recorded in stats when non-empty so size skips show up in the
// coverage breakdown the same way every other filter does.
func (sc *SkipChecker) ShouldSkipSize(size int64, path string) bool {
	if size <= sc.fs.maxSize {
		return false
	}
	if sc.stats != nil {
		label := sc.relLabel(path)
		if label == "" || label == "." {
			label = "(unknown)"
		}
		sc.stats.Note(SkipReasonLarge, label)
	}
	return true
}

// MaxSize exposes the resolved size ceiling.
func (sc *SkipChecker) MaxSize() int64 { return sc.fs.maxSize }

// IgnoreSet exposes the resolved ignore configuration.
func (sc *SkipChecker) IgnoreSet() *IgnoreSet { return sc.fs.ignore }

// relLabel returns a stable, root-relative path for skip examples.
func (sc *SkipChecker) relLabel(absPath string) string {
	if rel, err := filepath.Rel(sc.root, absPath); err == nil && rel != "" && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.Base(absPath)
}
