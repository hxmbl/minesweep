package filesystem

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type IgnorePattern struct {
	patterns []ignoreRule
}

type ignoreRule struct {
	pattern  string
	negate   bool
	dirMatch bool
}

func NewIgnorePattern(patterns []string) *IgnorePattern {
	ip := &IgnorePattern{}
	for _, line := range patterns {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule := ignoreRule{}
		if strings.HasPrefix(line, "!") {
			rule.negate = true
			line = strings.TrimSpace(line[1:])
		}
		if strings.HasSuffix(line, "/") {
			rule.dirMatch = true
			line = strings.TrimSuffix(line, "/")
		}
		rule.pattern = line
		ip.patterns = append(ip.patterns, rule)
	}
	return ip
}

func LoadMinesweepIgnore(path string) (*IgnorePattern, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewIgnorePattern(nil), nil
		}
		return nil, fmt.Errorf("open ignore file %q: %w", path, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read ignore file %q: %w", path, err)
	}
	return NewIgnorePattern(lines), nil
}

func (ip *IgnorePattern) Ignored(path string) bool {
	base := filepath.Base(path)
	ignored := false

	for _, rule := range ip.patterns {
		if rule.pattern == "" {
			continue
		}

		matched := false

		if rule.dirMatch {
			if strings.HasPrefix(path, rule.pattern+"/") || strings.Contains(path, "/"+rule.pattern+"/") {
				matched = true
			}
			if base == rule.pattern {
				matched = true
			}
		}

		if !matched && (strings.Contains(rule.pattern, "/") || strings.Contains(rule.pattern, "**")) {
			matched = matchPath(rule.pattern, path)
		}

		if !matched {
			if m, _ := filepath.Match(rule.pattern, base); m {
				matched = true
			}
			if m, _ := filepath.Match(rule.pattern, path); m {
				matched = true
			}
		}

		if matched {
			ignored = !rule.negate
		}
	}
	return ignored
}

func matchPath(pattern, path string) bool {
	parts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, string(filepath.Separator))

	return matchGlobParts(parts, pathParts)
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

func walkWithOptions(root string, opts WalkOption) ([]*File, error) {
	ip := opts.Ignore
	if ip == nil {
		ip = NewIgnorePattern(nil)
		ignoreFilePath := opts.IgnoreFilePath
		if ignoreFilePath == "" {
			ignoreFilePath = filepath.Join(root, ".minesweepignore")
		}
		if fileIgnore, err := LoadMinesweepIgnore(ignoreFilePath); err == nil {
			ip = mergeIgnorePatterns(ip, fileIgnore)
		}
	}

	skipDirs := opts.SkipDirs
	if skipDirs == nil {
		skipDirs = DefaultSkipDirs
	}
	// .git alone is pruned during traversal (its contents are not project
	// data); other skip-dirs are DESCENDED so their files can be counted,
	// keeping the skipped-coverage number honest.
	var gitDir string
	if root != "." && !strings.HasSuffix(root, string(filepath.Separator)) {
		gitDir = filepath.Join(root, ".git") + string(filepath.Separator)
	} else {
		gitDir = filepath.Join(root, ".git") + string(filepath.Separator)
	}
	skipDirSet := make(map[string]bool)
	for _, d := range skipDirs {
		skipDirSet[d] = true
	}
	// Only directories WITHIN the scan root count: an ancestor segment
	// that happens to share a name with a skip dir (/tmp scanning, a
	// ~/go/src checkout, ...) must not nuke the whole walk.
	isInSkipDir := func(path string) bool {
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			return false
		}
		segs := strings.Split(rel, string(filepath.Separator))
		for _, seg := range segs[:len(segs)-1] {
			if skipDirSet[seg] {
				return true
			}
		}
		return false
	}

	// Split extension rules into exact matches and suffix matches once per
	// walk instead of re-scanning the slice for every file. Entries with an
	// inner dot (".min.js") must be suffix-matched against the base name.
	skipExts := opts.SkipExtensions
	if skipExts == nil {
		skipExts = DefaultSkipExtensions
	}
	skipExtSet := make(map[string]bool, len(skipExts))
	var skipSuffixes []string
	for _, e := range skipExts {
		if strings.Contains(e[1:], ".") {
			skipSuffixes = append(skipSuffixes, e)
		} else {
			skipExtSet[e] = true
		}
	}
	includeTests := opts.IncludeTestFiles

	var files []*File
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
			return nil
		}

		if strings.HasPrefix(path, gitDir) {
			return nil
		}

		if isInSkipDir(path) {
			if opts.Stats != nil {
				opts.Stats.SkippedVendor++
			}
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		if ip.Ignored(rel) {
			if opts.Stats != nil {
				opts.Stats.SkippedIgnore++
			}
			return nil
		}

		ext := filepath.Ext(path)
		if skipExtSet[ext] {
			if opts.Stats != nil {
				opts.Stats.SkippedExt++
			}
			return nil
		}
		if len(skipSuffixes) > 0 {
			base := filepath.Base(path)
			for _, sfx := range skipSuffixes {
				if strings.HasSuffix(base, sfx) {
					if opts.Stats != nil {
						opts.Stats.SkippedExt++
					}
					return nil
				}
			}
		}

		if !includeTests && isTestFile(path) {
			if opts.Stats != nil {
				opts.Stats.SkippedTest++
			}
			return nil
		}

		info, err := d.Info()
		if err == nil && info.Size() > opts.MaxFileSize {
			if opts.Stats != nil {
				opts.Stats.SkippedLarge++
			}
			return nil
		}

		f, err := newFileFromDirEntry(path, d, root)
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			return nil
		}

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

func isTestFile(path string) bool {
	base := filepath.Base(path)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	return strings.HasSuffix(name, "_test") || strings.HasSuffix(name, ".test") || strings.HasSuffix(name, ".spec")
}

// SkipChecker applies the same filters a directory walk uses to individual
// files, so diff and staged scans honor identical coverage rules. It is not
// a traversal; callers resolve each path and ask.
type SkipChecker struct {
	root       string
	ignore     *IgnorePattern
	skipExtSet map[string]bool
	skipSfx    []string
	skipDirs   []string
	includeT   bool
	maxSize    int64
}

// NewSkipChecker builds a per-file filter mirroring WalkWithOptions defaults,
// including the repository's .minesweepignore file at root.
func NewSkipChecker(root string, opts WalkOption) *SkipChecker {
	ip := opts.Ignore
	if ip == nil {
		ip = NewIgnorePattern(nil)
		if fileIgnore, err := LoadMinesweepIgnore(filepath.Join(root, ".minesweepignore")); err == nil {
			ip = mergeIgnorePatterns(ip, fileIgnore)
		}
	}
	skipDirs := opts.SkipDirs
	if skipDirs == nil {
		skipDirs = DefaultSkipDirs
	}
	skipExts := opts.SkipExtensions
	if skipExts == nil {
		skipExts = DefaultSkipExtensions
	}
	sc := &SkipChecker{root: root, ignore: ip, skipDirs: skipDirs, includeT: opts.IncludeTestFiles}
	sc.maxSize = opts.MaxFileSize
	if sc.maxSize <= 0 {
		sc.maxSize = DefaultMaxFileSize
	}
	sc.skipExtSet = make(map[string]bool, len(skipExts))
	for _, e := range skipExts {
		if strings.Contains(e[1:], ".") {
			sc.skipSfx = append(sc.skipSfx, e)
		} else {
			sc.skipExtSet[e] = true
		}
	}
	return sc
}

// ShouldSkip reports whether the file at absPath should be excluded from a
// scoped scan. Mirror of the traversal filters: prune .git/.svn/.hg contents,
// skip-dir nesting, ignore patterns, extensions, and test files.
func (sc *SkipChecker) ShouldSkip(absPath string) bool {
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
	if strings.HasPrefix(absPath, filepath.Join(sc.root, ".git")+string(filepath.Separator)) ||
		strings.HasPrefix(absPath, filepath.Join(sc.root, ".svn")+string(filepath.Separator)) ||
		strings.HasPrefix(absPath, filepath.Join(sc.root, ".hg")+string(filepath.Separator)) {
		return true
	}
	rel, err := filepath.Rel(sc.root, absPath)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return true
	}
	segs := strings.Split(rel, string(filepath.Separator))
	skipDirSet := make(map[string]bool)
	for _, d := range sc.skipDirs {
		skipDirSet[d] = true
	}
	for _, seg := range segs[:len(segs)-1] {
		if skipDirSet[seg] {
			return true
		}
	}
	if sc.ignore.Ignored(rel) {
		return true
	}
	if sc.skipExtSet[filepath.Ext(absPath)] {
		return true
	}
	if len(sc.skipSfx) > 0 {
		base := filepath.Base(absPath)
		for _, sfx := range sc.skipSfx {
			if strings.HasSuffix(base, sfx) {
				return true
			}
		}
	}
	if !sc.includeT && isTestFile(absPath) {
		return true
	}
	return false
}

// ShouldSkipSize reports whether the file exceeds the scan's size ceiling.
func (sc *SkipChecker) ShouldSkipSize(size int64) bool {
	return size > sc.maxSize
}

func mergeIgnorePatterns(a, b *IgnorePattern) *IgnorePattern {
	combined := make([]ignoreRule, 0, len(a.patterns)+len(b.patterns))
	combined = append(combined, a.patterns...)
	combined = append(combined, b.patterns...)
	return &IgnorePattern{patterns: combined}
}
