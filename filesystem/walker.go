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
		if f.IsSymlink && f.SymlinkTarget != "" && strings.Contains(f.SymlinkTarget, "(") {
			if opts.Stats != nil {
				opts.Stats.SkippedSymlink++
			}
		}
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

func mergeIgnorePatterns(a, b *IgnorePattern) *IgnorePattern {
	combined := make([]ignoreRule, 0, len(a.patterns)+len(b.patterns))
	combined = append(combined, a.patterns...)
	combined = append(combined, b.patterns...)
	return &IgnorePattern{patterns: combined}
}
