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
			if strings.HasPrefix(base, rule.pattern) && base == rule.pattern {
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

const DefaultMaxFileSize int64 = 50 * 1024 * 1024 // 50MB

type WalkOption struct {
	Ignore          *IgnorePattern
	IgnoreFilePath  string
	MaxFileSize     int64
	OnError         func(path string, err error)
}

func Walk(root string, ignore *IgnorePattern, ignoreFilePath string) ([]*File, error) {
	return walkWithOptions(root, WalkOption{
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

	var files []*File
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == ".svn" || name == "__pycache__" ||
				name == ".venv" || name == "venv" || name == "vendor" || name == "dist" ||
				name == "build" || name == "target" || name == ".idea" || name == ".vscode" {
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		if ip.Ignored(rel) {
			return nil
		}

		ext := filepath.Ext(path)
		switch ext {
		case ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".mp4", ".avi", ".mov":
			return nil
		case ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib", ".class", ".pyc":
			return nil
		}

		info, err := d.Info()
		if err == nil && info.Size() > opts.MaxFileSize {
			return nil
		}

		f, err := NewFile(path)
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(path, err)
			}
			return nil
		}
		files = append(files, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func mergeIgnorePatterns(a, b *IgnorePattern) *IgnorePattern {
	combined := make([]ignoreRule, 0, len(a.patterns)+len(b.patterns))
	combined = append(combined, a.patterns...)
	combined = append(combined, b.patterns...)
	return &IgnorePattern{patterns: combined}
}
