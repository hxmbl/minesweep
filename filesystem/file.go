package filesystem

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zeebo/blake3"
)

type symlinkState int

const (
	symlinkOK symlinkState = iota
	symlinkUnreadable
	symlinkUnsafe
	symlinkBroken
)

type File struct {
	Path          string
	Content       []byte
	Size          int64
	Mode          os.FileMode
	IsSymlink     bool
	SymlinkTarget string
	IsBinary      bool
	Hash          string
	// MaxContentBytes bounds how much content will be loaded. Zero means
	// unlimited. Exceeding it is reported as an error, never as a silent
	// truncation: a partly-scanned file is a false negative, and producing
	// false negatives is the one failure this tool must not have.
	MaxContentBytes int64
	// FindingBudget caps how many findings detectors may emit for this
	// file. Zero means unlimited. The engine sets it from the global
	// remaining budget, which is what keeps one pathological file from
	// producing hundreds of thousands of findings before the global cap is
	// ever consulted. It lives on File because File is the per-scan unit
	// every detector already receives, so the budget is race-free without
	// mutating shared detector state.
	FindingBudget    int
	FindingBudgetHit bool
	// Lazy loading support
	contentLoaded bool
	contentErr    error
	contentMu     sync.Mutex
	lowered       []byte
	lineIdx       *LineIndex
	symlinkState  symlinkState
	// loader, when set, produces content from somewhere other than disk
	// (e.g. git blobs). It runs at most once, under contentMu.
	loader func() ([]byte, error)
}

// ErrTooLarge is returned when content exceeds a File's MaxContentBytes.
var ErrTooLarge = errors.New("content exceeds the configured size ceiling")

// isSafePath checks if a path is safe (doesn't traverse outside root)
func isSafePath(path, root string) bool {
	// Relative paths are interpreted relative to the scan root.
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}

	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return false
	}

	// If rel starts with ".." then it's outside root
	if strings.HasPrefix(rel, "..") {
		return false
	}

	return true
}

func NewFile(path string) (*File, error) {
	return NewFileWithRoot(path, "")
}

// NewFileWithRoot creates a new File with path traversal protection relative to root
func NewFileWithRoot(path, root string) (*File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	return newFileFromInfo(path, info.Mode(), info.Size(), root)
}

// newFileFromDirEntry builds a File from a directory entry already provided
// by the walker, avoiding a redundant lstat syscall per file. d.Info() is
// satisfied from the directory read on most platforms.
func newFileFromDirEntry(path string, d os.DirEntry, root string) (*File, error) {
	info, err := d.Info()
	if err != nil {
		return nil, err
	}
	return newFileFromInfo(path, d.Type(), info.Size(), root)
}

func newFileFromInfo(path string, mode os.FileMode, size int64, root string) (*File, error) {
	f := &File{
		Path: path,
		Size: size,
		Mode: mode,
	}

	if mode&os.ModeSymlink != 0 {
		f.IsSymlink = true
		target, err := os.Readlink(path)
		if err != nil {
			f.symlinkState = symlinkUnreadable
			f.SymlinkTarget = "(unreadable)"
			return f, nil
		}

		// Resolve the target path
		var absTarget string
		if filepath.IsAbs(target) {
			absTarget = target
		} else {
			absTarget = filepath.Join(filepath.Dir(path), target)
		}

		// Clean the path (remove . and ..)
		absTarget = filepath.Clean(absTarget)

		// If root is specified, check if the symlink target is safe
		if root != "" {
			if !isSafePath(absTarget, root) {
				// Symlink points outside root - mark as unsafe
				f.symlinkState = symlinkUnsafe
				f.SymlinkTarget = "(unsafe: outside scan root)"
				return f, nil
			}
		}

		// Try to get absolute path
		finalTarget, err := filepath.Abs(absTarget)
		if err != nil {
			f.SymlinkTarget = absTarget
		} else {
			f.SymlinkTarget = finalTarget
		}

		// Check if target exists
		if _, err := os.Stat(f.SymlinkTarget); os.IsNotExist(err) {
			f.symlinkState = symlinkBroken
			f.SymlinkTarget = f.SymlinkTarget + " (broken)"
			return f, nil
		}
		// Stat the resolved target to get the real file size; Lstat on
		// the symlink itself returns the length of the target path string.
		if targetInfo, err := os.Stat(f.SymlinkTarget); err == nil {
			f.Size = targetInfo.Size()
		}
	}

	// Don't load content by default - use lazy loading via GetContent().
	return f, nil
}

// GetContent returns the file content, loading it lazily if not already loaded.
// Named GetContent (not Content) because File already has a Content field.
func (f *File) GetContent() ([]byte, error) {
	f.contentMu.Lock()
	defer f.contentMu.Unlock()
	return f.contentLocked()
}

// UseLoader replaces the on-disk content source with loader (used to serve
// staged index blobs instead of the working tree). The loader runs lazily, at
// most once, when a detector first requests content.
func (f *File) UseLoader(loader func() ([]byte, error)) {
	f.contentMu.Lock()
	defer f.contentMu.Unlock()
	f.loader = loader
	f.Content = nil
	f.contentErr = nil
	f.contentLoaded = false
	f.Hash = ""
	f.lowered = nil
	f.lineIdx = nil
}

// NewBlobFile creates a File whose content is produced by loader rather than
// read from disk — used for git history blobs. The loader runs lazily, at
// most once, when a detector first requests content.
func NewBlobFile(path string, size int64, loader func() ([]byte, error)) *File {
	return &File{Path: path, Size: size, Mode: 0100644, loader: loader}
}

func (f *File) contentLocked() ([]byte, error) {
	if f.contentLoaded {
		return f.Content, f.contentErr
	}

	// Pre-populated content (tests, decoded buffers) — skip disk read.
	if f.Content != nil {
		f.contentLoaded = true
		return f.Content, nil
	}

	if f.loader != nil {
		data, err := f.loader()
		if err == nil && f.MaxContentBytes > 0 && int64(len(data)) > f.MaxContentBytes {
			err = fmt.Errorf("%w: %d bytes over a %d byte ceiling", ErrTooLarge, int64(len(data))-f.MaxContentBytes, f.MaxContentBytes)
		}
		f.Content = data
		f.contentErr = err
		f.contentLoaded = true
		if err != nil {
			return nil, err
		}
		f.IsBinary = IsBinary(data)
		return f.Content, nil
	}

	// Unsafe/broken/unreadable symlinks: no content.
	if f.IsSymlink && f.symlinkState != symlinkOK {
		f.Content = []byte{}
		f.contentLoaded = true
		return f.Content, nil
	}

	data, err := f.readBounded()
	if err != nil {
		f.contentErr = err
		f.contentLoaded = true
		return nil, err
	}
	f.Content = data
	f.contentLoaded = true

	f.IsBinary = IsBinary(data)

	return f.Content, nil
}

// readBounded loads the file, refusing anything past MaxContentBytes.
//
// The walker's size check is not sufficient on its own: a file can grow
// between the directory read and this read, so the ceiling is re-enforced
// here against the bytes actually delivered. Reading one byte past the limit
// detects overflow without buffering the whole oversized file.
func (f *File) readBounded() ([]byte, error) {
	if f.MaxContentBytes <= 0 {
		return os.ReadFile(f.Path)
	}
	fh, err := os.Open(f.Path)
	if err != nil {
		return nil, err
	}
	defer fh.Close() //nolint:errcheck // read-only handle

	data, err := io.ReadAll(io.LimitReader(fh, f.MaxContentBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > f.MaxContentBytes {
		return nil, fmt.Errorf("%w: limit %d bytes", ErrTooLarge, f.MaxContentBytes)
	}
	return data, nil
}

// ClaimFinding reserves one unit of the file's finding budget and reports
// whether a detector may emit another finding. Once the budget is spent it
// returns false forever, so a detector can simply stop.
func (f *File) ClaimFinding() bool {
	if f.FindingBudget <= 0 {
		return true // unlimited
	}
	if f.FindingBudgetHit || f.FindingBudget <= 0 {
		f.FindingBudgetHit = true
		return false
	}
	f.FindingBudget--
	return true
}

// SetFindingBudget arms (or disarms) the budget for this file.
func (f *File) SetFindingBudget(n int) {
	f.FindingBudget = n
	f.FindingBudgetHit = false
}

// Release drops the cached content and every view derived from it, so a file
// that has finished scanning stops holding memory. The File stays usable:
// content is re-read on demand.
//
// LineIndex must be cleared alongside Content because it retains a reference
// to the same backing array — nil'ing Content alone would keep every byte of
// the file alive.
func (f *File) Release() {
	f.contentMu.Lock()
	defer f.contentMu.Unlock()
	f.Content = nil
	f.lowered = nil
	f.lineIdx = nil
	f.Hash = ""
	f.contentLoaded = false
	f.contentErr = nil
}

// ContentHash returns the BLAKE3 hash of the file content, computing it on
// first use. Hashing is deliberately not part of GetContent: the hash has no
// consumers in the scan pipeline, and hashing every byte of every file was a
// measurable share of scan time.
func (f *File) ContentHash() string {
	f.contentMu.Lock()
	defer f.contentMu.Unlock()
	if f.Hash != "" {
		return f.Hash
	}
	content, err := f.contentLocked()
	if err != nil {
		return ""
	}
	hasher := blake3.New()
	if _, err := hasher.Write(content); err != nil {
		return ""
	}
	f.Hash = hex.EncodeToString(hasher.Sum(nil))
	return f.Hash
}

// LoadContent forces loading of file content (for backward compatibility)
func (f *File) LoadContent() error {
	_, err := f.GetContent()
	return err
}

// LoweredContent returns a case-folded copy of the content, computed once and
// shared by every detector that runs case-insensitive literal pre-checks.
//
// The folding matches Go's regexp `(?i)` semantics (see FoldLower), not plain
// ASCII lowercasing, so that a case-insensitive literal gate stays sound for the
// letters whose Unicode fold orbit escapes ASCII. Returns nil when the content
// cannot be loaded.
func (f *File) LoweredContent() []byte {
	f.contentMu.Lock()
	defer f.contentMu.Unlock()
	if f.lowered == nil {
		content, err := f.contentLocked()
		if err != nil || content == nil {
			return nil
		}
		f.lowered = FoldLower(content)
	}
	return f.lowered
}

// Lines returns the file's line index, built once and shared by all
// detectors for line/column lookups, context blocks, and source lines.
// Returns nil when the content cannot be loaded.
func (f *File) Lines() *LineIndex {
	f.contentMu.Lock()
	defer f.contentMu.Unlock()
	if f.lineIdx == nil {
		content, err := f.contentLocked()
		if err != nil || content == nil {
			return nil
		}
		f.lineIdx = NewLineIndex(content)
	}
	return f.lineIdx
}

func (f *File) IsRegular() bool {
	return f.Mode.IsRegular()
}

func (f *File) IsExecutable() bool {
	return f.Mode&0111 != 0
}
