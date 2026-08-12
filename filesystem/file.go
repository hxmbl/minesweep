package filesystem

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zeebo/blake3"
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
	// Lazy loading support
	contentLoaded bool
	contentErr    error
	contentMu     sync.Mutex
}

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

	f := &File{
		Path: path,
		Size: info.Size(),
		Mode: info.Mode(),
	}

	if info.Mode()&os.ModeSymlink != 0 {
		f.IsSymlink = true
		target, err := os.Readlink(path)
		if err != nil {
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
			f.SymlinkTarget = f.SymlinkTarget + " (broken)"
			return f, nil
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

	if f.contentLoaded {
		return f.Content, f.contentErr
	}

	// Pre-populated content (tests, decoded buffers) — skip disk read.
	if f.Content != nil {
		f.contentLoaded = true
		return f.Content, nil
	}

	// Unsafe/broken/unreadable symlinks: no content.
	if f.IsSymlink && (strings.Contains(f.SymlinkTarget, "(unsafe") ||
		strings.Contains(f.SymlinkTarget, "(broken") ||
		strings.Contains(f.SymlinkTarget, "(unreadable")) {
		f.Content = []byte{}
		f.contentLoaded = true
		return f.Content, nil
	}

	data, err := os.ReadFile(f.Path)
	if err != nil {
		f.contentErr = err
		f.contentLoaded = true
		return nil, err
	}
	f.Content = data
	f.contentLoaded = true

	hasher := blake3.New()
	if _, err := hasher.Write(data); err != nil {
		f.contentErr = err
		f.contentLoaded = true
		return nil, err
	}
	f.Hash = hex.EncodeToString(hasher.Sum(nil))

	f.IsBinary = IsBinary(data)

	return f.Content, nil
}

// LoadContent forces loading of file content (for backward compatibility)
func (f *File) LoadContent() error {
	_, err := f.GetContent()
	return err
}

func (f *File) IsRegular() bool {
	return f.Mode.IsRegular()
}

func (f *File) IsExecutable() bool {
	return f.Mode&0111 != 0
}
