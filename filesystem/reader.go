package filesystem

import (
	"os"
)

// FileReader defines an interface for reading files
// This allows for mocking in tests
type FileReader interface {
	ReadFile(path string) ([]byte, error)
	Stat(path string) (os.FileInfo, error)
	Lstat(path string) (os.FileInfo, error)
	Readlink(path string) (string, error)
	ReadDir(dir string) ([]os.DirEntry, error)
}

// OSFileReader implements FileReader using the standard os package
type OSFileReader struct{}

// ReadFile reads a file from the filesystem
func (r *OSFileReader) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// Stat returns file info
func (r *OSFileReader) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// Lstat returns file info without following symlinks
func (r *OSFileReader) Lstat(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

// Readlink reads a symlink
func (r *OSFileReader) Readlink(path string) (string, error) {
	return os.Readlink(path)
}

// ReadDir reads a directory
func (r *OSFileReader) ReadDir(dir string) ([]os.DirEntry, error) {
	return os.ReadDir(dir)
}

// DefaultFileReader is the default file reader using os operations
var DefaultFileReader FileReader = &OSFileReader{}

// SetDefaultFileReader sets the default file reader
// This can be used for testing to inject a mock reader
func SetDefaultFileReader(reader FileReader) {
	DefaultFileReader = reader
}
