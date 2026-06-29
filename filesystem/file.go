package filesystem

import (
	"os"
	"path/filepath"

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
}

func NewFile(path string) (*File, error) {
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
		f.SymlinkTarget = target
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		if _, err := os.Stat(target); os.IsNotExist(err) {
			f.SymlinkTarget = target + " (broken)"
			return f, nil
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f.Content = data

	hasher := blake3.New()
	hasher.Write(data)
	f.Hash = string(hasher.Sum(nil))

	f.IsBinary = IsBinary(data)

	return f, nil
}

func (f *File) IsRegular() bool {
	return f.Mode.IsRegular()
}

func (f *File) IsExecutable() bool {
	return f.Mode&0111 != 0
}
