package filesystem

import "strings"

var textExtensions = map[string]bool{
	".txt": true, ".md": true, ".rst": true, ".adoc": true,
	".go": true, ".rs": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".java": true, ".c": true, ".h": true, ".cpp": true, ".hpp": true, ".cs": true,
	".rb": true, ".php": true, ".pl": true, ".pm": true, ".swift": true, ".kt": true,
	".sh": true, ".bash": true, ".zsh": true, ".fish": true,
	".yaml": true, ".yml": true, ".json": true, ".xml": true, ".toml": true, ".ini": true, ".cfg": true, ".conf": true,
	".html": true, ".htm": true, ".css": true, ".scss": true, ".sass": true, ".less": true,
	".sql": true, ".graphql": true,
	".env": true, ".editorconfig": true, ".gitignore": true, ".dockerignore": true,
	".makefile": true, "Makefile": true, "Dockerfile": true,
	".mod": true, ".sum": true, ".lock": true,
}

var binaryExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".ico": true, ".svg": true,
	".webp": true, ".bmp": true, ".tiff": true,
	".mp3": true, ".mp4": true, ".wav": true, ".ogg": true, ".flac": true, ".avi": true, ".mov": true, ".mkv": true,
	".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
	".zip": true, ".tar": true, ".gz": true, ".bz2": true, ".xz": true, ".zst": true, ".7z": true, ".rar": true,
	".exe": true, ".dll": true, ".so": true, ".dylib": true, ".bin": true, ".o": true, ".a": true, ".lib": true,
	".class": true, ".pyc": true, ".pyo": true, ".wasm": true,
	".ttf": true, ".otf": true, ".woff": true, ".woff2": true, ".eot": true,
	".db": true, ".sqlite": true, ".sqlite3": true,
}

func IsTextFile(ext string) bool {
	if textExtensions[ext] {
		return true
	}
	return textExtensions[strings.TrimPrefix(ext, ".")]
}

func IsBinaryFile(ext string) bool {
	if binaryExtensions[ext] {
		return true
	}
	return binaryExtensions[strings.TrimPrefix(ext, ".")]
}

var binaryMagics = [][]byte{
	{0x7f, 'E', 'L', 'F'},          // ELF
	{'M', 'Z'},                     // PE/Windows
	{'%', 'P', 'D', 'F'},           // PDF
	{0x89, 'P', 'N', 'G'},          // PNG
	{'P', 'K', 0x03, 0x04},         // ZIP
	{0x1f, 0x8b},                   // GZIP
	{0x42, 0x5a},                   // BZ2
	{0xfd, 0x37, 0x7a, 0x58, 0x5a}, // XZ
	{0xfe, 0xed, 0xfa, 0xce},       // Mach-O (32-bit big)
	{0xfe, 0xed, 0xfa, 0xcf},       // Mach-O (64-bit big)
	{0xce, 0xfa, 0xed, 0xfe},       // Mach-O (32-bit little)
	{0xcf, 0xfa, 0xed, 0xfe},       // Mach-O (64-bit little)
}

func hasMagic(data []byte, magic []byte) bool {
	if len(data) < len(magic) {
		return false
	}
	for i, b := range magic {
		if data[i] != b {
			return false
		}
	}
	return true
}

func IsBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	for _, m := range binaryMagics {
		if hasMagic(data, m) {
			return true
		}
	}

	for _, b := range data {
		if b == 0 {
			return true
		}
	}

	controlCount := 0
	for _, b := range data {
		if b < 0x20 && b != 0x09 && b != 0x0a && b != 0x0d {
			controlCount++
		}
	}
	return float64(controlCount)/float64(len(data)) > 0.10
}

func IsUTF8(data []byte) bool {
	i := 0
	for i < len(data) {
		if data[i] < 0x80 {
			i++
			continue
		}
		if data[i]&0xE0 == 0xC0 {
			if i+1 >= len(data) || data[i+1]&0xC0 != 0x80 {
				return false
			}
			i += 2
			continue
		}
		if data[i]&0xF0 == 0xE0 {
			if i+2 >= len(data) || data[i+1]&0xC0 != 0x80 || data[i+2]&0xC0 != 0x80 {
				return false
			}
			i += 3
			continue
		}
		if data[i]&0xF8 == 0xF0 {
			if i+3 >= len(data) || data[i+1]&0xC0 != 0x80 || data[i+2]&0xC0 != 0x80 || data[i+3]&0xC0 != 0x80 {
				return false
			}
			i += 4
			continue
		}
		return false
	}
	return true
}

func HasBOM(data []byte) (string, bool) {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return "utf-8", true
	}
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		return "utf-16-le", true
	}
	if len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF {
		return "utf-16-be", true
	}
	return "", false
}
