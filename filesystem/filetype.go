package filesystem

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

// binarySampleSize limits NUL-byte and control-character detection to a
// prefix window, following the same convention as git and ripgrep. Real
// binaries almost always reveal themselves within the first few KB, and
// scanning multi-megabyte files byte-by-byte was a measurable share of load
// time.
const binarySampleSize = 8192

func IsBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	for _, m := range binaryMagics {
		if hasMagic(data, m) {
			return true
		}
	}

	sample := data
	if len(sample) > binarySampleSize {
		sample = sample[:binarySampleSize]
	}

	for _, b := range sample {
		if b == 0 {
			return true
		}
	}

	controlCount := 0
	for _, b := range sample {
		if b < 0x20 && b != 0x09 && b != 0x0a && b != 0x0d {
			controlCount++
		}
	}
	return float64(controlCount)/float64(len(sample)) > 0.10
}
