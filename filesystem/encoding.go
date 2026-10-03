package filesystem

import (
	"bytes"
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

// Byte-order marks for the encodings we can decode without loss.
var (
	bomUTF8    = []byte{0xEF, 0xBB, 0xBF}
	bomUTF16LE = []byte{0xFF, 0xFE}
	bomUTF16BE = []byte{0xFE, 0xFF}
)

// transcodeBOM converts BOM-marked UTF-16 to UTF-8 and strips a UTF-8 BOM.
//
// The reason this exists: a UTF-16 file is full of NUL bytes, so IsBinary
// classified it as binary and every content detector returned early. A .env saved
// by a Windows editor therefore scanned clean -- only a
// "binary-file-detected" info finding, no secrets, and no incomplete flag.
// Decoding the encoding the author actually wrote is what makes those files
// scannable at all.
//
// Only BOM-marked input is transcoded. Guessing at unmarked UTF-16 would mean
// guessing the byte order, and guessing wrong would corrupt the file's contents
// in the report, which is worse than not scanning it. The second return value is
// false when nothing was decoded, in which case the caller must keep the original
// bytes.
func transcodeBOM(data []byte) ([]byte, bool) {
	switch {
	case bytes.HasPrefix(data, bomUTF8):
		// Strip only. Valid UTF-8 needs no transcoding, and invalid bytes are
		// left for IsBinary to judge rather than mangled here.
		out := make([]byte, len(data)-len(bomUTF8))
		copy(out, data[len(bomUTF8):])
		return out, true
	case bytes.HasPrefix(data, bomUTF16LE):
		return decodeUTF16(data[len(bomUTF16LE):], binary.LittleEndian)
	case bytes.HasPrefix(data, bomUTF16BE):
		return decodeUTF16(data[len(bomUTF16BE):], binary.BigEndian)
	}
	return nil, false
}

// decodeUTF16 reads 16-bit code units in the given order and re-encodes as UTF-8.
// An odd trailing byte is dropped: a truncated final unit is not a reason to
// discard the whole file.
func decodeUTF16(body []byte, order binary.ByteOrder) ([]byte, bool) {
	n := len(body) / 2
	if n == 0 {
		return nil, false
	}
	units := make([]uint16, n)
	for i := 0; i < n; i++ {
		units[i] = order.Uint16(body[i*2:])
	}
	runes := utf16.Decode(units)
	// A surrogate that survived decoding cannot be encoded; utf8.EncodeRune
	// substitutes U+FFFD, which keeps the rest of the file intact.
	return []byte(string(runes)), true
}

// IsUTF8Content reports whether b is well-formed UTF-8 text.
//
// It replaces the previous IsUTF8, which was never called: a file that was valid
// UTF-8 was treated the same as one that was not, and the distinction was only
// ever relevant when deciding whether to transcode -- which this package now does
// unconditionally for BOM-marked input.
func IsUTF8Content(b []byte) bool { return utf8.Valid(b) }
