package utils

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// ToUTF16LE converts a Go string to little-endian UTF-16 bytes.
func ToUTF16LE(s string) []byte {
	runes := []rune(s)
	out := make([]byte, len(runes)*2)
	for i, r := range runes {
		out[i*2] = byte(r)
		out[i*2+1] = byte(r >> 8)
	}
	return out
}

// ToUTF16BE converts a Go string to big-endian UTF-16 bytes.
func ToUTF16BE(s string) []byte {
	runes := []rune(s)
	out := make([]byte, len(runes)*2)
	for i, r := range runes {
		out[i*2] = byte(r >> 8)
		out[i*2+1] = byte(r)
	}
	return out
}

// DecodeUTF16 decodes a raw little-endian UTF-16 byte slice into a Go string.
func DecodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i, c := range u16 {
		if c == 0 {
			u16 = u16[:i]
			break
		}
	}
	return string(utf16.Decode(u16))
}

// IsRecycleRPath checks whether a path is a Recycle-Bin $R file.
func IsRecycleRPath(p string) bool {
	pl := strings.ToLower(p)
	if !strings.Contains(pl, `\$recycle.bin\`) {
		return false
	}
	base := strings.ToLower(filepath.Base(p))
	return strings.HasPrefix(base, "$r")
}

// ReadRecycleInfoFromRPath attempts to derive the $I companion path from a $R path.
func ReadRecycleInfoFromRPath(rPath string) (iPath string, ok bool) {
	pl := strings.ToLower(rPath)
	if !strings.Contains(pl, `\$recycle.bin\`) {
		return "", false
	}
	base := filepath.Base(rPath)
	if len(base) < 3 || strings.ToLower(base[:2]) != "$r" {
		return "", false
	}
	iName := "$I" + base[2:]
	return filepath.Join(filepath.Dir(rPath), iName), true
}
