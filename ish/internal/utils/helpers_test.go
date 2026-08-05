package utils

import (
	"encoding/binary"
	"path/filepath"
	"testing"
)

func TestToUTF16LE(t *testing.T) {
	got := ToUTF16LE("AB")
	want := []byte{0x41, 0x00, 0x42, 0x00}
	if string(got) != string(want) {
		t.Fatalf("ToUTF16LE(AB) = %x, want %x", got, want)
	}
}

func TestToUTF16BE(t *testing.T) {
	got := ToUTF16BE("AB")
	want := []byte{0x00, 0x41, 0x00, 0x42}
	if string(got) != string(want) {
		t.Fatalf("ToUTF16BE(AB) = %x, want %x", got, want)
	}
}

func TestDecodeUTF16(t *testing.T) {
	b := []byte{0x48, 0x00, 0x69, 0x00, 0x00, 0x00} // "Hi\0"
	got := DecodeUTF16(b)
	if got != "Hi" {
		t.Fatalf("DecodeUTF16 = %q, want Hi", got)
	}
}

func TestIsRecycleRPath(t *testing.T) {
	if !IsRecycleRPath(`C:\$Recycle.Bin\S-1-5-21\$R12345.txt`) {
		t.Fatal("expected Recycle path to match")
	}
	if IsRecycleRPath(`C:\Users\foo\file.txt`) {
		t.Fatal("expected normal path not to match")
	}
}

func TestReadRecycleInfoFromRPath(t *testing.T) {
	iPath, ok := ReadRecycleInfoFromRPath(`C:\$Recycle.Bin\SID\$RABC.txt`)
	if !ok {
		t.Fatal("expected ok")
	}
	base := filepath.Base(iPath)
	if base != "$IABC.txt" {
		t.Fatalf("expected $IABC.txt, got %s", base)
	}
}

func TestDecodeUTF16_IFile(t *testing.T) {
	// Build a minimal $I file (Win10+ format).
	// Header: 0x02 0x00 0x00 0x00 0x00 0x00 0x00 0x00
	// Original size: 8 bytes
	// Deleted time (FILETIME): 8 bytes
	// Original path length (DWORD): 4 bytes
	// UTF-16 path.
	b := make([]byte, 28)
	b[0] = 0x02                                                            // version 2
	copy(b[8:16], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})  // size
	copy(b[16:24], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) // time
	pathU16 := ToUTF16LE("C:\\test.txt")
	binary.LittleEndian.PutUint32(b[24:28], uint32(len(pathU16)))
	b = append(b, pathU16...)

	// We can only test DecodeUTF16 indirectly by passing the tail to it.
	tail := b[28:]
	got := DecodeUTF16(tail)
	if got != `C:\test.txt` {
		t.Fatalf("DecodeUTF16 tail = %q, want C:\\test.txt", got)
	}
}
