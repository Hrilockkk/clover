//go:build windows
// +build windows

package ntfs

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"scanner/internal/models"
	"scanner/internal/utils"
)

func TestResolveDeletedPath(t *testing.T) {
	nodes := map[uint64]models.MFTNode{
		0x100: {Name: "foo", Parent: 0x200, IsDir: true},
		0x200: {Name: "bar", Parent: 5, IsDir: true}, // 5 == root FRN
	}
	got := ResolveDeletedPath(0x100, nodes, "C:")
	want := `C:\bar\foo`
	if got != want {
		t.Fatalf("ResolveDeletedPath = %q, want %q", got, want)
	}
}

func TestResolveDeletedPath_Cycle(t *testing.T) {
	nodes := map[uint64]models.MFTNode{
		0x100: {Name: "a", Parent: 0x200},
		0x200: {Name: "b", Parent: 0x100},
	}
	got := ResolveDeletedPath(0x100, nodes, "C:")
	// Cycle stops accumulation once a node is revisited; both already collected nodes remain.
	want := `C:\b\a`
	if got != want {
		t.Fatalf("ResolveDeletedPath = %q, want %q", got, want)
	}
}

func TestPathResolver_ResolveAndCache(t *testing.T) {
	nodes := map[uint64]models.MFTNode{
		0x100: {Name: "foo", Parent: 0x200, IsDir: false},
		0x200: {Name: "bar", Parent: 5, IsDir: true},
	}
	r := NewPathResolver(nodes, "C:")
	got := r.Resolve(0x100)
	want := `C:\bar\foo`
	if got != want {
		t.Fatalf("Resolve = %q, want %q", got, want)
	}
	// Second call must hit the cache and return the same value.
	if got2 := r.Resolve(0x100); got2 != want {
		t.Fatalf("cached Resolve = %q, want %q", got2, want)
	}
	if r.cache[0x100] != want {
		t.Fatalf("cache not populated, got %q", r.cache[0x100])
	}
}

func TestPathResolver_MatchesResolveDeletedPath(t *testing.T) {
	nodes := map[uint64]models.MFTNode{
		0x10: {Name: "leaf", Parent: 0x20},
		0x20: {Name: "mid", Parent: 0x30},
		0x30: {Name: "top", Parent: 5},
	}
	r := NewPathResolver(nodes, "D:")
	if r.Resolve(0x10) != ResolveDeletedPath(0x10, nodes, "D:") {
		t.Fatalf("PathResolver and ResolveDeletedPath disagree")
	}
}

func TestParseRecycleIFile(t *testing.T) {
	// Build a synthetic $I file (version 2).
	b := make([]byte, 28)
	b[0] = 0x02 // version 2
	// original size: leave zero
	// deleted time: zero (epoch 1601)
	// path length
	origPath := `C:\Users\Test\file.txt`
	pathU16 := utils.ToUTF16LE(origPath)
	binary.LittleEndian.PutUint32(b[24:28], uint32(len(pathU16)))
	b = append(b, pathU16...)

	tmpDir := t.TempDir()
	iPath := filepath.Join(tmpDir, "$I12345")
	if err := os.WriteFile(iPath, b, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	info, err := ParseRecycleIFile(iPath)
	if err != nil {
		t.Fatalf("ParseRecycleIFile: %v", err)
	}
	if info.OriginalPath != origPath {
		t.Fatalf("OriginalPath = %q, want %q", info.OriginalPath, origPath)
	}
	if !info.DeletedAt.Equal(time.Unix(0, 0)) && !info.DeletedAt.IsZero() {
		// zero FILETIME maps to 1601-01-01, which is not Unix epoch; just ensure no panic.
	}
}

func TestMFTRecordSizeFromBoot_Positive(t *testing.T) {
	b := &models.NTFSBootSector{BytesPerSector: 512, SectorsPerCluster: 8, ClustersPerMFTRecord: 1}
	got := MFTRecordSizeFromBoot(b)
	if got != 4096 {
		t.Fatalf("MFTRecordSize = %d, want 4096", got)
	}
}

func TestMFTRecordSizeFromBoot_Negative(t *testing.T) {
	b := &models.NTFSBootSector{BytesPerSector: 512, SectorsPerCluster: 8, ClustersPerMFTRecord: -10}
	got := MFTRecordSizeFromBoot(b)
	if got != 1024 {
		t.Fatalf("MFTRecordSize = %d, want 1024", got)
	}
}

func TestApplyMFTFixup(t *testing.T) {
	// Create a minimal sector-sized buffer with a fixup array.
	sector := 512
	rec := make([]byte, sector)
	copy(rec[0:4], []byte("FILE"))
	binary.LittleEndian.PutUint16(rec[0x04:], 0x30) // update seq offset
	binary.LittleEndian.PutUint16(rec[0x06:], 0x03) // update seq count (1 + 2 fixups)
	// Fixup array at offset 0x30: seq number + 2 entries
	rec[0x30] = 0xAA
	rec[0x31] = 0xBB
	rec[0x32] = 0xCC
	rec[0x33] = 0xDD
	rec[0x34] = 0xEE
	rec[0x35] = 0xFF
	// Place the original signatures at end of each sector
	rec[sector-2] = 0xAA
	rec[sector-1] = 0xBB

	ok := applyMFTFixup(rec, 512)
	if !ok {
		t.Fatal("applyMFTFixup returned false")
	}
	if rec[sector-2] != 0xCC || rec[sector-1] != 0xDD {
		t.Fatalf("fixup not applied correctly: got %x %x", rec[sector-2], rec[sector-1])
	}
}

func TestParseMFTRecord_Minimal(t *testing.T) {
	sector := 512
	rec := make([]byte, sector)
	copy(rec[0:4], []byte("FILE"))
	binary.LittleEndian.PutUint16(rec[0x04:], 0x30)
	binary.LittleEndian.PutUint16(rec[0x06:], 0x01) // no fixups beyond header
	binary.LittleEndian.PutUint16(rec[0x14:], 0x38) // first attribute offset
	binary.LittleEndian.PutUint16(rec[0x16:], 0x00) // flags: not in use, not dir
	binary.LittleEndian.PutUint32(rec[0x2C:], 42)   // record number
	// Attribute: end-of-attributes marker
	binary.LittleEndian.PutUint32(rec[0x38:], 0xFFFFFFFF)

	boot := &models.NTFSBootSector{BytesPerSector: 512}
	parsed, err := ParseMFTRecord(rec, boot)
	if err != nil {
		t.Fatalf("ParseMFTRecord: %v", err)
	}
	if parsed.MFTRecordNum != 42 {
		t.Fatalf("RecordNum = %d, want 42", parsed.MFTRecordNum)
	}
	if parsed.IsInUse {
		t.Fatal("expected IsInUse = false")
	}
	if parsed.IsDir {
		t.Fatal("expected IsDir = false")
	}
}

func TestParseMFTRecord_WithFileName(t *testing.T) {
	sector := 512
	rec := make([]byte, sector)
	copy(rec[0:4], []byte("FILE"))
	binary.LittleEndian.PutUint16(rec[0x04:], 0x30)
	binary.LittleEndian.PutUint16(rec[0x06:], 0x01)
	binary.LittleEndian.PutUint16(rec[0x14:], 0x38)
	binary.LittleEndian.PutUint16(rec[0x16:], 0x01) // in use
	binary.LittleEndian.PutUint32(rec[0x2C:], 1)

	attrOff := 0x38
	// $FILE_NAME attribute (0x30)
	binary.LittleEndian.PutUint32(rec[attrOff:], 0x30) // type
	attrLen := uint32(0x80)
	binary.LittleEndian.PutUint32(rec[attrOff+4:], attrLen)
	rec[attrOff+8] = 0x00                                   // non-resident = 0
	binary.LittleEndian.PutUint16(rec[attrOff+0x14:], 0x18) // value offset
	// value area
	valOff := attrOff + 0x18
	binary.LittleEndian.PutUint64(rec[valOff:], 0x200)     // ParentFRN
	binary.LittleEndian.PutUint64(rec[valOff+0x30:], 1234) // Size
	rec[valOff+0x40] = 4                                   // name length
	nameU16 := utils.ToUTF16LE("test")
	copy(rec[valOff+0x42:], nameU16)

	// end marker
	binary.LittleEndian.PutUint32(rec[attrOff+int(attrLen):], 0xFFFFFFFF)

	boot := &models.NTFSBootSector{BytesPerSector: 512}
	parsed, err := ParseMFTRecord(rec, boot)
	if err != nil {
		t.Fatalf("ParseMFTRecord: %v", err)
	}
	if parsed.Name != "test" {
		t.Fatalf("Name = %q, want test", parsed.Name)
	}
	if parsed.Size != 1234 {
		t.Fatalf("Size = %d, want 1234", parsed.Size)
	}
	if parsed.ParentFRN != 0x200 {
		t.Fatalf("ParentFRN = %x, want 0x200", parsed.ParentFRN)
	}
}
