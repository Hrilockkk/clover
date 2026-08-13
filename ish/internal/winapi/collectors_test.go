//go:build windows
// +build windows

package winapi

import (
	"encoding/binary"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// buildShimcacheBlob builds a synthetic Win10-format ShimCache blob per the
// Velociraptor/Mandiant spec: header (52 bytes) + "10ts" entries with
// stride = 12 + bodySize.
func buildShimcacheBlob(paths []string) []byte {
	out := make([]byte, 52)
	binary.LittleEndian.PutUint32(out[0:4], 52) // headerSize
	for _, p := range paths {
		pu := make([]uint16, len(p)+1)
		for i, r := range p {
			pu[i] = uint16(r)
		}
		pathBytes := make([]byte, len(pu)*2)
		for i, c := range pu {
			binary.LittleEndian.PutUint16(pathBytes[i*2:], c)
		}
		// body = pathSize(2) + path + lastMod(8) + dataSize(4) + data(4: exec flag)
		data := []byte{1, 0, 0, 0} // executed = 1
		bodySize := 2 + len(pathBytes) + 8 + 4 + len(data)
		entry := make([]byte, 12+bodySize)
		copy(entry[0:4], []byte("10ts"))
		binary.LittleEndian.PutUint32(entry[8:12], uint32(bodySize))
		binary.LittleEndian.PutUint16(entry[12:14], uint16(len(pathBytes)))
		copy(entry[14:], pathBytes)
		modOff := 14 + len(pathBytes)
		intervals := uint64(133000000000000000) // arbitrary valid FILETIME
		binary.LittleEndian.PutUint64(entry[modOff:], intervals)
		binary.LittleEndian.PutUint32(entry[modOff+8:], uint32(len(data)))
		copy(entry[modOff+12:], data)
		out = append(out, entry...)
	}
	return out
}

func TestParseShimcacheWin10(t *testing.T) {
	blob := buildShimcacheBlob([]string{`C:\Games\cs2.exe`, `C:\Tools\XONE\loader.exe`})
	entries := parseShimcacheWin10(blob, []string{"XONE"})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Path != `C:\Games\cs2.exe` {
		t.Fatalf("entry0 path = %q", entries[0].Path)
	}
	if entries[0].Matched != "" {
		t.Fatalf("entry0 should not match, got %q", entries[0].Matched)
	}
	if !entries[0].Executed {
		t.Fatal("entry0 Executed should be true (data flag = 1)")
	}
	if entries[1].Matched != "XONE" {
		t.Fatalf("entry1 should match XONE, got %q", entries[1].Matched)
	}
	if entries[1].Modified.IsZero() {
		t.Fatal("entry1 Modified should be parsed from filetime")
	}
}

func TestParseShimcacheWin10_BadMagic(t *testing.T) {
	blob := make([]byte, 64)
	if got := parseShimcacheWin10(blob, nil); got != nil {
		t.Fatalf("expected nil for bad magic, got %v", got)
	}
}

func TestMatchTargetName(t *testing.T) {
	targets := []string{"XONE", "exloader.exe", "nl.log"}
	cases := []struct {
		name, path, want string
	}{
		{"xone", `C:\xone\`, "XONE"},                      // exact dir-name
		{"exloader", `C:\t\exloader.exe`, "exloader.exe"}, // program name without ext
		{"cs2", `C:\games\cs2.exe`, ""},
		{"random", `D:\stuff\nl.log`, "nl.log"}, // path contains file name
		{"", `C:\nothing\here.exe`, ""},
	}
	for _, c := range cases {
		if got := matchTargetName(c.name, c.path, targets); got != c.want {
			t.Errorf("matchTargetName(%q, %q) = %q, want %q", c.name, c.path, got, c.want)
		}
	}
}

func TestFiletimeRoundTrip(t *testing.T) {
	// 2025-06-01 12:00:00 UTC in FILETIME
	want := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	ft := windows.Filetime{}
	ft.Nanoseconds() // keep compiler happy about import usage pattern
	// Convert via Windows API types: FILETIME = 100ns intervals since 1601.
	intervals := uint64(want.Unix()+11644473600) * 10_000_000
	ft.LowDateTime = uint32(intervals)
	ft.HighDateTime = uint32(intervals >> 32)
	got := FiletimeToTime(ft)
	if !got.Equal(want) {
		t.Fatalf("FiletimeToTime = %v, want %v", got, want)
	}
}
