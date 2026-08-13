//go:build windows
// +build windows

package winapi

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"scanner/internal/models"
	"scanner/internal/obfuscate"
)

// winUTF16ToString decodes a UTF-16LE byte slice (as stored in binary
// registry/MFT structures) into a Go string.
func winUTF16ToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return windows.UTF16ToString(u16)
}

// matchTargetName checks whether a program name (e.g. from a Prefetch file
// name) or a path references one of the configured target names
// (case-insensitive substring match). Returns the matched name or "".
func matchTargetName(nameLower, pathLower string, targetNames []string) string {
	for _, t := range targetNames {
		tl := strings.ToLower(strings.TrimSpace(t))
		if tl == "" {
			continue
		}
		if nameLower == tl || strings.Contains(pathLower, tl) {
			return t
		}
		// "exloader.exe" should also match program name "exloader"
		if nameLower == strings.TrimSuffix(tl, ".exe") {
			return t
		}
	}
	return ""
}

// MatchProgramName exposes matchTargetName for the engine wiring.
func MatchProgramName(nameLower, pathLower string, targetNames []string) string {
	return matchTargetName(nameLower, pathLower, targetNames)
}

// ─── ShimCache (AppCompatCache) ─────────────────────────────────────────────

const maxShimcacheEntries = 1024

// CollectShimcache parses the Windows 10/11 AppCompatCache (ShimCache):
// paths of programs the process-creation shim has seen, with the entry
// modification timestamp. Unknown/newer formats yield nil (best-effort).
func CollectShimcache(targetNames []string) []models.ShimcacheEntry {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, obfuscate.REG_SHIMCACHE_KEY(), registry.QUERY_VALUE)
	if err != nil {
		return nil // needs admin
	}
	defer key.Close()
	raw, _, err := key.GetBinaryValue(obfuscate.REG_SHIMCACHE_VAL())
	if err != nil || len(raw) < 12 {
		return nil
	}
	return parseShimcacheWin10(raw, targetNames)
}

// parseShimcacheWin10 decodes the Win10/11 ShimCache blob (layout per the
// public Velociraptor/Mandiant spec):
//
//	header: u32 headerSize (48 or 52) | ... | entries start at headerSize
//	entry:  char[4] sig "10ts" | u32 unknown | u32 bodySize | u16 pathSize |
//	        utf16le path | u64 lastMod FILETIME | u32 dataSize | data...
//	entry stride = 12 + bodySize; executed flag = last u32 of the data block.
func parseShimcacheWin10(raw []byte, targetNames []string) []models.ShimcacheEntry {
	if len(raw) < 8 {
		return nil
	}
	headerSize := int(binary.LittleEndian.Uint32(raw[0:4]))
	if headerSize != 48 && headerSize != 52 {
		return nil // not the Win10/11 format
	}
	off := headerSize

	var out []models.ShimcacheEntry
	for off+14 <= len(raw) && len(out) < maxShimcacheEntries {
		if raw[off] != '1' || raw[off+1] != '0' || raw[off+2] != 't' || raw[off+3] != 's' {
			break
		}
		bodySize := int(binary.LittleEndian.Uint32(raw[off+8:]))
		if bodySize <= 0 {
			break
		}
		entryLen := bodySize + 12
		if off+entryLen > len(raw) {
			break
		}
		pathSize := int(binary.LittleEndian.Uint16(raw[off+12:]))
		pathOff := off + 14
		modOff := pathOff + pathSize
		if modOff+8 > off+entryLen {
			break
		}
		path := ""
		if pathSize > 0 {
			path = winUTF16ToString(raw[pathOff : pathOff+pathSize])
		}
		ts := binary.LittleEndian.Uint64(raw[modOff:])
		mod := time.Time{}
		if ts != 0 {
			mod = FiletimeToTime(windows.Filetime{LowDateTime: uint32(ts), HighDateTime: uint32(ts >> 32)})
		}
		executed := false
		dataSizeOff := modOff + 8
		if dataSizeOff+4 <= off+entryLen {
			dataSize := int(binary.LittleEndian.Uint32(raw[dataSizeOff:]))
			execOff := dataSizeOff + 4 + dataSize - 4
			if dataSize >= 4 && execOff+4 <= off+entryLen {
				executed = binary.LittleEndian.Uint32(raw[execOff:]) == 1
			}
		}
		if path != "" {
			out = append(out, models.ShimcacheEntry{
				Path:     path,
				Modified: mod,
				Executed: executed,
				Matched:  matchTargetName("", strings.ToLower(path), targetNames),
			})
		}
		off += entryLen
	}
	return out
}

// ─── Processes ──────────────────────────────────────────────────────────────

const maxProcessEntries = 512

// CollectProcesses snapshots running processes (Toolhelp32) and resolves the
// image path of each (best-effort; protected/system processes may have none).
// Matched is set when the process name or path hits a configured target name.
func CollectProcesses(targetNames []string) []models.ProcessEntry {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)

	kernel32 := windows.NewLazySystemDLL(obfuscate.KERNEL32())
	openProcess := kernel32.NewProc(obfuscate.OPEN_PROCESS_PROC())
	queryFullName := kernel32.NewProc(obfuscate.QUERY_FULL_IMAGE_PROC())

	out := make([]models.ProcessEntry, 0, 256)
	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil
	}
	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		pe := models.ProcessEntry{PID: entry.ProcessID, Name: name}
		pe.Path = processImagePath(openProcess, queryFullName, entry.ProcessID)
		lowerName := strings.ToLower(name)
		pe.Matched = matchTargetName(strings.TrimSuffix(lowerName, ".exe"), strings.ToLower(pe.Path), targetNames)
		out = append(out, pe)
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
		if len(out) >= maxProcessEntries {
			break
		}
	}
	return out
}

func processImagePath(openProcess, queryFullName *windows.LazyProc, pid uint32) string {
	const processQueryLimitedInformation = 0x1000
	h, _, _ := openProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer windows.CloseHandle(windows.Handle(h))
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	r, _, _ := queryFullName.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// ─── Services / drivers ─────────────────────────────────────────────────────

const (
	maxDriverEntries   = 1024
	driverRecentWindow = 7 * 24 * time.Hour
)

// CollectDrivers enumerates installed kernel/file-system drivers from
// HKLM\SYSTEM\CurrentControlSet\Services. A driver gets the "blacklist" flag
// when its image file name is a known-abused (BYOVD) driver — the exact class
// cheats load via KDMapper-style mappers; and the "recent" flag when the
// service key was modified within the last week (fresh install before a check).
func CollectDrivers(blacklist []string) []models.DriverEntry {
	servicesKey := obfuscate.REG_SERVICES_KEY()
	rootKey, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer rootKey.Close()
	names, err := rootKey.ReadSubKeyNames(0)
	if err != nil {
		return nil
	}

	bl := make(map[string]bool, len(blacklist))
	for _, b := range blacklist {
		b = strings.ToLower(strings.TrimSpace(b))
		if b != "" {
			bl[b] = true
		}
	}
	recentAfter := time.Now().Add(-driverRecentWindow)

	out := make([]models.DriverEntry, 0, 256)
	for _, name := range names {
		if len(out) >= maxDriverEntries {
			break
		}
		sub, err := registry.OpenKey(registry.LOCAL_MACHINE, servicesKey+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		// 1 = kernel driver, 2 = file-system driver; Win32 services are noise.
		typ, _, err := sub.GetIntegerValue("Type")
		if err != nil || (typ != 1 && typ != 2) {
			sub.Close()
			continue
		}
		imagePath, _, _ := sub.GetStringValue("ImagePath")
		info, _ := sub.Stat()
		sub.Close()

		de := models.DriverEntry{Name: name, ImagePath: imagePath}
		if typ == 1 {
			de.Kind = "kernel"
		} else {
			de.Kind = "fs"
		}
		if info != nil {
			de.KeyModified = info.ModTime()
		}
		base := strings.ToLower(filepath.Base(strings.ReplaceAll(imagePath, "/", "\\")))
		// "recent" only makes sense for drivers outside the stock Windows
		// locations — otherwise every Windows update flags hundreds of
		// system32\drivers entries (pure noise).
		pathLower := strings.ToLower(strings.ReplaceAll(imagePath, "/", "\\"))
		stock := strings.Contains(pathLower, `system32\drivers`) || strings.Contains(pathLower, `system32\driverstore`)
		switch {
		case bl[base]:
			de.Flag = "blacklist"
		case info != nil && !stock && de.KeyModified.After(recentAfter):
			de.Flag = "recent"
		}
		out = append(out, de)
	}
	return out
}

// ─── BAM / DAM ──────────────────────────────────────────────────────────────

const maxBamEntries = 1024

// CollectBamDam parses Background/Shell Activity Moderator state: per-user
// launch records (value name = program path, QWORD value = last run FILETIME).
// Needs admin (HKLM).
func CollectBamDam(targetNames []string) []models.BamEntry {
	var out []models.BamEntry
	roots := []struct {
		key    string
		source string
	}{
		{obfuscate.REG_BAM_KEY(), "bam"},
		{obfuscate.REG_DAM_KEY(), "dam"},
	}
	for _, root := range roots {
		rootKey, err := registry.OpenKey(registry.LOCAL_MACHINE, root.key, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		sids, err := rootKey.ReadSubKeyNames(0)
		rootKey.Close()
		if err != nil {
			continue
		}
		for _, sid := range sids {
			if len(out) >= maxBamEntries {
				return out
			}
			sub, err := registry.OpenKey(registry.LOCAL_MACHINE, root.key+`\`+sid, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			valueNames, err := sub.ReadValueNames(0)
			if err != nil {
				sub.Close()
				continue
			}
			for _, vname := range valueNames {
				if len(out) >= maxBamEntries {
					break
				}
				n, _, err := sub.GetValue(vname, nil)
				if err != nil || n < 8 {
					continue
				}
				buf := make([]byte, n)
				n, _, err = sub.GetValue(vname, buf)
				if err != nil || n < 8 {
					continue
				}
				ts := binary.LittleEndian.Uint64(buf[:8])
				lastRun := FiletimeToTime(windows.Filetime{LowDateTime: uint32(ts), HighDateTime: uint32(ts >> 32)})
				if lastRun.Year() < 2000 || lastRun.After(time.Now().Add(24*time.Hour)) {
					continue
				}
				out = append(out, models.BamEntry{
					Source:  root.source,
					UserSID: sid,
					Path:    vname,
					LastRun: lastRun,
					Matched: matchTargetName("", strings.ToLower(vname), targetNames),
				})
			}
			sub.Close()
		}
	}
	return out
}

// ─── Prefetch ───────────────────────────────────────────────────────────────

const maxPrefetchEntries = 512

// CollectPrefetch lists Windows Prefetch .pf files. A .pf name is
// "<PROGRAM>.EXE-<8 hex>.pf"; its mtime approximates the last program launch.
// The .pf file format itself (compressed on Win10+) is not parsed — the
// metadata alone already answers "was cheat X ever launched here".
func CollectPrefetch(targetNames []string) []models.PrefetchEntry {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	dir := filepath.Join(root, obfuscate.PF_DIR_NAME())
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil // needs admin; Prefetch may also be disabled
	}

	out := make([]models.PrefetchEntry, 0, 128)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".pf") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		// PROGRAM.EXE-1234ABCD.pf -> PROGRAM.EXE
		base := strings.TrimSuffix(name, filepath.Ext(name))
		if i := strings.LastIndexByte(base, '-'); i > 0 {
			base = base[:i]
		}
		entry := models.PrefetchEntry{
			Name:     base,
			Path:     filepath.Join(dir, name),
			Size:     info.Size(),
			Modified: info.ModTime(),
		}
		if stat, ok := info.Sys().(*windows.Win32FileAttributeData); ok {
			entry.Created = FiletimeToTime(stat.CreationTime)
		}
		entry.Matched = matchTargetName(strings.ToLower(base), strings.ToLower(entry.Path), targetNames)
		out = append(out, entry)
	}

	// Most recently launched first.
	sort.Slice(out, func(i, j int) bool { return out[i].Modified.After(out[j].Modified) })
	if len(out) > maxPrefetchEntries {
		out = out[:maxPrefetchEntries]
	}
	return out
}
