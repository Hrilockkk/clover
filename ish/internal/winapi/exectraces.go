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

// This file collects program-execution artifacts beyond Prefetch/ShimCache/
// BAM/Amcache. Each source is maintained by a different Windows component,
// so wiping one (e.g. deleting Prefetch) leaves the others intact —
// cross-checking them exposes cleanup attempts.
//
// All collectors are best-effort: a missing key/file (feature disabled,
// older Windows, no rights) yields nil, never an abort.

const maxExecTracePerSource = 512

// CollectExecTraces gathers all execution-trace artifacts and flags entries
// matching the configured target names. Newest entries (those with a known
// timestamp) come first.
func CollectExecTraces(targetNames []string) []models.ExecTraceEntry {
	var out []models.ExecTraceEntry
	appendAll := func(entries []models.ExecTraceEntry) {
		for _, e := range entries {
			if len(out) >= maxExecTracePerSource*8 {
				return
			}
			out = append(out, e)
		}
	}
	appendAll(collectUserAssist(targetNames))
	appendAll(collectRecentApps(targetNames))
	appendAll(collectAppSwitched(targetNames))
	appendAll(collectMuiCache(targetNames))
	appendAll(collectAppCompatStore(targetNames))
	appendAll(collectRunMRU(targetNames))
	appendAll(collectComDlg32(targetNames))
	appendAll(collectPCA(targetNames))
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastRun.After(out[j].LastRun) })
	return out
}

func matchExecTrace(nameLower, pathLower string, targetNames []string) string {
	return matchTargetName(nameLower, pathLower, targetNames)
}

// baseName extracts a display name from a path-ish string.
func execBaseName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ReplaceAll(s, "/", `\`)
	s = strings.Trim(s, `"`)
	if i := strings.LastIndexByte(s, '\\'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// matchExecName is the common matcher for an entry whose name/path we have.
func matchExecName(name, path string, targetNames []string) string {
	return matchExecTrace(strings.ToLower(strings.TrimSuffix(name, ".exe")), strings.ToLower(path), targetNames)
}

// ─── UserAssist (ROT13, run count + last run) ───────────────────────────────

// rot13 applies the ROT13 substitution UserAssist uses for its value names.
func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

// collectUserAssist parses HKCU\...\Explorer\UserAssist\{GUID}\Count.
// Data layout (Win7+, 72 bytes): u32 session @0, u32 runCount @4,
// u32 focusCount @8, FILETIME lastRun @60.
func collectUserAssist(targetNames []string) []models.ExecTraceEntry {
	root, err := registry.OpenKey(registry.CURRENT_USER, obfuscate.REG_USERASSIST_KEY(), registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	guids, err := root.ReadSubKeyNames(0)
	root.Close()
	if err != nil {
		return nil
	}

	var out []models.ExecTraceEntry
	for _, guid := range guids {
		if len(out) >= maxExecTracePerSource {
			break
		}
		sub, err := registry.OpenKey(registry.CURRENT_USER, obfuscate.REG_USERASSIST_KEY()+`\`+guid+`\Count`, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		valueNames, err := sub.ReadValueNames(0)
		if err != nil {
			sub.Close()
			continue
		}
		for _, vname := range valueNames {
			if len(out) >= maxExecTracePerSource {
				break
			}
			n, _, err := sub.GetValue(vname, nil)
			if err != nil || n < 16 {
				continue
			}
			buf := make([]byte, n)
			if _, _, err := sub.GetValue(vname, buf); err != nil {
				continue
			}
			decoded := rot13(vname)
			// Skip UEME_* bookkeeping values — not program launches.
			if strings.HasPrefix(strings.ToUpper(decoded), "UEME_") {
				continue
			}
			e := models.ExecTraceEntry{Source: "userassist"}
			e.Count = binary.LittleEndian.Uint32(buf[4:8])
			if len(buf) >= 68 {
				ts := binary.LittleEndian.Uint64(buf[60:68])
				if ts != 0 {
					e.LastRun = FiletimeToTime(windows.Filetime{LowDateTime: uint32(ts), HighDateTime: uint32(ts >> 32)})
				}
			}
			if strings.Contains(decoded, `:\`) || strings.HasPrefix(decoded, `\\`) {
				e.Path = decoded
				e.Name = execBaseName(decoded)
			} else {
				e.Name = execBaseName(decoded)
			}
			if e.Name == "" {
				continue
			}
			e.Matched = matchExecName(e.Name, e.Path, targetNames)
			out = append(out, e)
		}
		sub.Close()
	}
	return out
}

// ─── RecentApps (Win10 1703+ search indexer) ────────────────────────────────

func collectRecentApps(targetNames []string) []models.ExecTraceEntry {
	root, err := registry.OpenKey(registry.CURRENT_USER, obfuscate.REG_RECENTAPPS_KEY(), registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	guids, err := root.ReadSubKeyNames(0)
	root.Close()
	if err != nil {
		return nil
	}

	var out []models.ExecTraceEntry
	for _, guid := range guids {
		if len(out) >= maxExecTracePerSource {
			break
		}
		sub, err := registry.OpenKey(registry.CURRENT_USER, obfuscate.REG_RECENTAPPS_KEY()+`\`+guid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		e := models.ExecTraceEntry{Source: "recentapps"}
		appPath, _, _ := sub.GetStringValue("AppPath")
		e.Path = appPath
		e.Name = execBaseName(appPath)
		if cnt, _, err := sub.GetIntegerValue("LaunchCount"); err == nil {
			e.Count = uint32(cnt)
		}
		if n, _, err := sub.GetValue("LastAccessedTime", nil); err == nil && n >= 8 {
			buf := make([]byte, n)
			if n, _, err := sub.GetValue("LastAccessedTime", buf); err == nil && n >= 8 {
				ts := binary.LittleEndian.Uint64(buf[:8])
				if ts != 0 {
					e.LastRun = FiletimeToTime(windows.Filetime{LowDateTime: uint32(ts), HighDateTime: uint32(ts >> 32)})
				}
			}
		}
		sub.Close()
		if e.Name == "" {
			continue
		}
		e.Matched = matchExecName(e.Name, e.Path, targetNames)
		out = append(out, e)
	}
	return out
}

// ─── FeatureUsage\AppSwitched (taskbar app switching) ───────────────────────

func collectAppSwitched(targetNames []string) []models.ExecTraceEntry {
	key, err := registry.OpenKey(registry.CURRENT_USER, obfuscate.REG_APPSWITCHED_KEY(), registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()
	valueNames, err := key.ReadValueNames(0)
	if err != nil {
		return nil
	}

	var out []models.ExecTraceEntry
	for _, vname := range valueNames {
		if len(out) >= maxExecTracePerSource {
			break
		}
		cnt, _, err := key.GetIntegerValue(vname)
		if err != nil {
			continue
		}
		name := execBaseName(vname)
		if name == "" {
			continue
		}
		out = append(out, models.ExecTraceEntry{
			Source:  "appswitched",
			Name:    name,
			Path:    vname,
			Count:   uint32(cnt),
			Matched: matchExecName(name, vname, targetNames),
		})
	}
	return out
}

// ─── MuiCache (app friendly names for executed binaries) ────────────────────

func collectMuiCache(targetNames []string) []models.ExecTraceEntry {
	key, err := registry.OpenKey(registry.CURRENT_USER, obfuscate.REG_MUICACHE_KEY(), registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()
	valueNames, err := key.ReadValueNames(0)
	if err != nil {
		return nil
	}

	var out []models.ExecTraceEntry
	for _, vname := range valueNames {
		if len(out) >= maxExecTracePerSource {
			break
		}
		// Value names look like "C:\path\app.exe.FriendlyAppName".
		idx := strings.LastIndex(vname, ".FriendlyAppName")
		if idx <= 0 {
			continue
		}
		path := vname[:idx]
		friendly, _, _ := key.GetStringValue(vname)
		name := execBaseName(path)
		if name == "" {
			continue
		}
		out = append(out, models.ExecTraceEntry{
			Source:  "muicache",
			Name:    name,
			Path:    path,
			Extra:   friendly,
			Matched: matchExecName(name, path, targetNames),
		})
	}
	return out
}

// ─── AppCompatFlags\Compatibility Assistant\Store ───────────────────────────

func collectAppCompatStore(targetNames []string) []models.ExecTraceEntry {
	key, err := registry.OpenKey(registry.CURRENT_USER, obfuscate.REG_APPCOMPAT_STORE_KEY(), registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()
	valueNames, err := key.ReadValueNames(0)
	if err != nil {
		return nil
	}

	var out []models.ExecTraceEntry
	for _, vname := range valueNames {
		if len(out) >= maxExecTracePerSource {
			break
		}
		// The value name IS the executable path; data is an opaque binary blob.
		name := execBaseName(vname)
		if name == "" {
			continue
		}
		out = append(out, models.ExecTraceEntry{
			Source:  "appcompatstore",
			Name:    name,
			Path:    vname,
			Matched: matchExecName(name, vname, targetNames),
		})
	}
	return out
}

// ─── RunMRU (Win+R command history) ─────────────────────────────────────────

func collectRunMRU(targetNames []string) []models.ExecTraceEntry {
	key, err := registry.OpenKey(registry.CURRENT_USER, obfuscate.REG_RUNMRU_KEY(), registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()
	valueNames, err := key.ReadValueNames(0)
	if err != nil {
		return nil
	}

	var out []models.ExecTraceEntry
	for _, vname := range valueNames {
		if len(out) >= maxExecTracePerSource {
			break
		}
		// Letters a..z hold commands; MRUListEx/MRUList are the order blobs.
		if strings.EqualFold(vname, "MRUListEx") || strings.EqualFold(vname, "MRUList") {
			continue
		}
		cmd, _, err := key.GetStringValue(vname)
		if err != nil || strings.TrimSpace(cmd) == "" {
			continue
		}
		// Commands are often suffixed with "\1" (Explorer separator).
		cmd = strings.TrimSuffix(cmd, `\1`)
		name := execBaseName(cmd)
		out = append(out, models.ExecTraceEntry{
			Source:  "runmru",
			Name:    name,
			Extra:   cmd,
			Matched: matchExecName(name, cmd, targetNames),
		})
	}
	return out
}

// ─── ComDlg32\LastVisitedPidlMRU (exe paths from open/save dialogs) ─────────

func collectComDlg32(targetNames []string) []models.ExecTraceEntry {
	key, err := registry.OpenKey(registry.CURRENT_USER, obfuscate.REG_COMDLG32_KEY(), registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer key.Close()
	valueNames, err := key.ReadValueNames(0)
	if err != nil {
		return nil
	}

	var out []models.ExecTraceEntry
	for _, vname := range valueNames {
		if len(out) >= maxExecTracePerSource {
			break
		}
		if strings.EqualFold(vname, "MRUListEx") {
			continue
		}
		n, _, err := key.GetValue(vname, nil)
		if err != nil || n < 4 {
			continue
		}
		buf := make([]byte, n)
		n, _, err = key.GetValue(vname, buf)
		if err != nil {
			continue
		}
		// Data starts with the UTF-16LE path of the exe that used the dialog,
		// NUL-terminated, followed by the shell-item PIDL of the folder.
		end := 0
		for end+1 < n {
			if buf[end] == 0 && buf[end+1] == 0 {
				break
			}
			end += 2
		}
		path := strings.TrimSpace(winUTF16ToString(buf[:end]))
		name := execBaseName(path)
		if name == "" {
			continue
		}
		out = append(out, models.ExecTraceEntry{
			Source:  "comdlg32",
			Name:    name,
			Path:    path,
			Matched: matchExecName(name, path, targetNames),
		})
	}
	return out
}

// ─── PCA text logs (Win11 22H2+: PcaAppLaunchDic.txt / PcaGeneralDb*.txt) ───

var pcaTimeLayouts = []string{
	"2006-01-02 15:04:05.9999999 -07:00",
	"2006-01-02 15:04:05.9999999",
	"2006-01-02 15:04:05 -07:00",
	"2006-01-02 15:04:05",
	time.RFC3339,
}

func parsePCATime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range pcaTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// collectPCA reads the Program Compatibility Assistant pipe-separated text
// logs. PcaAppLaunchDic.txt: "path|launch time". PcaGeneralDb0/1.txt:
// "exe|desc|path|...|time|..." — the first field is the program, the last
// parseable time field is LastRun.
func collectPCA(targetNames []string) []models.ExecTraceEntry {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	dir := filepath.Join(sysRoot, obfuscate.PCA_DIR_NAME())
	files := []string{"PcaAppLaunchDic.txt", "PcaGeneralDb0.txt", "PcaGeneralDb1.txt"}

	var out []models.ExecTraceEntry
	for _, fname := range files {
		if len(out) >= maxExecTracePerSource {
			break
		}
		data, err := os.ReadFile(filepath.Join(dir, fname))
		if err != nil {
			continue // file absent (pre-Win11 or PCA disabled) or no rights
		}
		lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		for _, line := range lines {
			if len(out) >= maxExecTracePerSource {
				break
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			fields := strings.Split(line, "|")
			prog := strings.TrimSpace(fields[0])
			if prog == "" {
				continue
			}
			e := models.ExecTraceEntry{Source: "pca"}
			// First field may be a full path (PcaAppLaunchDic) or a bare
			// exe name with the path in a later field (PcaGeneralDb).
			if strings.Contains(prog, `:\`) {
				e.Path = prog
			}
			for _, f := range fields[1:] {
				f = strings.TrimSpace(f)
				if e.Path == "" && strings.Contains(f, `:\`) {
					e.Path = f
				}
				if e.LastRun.IsZero() {
					if t := parsePCATime(f); !t.IsZero() {
						e.LastRun = t
					}
				}
			}
			e.Name = execBaseName(prog)
			if e.Name == "" {
				continue
			}
			e.Extra = fname
			e.Matched = matchExecName(e.Name, e.Path, targetNames)
			out = append(out, e)
		}
	}
	return out
}

// ─── Open windows (ESP overlays hide as borderless game-titled windows) ─────

const maxWindowEntries = 256

// CollectWindows enumerates visible top-level windows with their owning
// process name/path and flags target-name matches.
func CollectWindows(targetNames []string) []models.WindowEntry {
	user32 := windows.NewLazySystemDLL(obfuscate.USER32())
	enumWindows := user32.NewProc("EnumWindows")
	isVisible := user32.NewProc("IsWindowVisible")
	getText := user32.NewProc("GetWindowTextW")
	getTextLen := user32.NewProc("GetWindowTextLengthW")
	getThreadProc := user32.NewProc("GetWindowThreadProcessId")

	kernel32 := windows.NewLazySystemDLL(obfuscate.KERNEL32())
	openProcess := kernel32.NewProc(obfuscate.OPEN_PROCESS_PROC())
	queryFullName := kernel32.NewProc(obfuscate.QUERY_FULL_IMAGE_PROC())

	var out []models.WindowEntry
	cb := windows.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		if len(out) >= maxWindowEntries {
			return 0 // stop enumeration
		}
		vis, _, _ := isVisible.Call(hwnd)
		if vis == 0 {
			return 1
		}
		ln, _, _ := getTextLen.Call(hwnd)
		if ln == 0 {
			return 1
		}
		buf := make([]uint16, ln+2)
		r, _, _ := getText.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if r == 0 {
			return 1
		}
		title := strings.TrimSpace(windows.UTF16ToString(buf[:int(r)]))
		if title == "" {
			return 1
		}
		var pid uint32
		getThreadProc.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		we := models.WindowEntry{Title: title}
		if pid != 0 {
			we.Path = processImagePath(openProcess, queryFullName, pid)
			we.Process = execBaseName(we.Path)
		}
		we.Matched = matchTargetName(strings.ToLower(strings.TrimSuffix(we.Process, ".exe")), strings.ToLower(we.Path+" "+title), targetNames)
		out = append(out, we)
		return 1
	})
	enumWindows.Call(cb, 0)
	return out
}

// ─── Driver signature verification (WinVerifyTrust) ─────────────────────────

// wintrust structures for WTD_CHOICE_FILE verification.
type wintrustFileInfo struct {
	StructSize   uint32
	FilePath     *uint16
	File         windows.Handle
	KnownSubject *windows.GUID
}

type wintrustData struct {
	StructSize         uint32
	PolicyCallbackData uintptr
	SIPClientData      uintptr
	UIChoice           uint32 // WTD_UI_NONE = 2
	RevocationChecks   uint32 // WTD_REVOKE_NONE = 0
	UnionChoice        uint32 // WTD_CHOICE_FILE = 1
	FileInfo           *wintrustFileInfo
	StateAction        uint32 // WTD_STATEACTION_IGNORE = 0
	StateData          windows.Handle
	URLReference       *uint16
	ProvFlags          uint32
	UIContext          uint32
	SignatureSettings  uintptr
}

var wintrustActionGenericVerifyV2 = windows.GUID{
	Data1: 0x00AAC56B, Data2: 0xCD44, Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

const (
	wtdUICnone           = 2
	wtdRevokeNone        = 0
	wtdChoiceFile        = 1
	wtdStateActionIgnore = 0
	wtdCacheOnlyURLRetr  = 0x1000 // WTD_CACHE_ONLY_URL_RETRIEVAL — no network stalls
	maxDriverSigChecks   = 256
)

// resolveDriverImagePath turns registry ImagePath forms
// ("\SystemRoot\System32\drivers\x.sys", "system32\...", "\??\C:\...")
// into a plain filesystem path.
func resolveDriverImagePath(imagePath string) string {
	p := strings.TrimSpace(imagePath)
	p = strings.Trim(p, `"`)
	lower := strings.ToLower(p)
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	switch {
	case strings.HasPrefix(lower, `\??\`):
		p = p[4:]
	case strings.HasPrefix(lower, `\systemroot\`):
		p = sysRoot + p[len(`\SystemRoot`):]
	case strings.HasPrefix(lower, `system32\`):
		p = filepath.Join(sysRoot, p)
	}
	return p
}

// verifyFileSignature reports whether the file carries a valid Authenticode
// signature (best-effort; offline CRL failures count as unsigned).
func verifyFileSignature(path string) bool {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	fi := &wintrustFileInfo{StructSize: uint32(binary.Size(wintrustFileInfo{})), FilePath: pathPtr}
	wtd := &wintrustData{
		StructSize:       uint32(binary.Size(wintrustData{})),
		UIChoice:         wtdUICnone,
		RevocationChecks: wtdRevokeNone,
		UnionChoice:      wtdChoiceFile,
		FileInfo:         fi,
		StateAction:      wtdStateActionIgnore,
		ProvFlags:        wtdCacheOnlyURLRetr,
	}
	wt := windows.NewLazySystemDLL(obfuscate.WINTRUST())
	winVerifyTrust := wt.NewProc("WinVerifyTrust")
	ret, _, _ := winVerifyTrust.Call(
		^uintptr(0), // INVALID_HANDLE_VALUE
		uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(wtd)),
	)
	return ret == 0 // ERROR_SUCCESS
}

// FlagUnsignedDrivers marks non-stock drivers whose image file fails
// Authenticode verification. Precedence: blacklist > unsigned > recent.
func FlagUnsignedDrivers(drivers []models.DriverEntry) {
	checked := 0
	for i := range drivers {
		if checked >= maxDriverSigChecks {
			return
		}
		d := &drivers[i]
		if d.Flag == "blacklist" {
			continue
		}
		pathLower := strings.ToLower(strings.ReplaceAll(d.ImagePath, "/", `\`))
		stock := strings.Contains(pathLower, `system32\drivers`) || strings.Contains(pathLower, `system32\driverstore`)
		if stock {
			continue // stock Windows drivers are catalog-signed (no embedded sig)
		}
		fsPath := resolveDriverImagePath(d.ImagePath)
		if fsPath == "" {
			continue
		}
		if _, err := os.Stat(fsPath); err != nil {
			continue
		}
		checked++
		if !verifyFileSignature(fsPath) {
			d.Flag = "unsigned"
		}
	}
}
