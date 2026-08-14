//go:build windows
// +build windows

package winapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/sys/windows/registry"
	"scanner/internal/models"
)

var shellbagRoots = []string{
	`Software\Microsoft\Windows\Shell\BagMRU`,
	`Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`,
}

// ─── Full BagMRU listing (shellbag_analyzer_cleaner style) ─────────────────
//
// BagMRU layout: every key is a folder node; its numeric values (slot names
// "0","1",...) hold child shell items; the MRUListEx value lists the slots
// that are still "live" — slots present as values but absent from MRUListEx
// are old/deleted entries. Folder shell items (0x31/0x32/...) carry a FAT
// modified timestamp at offset 8 and usually a 0xBEEF0004 extension block
// with creation/access FAT timestamps.

// fatDateTime converts the packed date/time pair stored in shell items into
// time.Time. In shell items the LOW word is the FAT date (year-1980:7,
// month:4, day:5) and the HIGH word is the FAT time (h:5, m:6, s/2:5).
func fatDateTime(v uint32) time.Time {
	if v == 0 {
		return time.Time{}
	}
	d, t := v&0xFFFF, v>>16
	year := int((d>>9)&0x7F) + 1980
	mon := time.Month((d >> 5) & 0x0F)
	day := int(d & 0x1F)
	hh := int(t >> 11)
	mm := int((t >> 5) & 0x3F)
	ss := int(t&0x1F) * 2
	if year < 2000 || year > 2107 || mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59 {
		return time.Time{}
	}
	return time.Date(year, mon, day, hh, mm, ss, 0, time.Local)
}

// parseShellItemName extracts a display name from a shell item blob.
// Drive items (0x2F) hold "C:\" at offset 3. Folder/file items (0x31/0x32/
// 0x35/0x36/0x74/0x61) carry the primary ASCII name at offset 14 (right after
// size/type/filesize/modified/unk); a long UTF-16 name may follow the last
// 0xBEEF0004 extension block and wins when present.
func parseShellItemName(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	typ := data[2]
	if typ == 0x2F { // drive
		if name := asciiRunN2(data, 3); name != "" {
			return name
		}
	}

	primary := ""
	switch typ {
	case 0x31, 0x32, 0x35, 0x36, 0x61, 0x71, 0x74:
		primary = asciiRunN2(data, 14)
		// The primary name field is ANSI: if the real name contains Cyrillic
		// (or other non-ASCII) chars, the ANSI run is just a garbage prefix —
		// drop it so the UTF-16 long name wins.
		if primary != "" && strings.HasSuffix(primary, "?") {
			primary = ""
		}
	}

	// Long name: printable run starting strictly after the LAST 0xBEEF0004
	// signature, at a real boundary.
	beef := -1
	for i := 0; i+4 <= len(data); i++ {
		if data[i] == 0x04 && data[i+1] == 0x00 && data[i+2] == 0xEF && data[i+3] == 0xBE {
			beef = i
		}
	}
	longName := ""
	if beef >= 0 {
		for i := beef + 4; i < len(data)-2; i++ {
			if s, n := utf16Run(data, i); s != "" {
				s = cleanLongName(s, primary)
				if isPlausibleName(s) && len(s) > len(longName) {
					longName = s
				}
				i += n
			}
		}
	}
	if len(longName) > len(primary) && isPlausibleName(longName) {
		return longName
	}
	if isPlausibleName(primary) {
		return primary
	}
	return ""
}

// asciiRunN2 reads a printable ASCII run starting exactly at pos with a hard
// left boundary (previous byte must be non-printable) — used for the
// fixed-offset primary name so no header byte can bleed into the string.
func asciiRunN2(data []byte, pos int) string {
	if pos >= len(data) || !isPrintableASCII(data[pos]) {
		return ""
	}
	if pos > 0 && isPrintableASCII(data[pos-1]) {
		return "" // not a real run start
	}
	end := pos
	for end < len(data) && isPrintableASCII(data[end]) {
		end++
	}
	if end-pos < 2 {
		return ""
	}
	return string(data[pos:end])
}

func isASCIILetter(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
}

// cleanLongName fixes the extra head character that Win10/11 shell items
// sometimes carry before the UTF-16 long name inside the 0xBEEF0004 block
// (observed: "]browserdownloadsview-x64.zip", "Ooneaccounts-extension",
// "l_internal"). Two reliable tells: the head is punctuation, or dropping it
// yields exactly the primary (offset-14) name.
func cleanLongName(s, primary string) string {
	rs := []rune(s)
	if len(rs) < 2 {
		return s
	}
	head, tail := rs[0], string(rs[1:])
	// Tell 1: leading char cannot begin a filename (']', '|', ...).
	if !isNameHeadChar(head) {
		return tail
	}
	// Tell 2: tail equals the primary name (case-insensitive) → head is junk.
	if primary != "" && strings.EqualFold(tail, primary) {
		return tail
	}
	// Tell 3 (no primary): head is an ASCII letter whose lowercase twin also
	// appears right after — "Ooneaccounts" style ("Oo" + real lowercase name).
	if primary == "" && len(rs) >= 3 && isASCIILetter(head) &&
		isASCIILetter(rs[1]) && rs[1] == []rune(strings.ToLower(string(head)))[0] &&
		strings.Contains(strings.ToLower(tail), strings.ToLower(string(head))) {
		return tail
	}
	return s
}

// isNameHeadChar reports whether r can plausibly start a file/folder name.
func isNameHeadChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) ||
		r == '_' || r == '-' || r == '.' || r == ' ' || r == '(' || r == '~' ||
		r == '#' || r == '$' || r == '@' || r == '!' || r == '&' || r == '+' ||
		r == '=' || r == '\'' || r == '`'
}

// isPlausibleName filters out GUIDs, paths and punctuation-only runs so the
// candidate pool for item names stays clean.
func isPlausibleName(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	if strings.ContainsAny(s, "{}\\:/") {
		return false
	}
	// Needs at least one letter/digit/cyrillic.
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r > 0x7F {
			return true
		}
	}
	return false
}

// asciiRun reads a printable ASCII run starting at pos.
func asciiRun(data []byte, pos int) string {
	s, _ := asciiRunN(data, pos)
	return s
}

// asciiRunN returns the printable run starting at pos and its byte length.
// A run is accepted only at a hard boundary (previous byte non-printable) so
// that scanning never returns a suffix with a garbage prefix character.
func asciiRunN(data []byte, pos int) (string, int) {
	if pos >= len(data) || !isPrintableASCII(data[pos]) {
		return "", 0
	}
	if pos > 0 && isPrintableASCII(data[pos-1]) {
		return "", 0
	}
	end := pos
	for end < len(data) && isPrintableASCII(data[end]) {
		end++
	}
	if end-pos < 2 {
		return "", 0
	}
	return string(data[pos:end]), end - pos
}

// utf16Run reads a printable UTF-16LE run starting at pos (low byte
// printable, high byte zero or cyrillic range 0x04xx). Same hard-boundary
// rule as asciiRunN.
func utf16Run(data []byte, pos int) (string, int) {
	if pos+1 >= len(data) {
		return "", 0
	}
	okByte := func(i int) bool {
		lo, hi := data[i], data[i+1]
		if hi == 0x00 && lo >= 0x20 && lo < 0x7F {
			return true
		}
		if hi == 0x04 && lo >= 0x10 { // Cyrillic U+0410+
			return true
		}
		return false
	}
	if !okByte(pos) {
		return "", 0
	}
	if pos >= 2 && okByte(pos-2) {
		return "", 0 // mid-run: skip, the real start was already visited
	}
	end := pos
	for end+1 < len(data) && okByte(end) {
		end += 2
	}
	if (end-pos)/2 < 2 {
		return "", 0
	}
	runes := make([]rune, 0, (end-pos)/2)
	for i := pos; i+1 < end; i += 2 {
		runes = append(runes, rune(uint16(data[i])|uint16(data[i+1])<<8))
	}
	return string(runes), end - pos
}

// shellItemTimestamps pulls modified (offset 8) and 0xBEEF0004
// created/accessed FAT timestamps out of the item blob.
func shellItemTimestamps(data []byte) (created, modified, accessed time.Time) {
	if len(data) < 12 {
		return
	}
	modified = fatDateTime(binary.LittleEndian.Uint32(data[8:12]))
	for i := 0; i+16 <= len(data); i++ {
		if data[i] == 0x04 && data[i+1] == 0x00 && data[i+2] == 0xEF && data[i+3] == 0xBE {
			// signature u32 at i; creation at i+4, access at i+8
			if c := fatDateTime(binary.LittleEndian.Uint32(data[i+4 : i+8])); !c.IsZero() {
				created = c
			}
			if a := fatDateTime(binary.LittleEndian.Uint32(data[i+8 : i+12])); !a.IsZero() {
				accessed = a
			}
		}
	}
	return
}

// ScanShellbagsFull enumerates every BagMRU slot in both hives and returns
// analyzer-style rows: resolved namespace path, slot number, existing/deleted
// flag and the timestamps recovered from the shell item.
func ScanShellbagsFull(targets []string) []models.ShellbagEntry {
	var out []models.ShellbagEntry
	seen := make(map[string]bool)
	for _, root := range shellbagRoots {
		k, err := registry.OpenKey(registry.CURRENT_USER, root, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		walkBagKey(k, "Desktop", "", targets, &out, seen)
		k.Close()
	}
	return out
}

func walkBagKey(k registry.Key, regPath, fsPath string, targets []string, out *[]models.ShellbagEntry, seen map[string]bool) {
	var keyMod time.Time
	if info, err := k.Stat(); err == nil {
		keyMod = info.ModTime()
	}

	active := map[uint32]bool{}
	hasMRU := false
	if raw, _, err := k.GetBinaryValue("MRUListEx"); err == nil && len(raw) >= 4 {
		hasMRU = true
		for i := 0; i+4 <= len(raw); i += 4 {
			v := binary.LittleEndian.Uint32(raw[i:])
			if v == 0xFFFFFFFF {
				break
			}
			active[v] = true
		}
	}

	names, err := k.ReadValueNames(-1)
	if err != nil {
		return
	}
	subNames, _ := k.ReadSubKeyNames(-1)
	subSet := make(map[string]bool, len(subNames))
	for _, s := range subNames {
		subSet[s] = true
	}

	for _, vn := range names {
		slot, err := strconv.Atoi(vn)
		if err != nil {
			continue // MRUListEx / NodeSlot etc.
		}
		data, _, err := k.GetBinaryValue(vn)
		if err != nil || len(data) < 4 {
			continue
		}

		name := parseShellItemName(data)
		created, modified, accessed := shellItemTimestamps(data)

		childPath := fsPath
		if name != "" {
			if fsPath == "" {
				childPath = name
			} else {
				sep := "\\"
				if strings.HasSuffix(fsPath, "\\") {
					sep = ""
				}
				childPath = fsPath + sep + name
			}
		}

		// Nameless entries are system/GUID items (This PC, Recycle Bin...) —
		// useless as rows, but their subkeys still hold real child folders.
		if name != "" {
			typ := "existing"
			if hasMRU && !active[uint32(slot)] {
				typ = "deleted"
			}

			entry := models.ShellbagEntry{
				Name:       name,
				Path:       childPath,
				Type:       typ,
				Slot:       slot,
				Created:    created,
				Modified:   modified,
				Accessed:   accessed,
				KeyModTime: keyMod,
			}
			for _, t := range targets {
				tl := strings.ToLower(strings.TrimSpace(t))
				if tl != "" && (strings.Contains(strings.ToLower(name), tl) || strings.Contains(strings.ToLower(childPath), tl)) {
					entry.Matched = t
					break
				}
			}
			key := childPath + "|" + strconv.Itoa(slot) + "|" + typ
			if !seen[key] {
				seen[key] = true
				*out = append(*out, entry)
			}
		}

		// Recurse into the same-numbered subkey with the resolved child path.
		if subSet[vn] {
			sk, err := registry.OpenKey(k, vn, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
			if err != nil {
				continue
			}
			walkBagKey(sk, regPath+"\\"+vn, childPath, targets, out, seen)
			sk.Close()
		}
	}

	// Cleaners often delete the slot VALUES but leave the numbered subkeys
	// behind — recurse into valueless subkeys too (path stays as-is).
	for _, sn := range subNames {
		if _, err := strconv.Atoi(sn); err != nil {
			continue
		}
		hadValue := false
		for _, vn := range names {
			if vn == sn {
				hadValue = true
				break
			}
		}
		if hadValue {
			continue // already recursed above
		}
		sk, err := registry.OpenKey(k, sn, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		walkBagKey(sk, regPath+"\\"+sn, fsPath, targets, out, seen)
		sk.Close()
	}
}

// ShellbagHit stores a single match found inside BagMRU binary data.
type ShellbagHit struct {
	Path       string
	TargetName string
	LastAccess time.Time
}

// ScanShellbags recursively reads BagMRU registry keys and searches binary
// values for occurrences of any name in targetDirNames. It tries to recover the
// real filesystem path and last-access time from the shell item blob.
func ScanShellbags(targetDirNames []string) []ShellbagHit {
	var allHits []ShellbagHit
	targets := make([]string, 0, len(targetDirNames))
	for _, n := range targetDirNames {
		if n = strings.TrimSpace(n); n != "" {
			targets = append(targets, strings.ToLower(n))
		}
	}
	if len(targets) == 0 {
		return allHits
	}
	for _, root := range shellbagRoots {
		k, err := registry.OpenKey(registry.CURRENT_USER, root, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[SHELLBAGS] open %s failed: %v\n", root, err)
			continue
		}
		hits := scanBagKey(k, root, targets)
		k.Close()
		if len(hits) > 0 {
			fmt.Fprintf(os.Stderr, "[SHELLBAGS] %s -> %d hits\n", root, len(hits))
		}
		allHits = append(allHits, hits...)
	}
	return allHits
}

func scanBagKey(k registry.Key, prefix string, targets []string) []ShellbagHit {
	var hits []ShellbagHit

	// Enumerate values (binary nodes)
	names, err := k.ReadValueNames(-1)
	if err == nil {
		for _, vn := range names {
			data, _, err := k.GetBinaryValue(vn)
			if err != nil || len(data) == 0 {
				continue
			}
			if found := findInBinary(data, targets, vn); found != nil {
				if found.Path == "" {
					found.Path = prefix + "/" + vn
				}
				if strings.TrimSpace(found.TargetName) == "" {
					found.TargetName = vn
				}
				hits = append(hits, *found)
			}
		}
	}

	// Recurse into sub-bags
	subNames, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return hits
	}
	for _, sn := range subNames {
		sk, err := registry.OpenKey(k, sn, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		newPrefix := prefix + "/" + sn
		hits = append(hits, scanBagKey(sk, newPrefix, targets)...)
		sk.Close()
	}
	return hits
}

// findInBinary searches raw BagMRU bytes for target directory names.
func findInBinary(data []byte, targets []string, valueName string) *ShellbagHit {
	lowerData := bytes.ToLower(data)
	for _, t := range targets {
		if t == "" {
			continue
		}
		idx := bytes.Index(lowerData, []byte(t))
		if idx >= 0 {
			ft := nearestFiletime(data, idx)
			name := strings.TrimSpace(string(data[idx : idx+len(t)]))
			if name == "" {
				name = t
			}
			bestPath := extractBestPath(data, name)
			return &ShellbagHit{TargetName: name, Path: bestPath, LastAccess: ft}
		}
	}
	return nil
}

// extractBestPath tries to recover a real filesystem path from the BagMRU blob.
// It looks for UTF-16LE and ASCII strings that look like Windows paths and prefers
// ones that contain the target folder name.
func extractBestPath(data []byte, targetName string) string {
	candidates := extractPathStrings(data)
	if len(candidates) == 0 {
		return ""
	}
	lowerTarget := strings.ToLower(targetName)
	var best string
	var bestScore int
	for _, p := range candidates {
		score := len(p)
		if lowerTarget != "" && strings.Contains(strings.ToLower(p), lowerTarget) {
			score += 100
		}
		if strings.Contains(p, ":\\") || strings.HasPrefix(p, "\\\\") {
			score += 50
		}
		if score > bestScore {
			bestScore = score
			best = p
		}
	}
	return best
}

// extractPathStrings extracts all printable UTF-16LE and ASCII strings from the
// blob and returns those that look like Windows filesystem paths.
func extractPathStrings(data []byte) []string {
	var out []string
	seen := make(map[string]bool)

	// UTF-16LE strings.
	for i := 0; i < len(data)-2; i += 2 {
		if s, ok := readUTF16LEString(data, i); ok && len(s) >= 3 && looksLikePath(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}

	// ASCII strings.
	for i := 0; i < len(data); i++ {
		if s, ok := readASCIIString(data, i); ok && len(s) >= 3 && looksLikePath(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// readUTF16LEString tries to read a null-terminated UTF-16LE string starting at pos.
// It returns true only if pos points at a printable low byte with a zero high byte
// and the run continues to a null terminator.
func readUTF16LEString(data []byte, pos int) (string, bool) {
	if pos%2 == 1 {
		pos--
	}
	if pos < 0 || pos >= len(data)-1 {
		return "", false
	}
	// Must start at a valid character position.
	if !isPrintableUTF16Byte(data[pos]) || data[pos+1] != 0 {
		return "", false
	}
	start := pos
	// Walk backwards to include earlier chars of the same string.
	for start >= 2 {
		prev := start - 2
		b0 := data[prev]
		b1 := data[prev+1]
		if b0 == 0 && b1 == 0 {
			break
		}
		if !isPrintableUTF16Byte(b0) || b1 != 0 {
			break
		}
		start = prev
	}
	// Walk forwards to the null terminator.
	end := start
	for end < len(data)-1 {
		b0 := data[end]
		b1 := data[end+1]
		if b0 == 0 && b1 == 0 {
			break
		}
		if !isPrintableUTF16Byte(b0) || b1 != 0 {
			return "", false
		}
		end += 2
	}
	if end-start < 6 { // at least 3 chars
		return "", false
	}
	var runes []rune
	for i := start; i < end; i += 2 {
		runes = append(runes, rune(data[i]))
	}
	return string(runes), true
}

func isPrintableUTF16Byte(b byte) bool {
	if b >= 0x20 && b < 0x7F {
		return true
	}
	// Allow common path punctuation.
	return b == '\\' || b == '/' || b == ':' || b == '.' || b == ' ' || b == '-' || b == '_'
}

// readASCIIString reads an ASCII string starting at pos if pos is a printable char.
func readASCIIString(data []byte, pos int) (string, bool) {
	if pos < 0 || pos >= len(data) || !isPrintableASCII(data[pos]) {
		return "", false
	}
	start := pos
	for start > 0 && isPrintableASCII(data[start-1]) {
		start--
	}
	end := pos
	for end < len(data) && isPrintableASCII(data[end]) {
		end++
	}
	if end-start < 3 {
		return "", false
	}
	return string(data[start:end]), true
}

func isPrintableASCII(b byte) bool {
	if b >= 0x20 && b < 0x7F {
		return true
	}
	return b == '\\' || b == '/' || b == ':' || b == '.' || b == ' ' || b == '-' || b == '_'
}

func looksLikePath(s string) bool {
	return strings.Contains(s, "\\") || strings.Contains(s, ":\\") || strings.HasPrefix(s, "\\\\")
}

// nearestFiletime looks for a valid-looking FILETIME (8 bytes) within 64 bytes
// before or after pos and converts it to time.Time. If none looks valid, returns zero.
func nearestFiletime(data []byte, pos int) time.Time {
	searchRadius := 64
	start := pos - searchRadius
	if start < 0 {
		start = 0
	}
	end := pos + searchRadius
	if end > len(data)-8 {
		end = len(data) - 8
	}
	for i := start; i <= end; i++ {
		low := binary.LittleEndian.Uint32(data[i:])
		high := binary.LittleEndian.Uint32(data[i+4:])
		ft := int64(uint64(low) | (uint64(high) << 32))
		if ft == 0 || uint64(ft) == ^uint64(0) {
			continue
		}
		t := windowsFiletimeToTime(ft)
		if !t.IsZero() && t.After(time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)) && t.Before(time.Now().Add(24*time.Hour)) {
			return t
		}
	}
	return time.Time{}
}

func windowsFiletimeToTime(ft int64) time.Time {
	const ticksPerSecond = 10000000
	const epochDiff = 11644473600 // seconds between 1601 and 1970
	seconds := ft/ticksPerSecond - epochDiff
	nsec := (ft % ticksPerSecond) * 100
	if seconds < 0 {
		return time.Time{}
	}
	return time.Unix(seconds, nsec)
}

func isObfuscatedName(name string) bool {
	if len(name) < 20 {
		return false
	}
	base := name
	if i := strings.LastIndex(name, "."); i > 0 {
		base = name[:i]
	}
	if len(base) < 20 {
		return false
	}
	letters, digits := 0, 0
	seen := make(map[rune]bool)
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			letters++
			seen[r] = true
		} else if r >= '0' && r <= '9' {
			digits++
			seen[r] = true
		} else {
			return false // only pure alphanumeric allowed
		}
	}
	if letters == 0 || digits == 0 {
		return false // must be mixed
	}
	return float64(len(seen))/float64(len(base)) >= 0.5
}

// ScanAppDataRoaming scans the top-level entries of %APPDATA%\Roaming for
// directories whose name looks obfuscated (length >= 20, alphanumeric, mixed
// letters+digits, decent entropy). Returns matched folders with their path and
// modification time.
func ScanAppDataRoaming() []struct {
	DirPath      string
	FilePath     string
	FileName     string
	DirModified  time.Time
	FileModified time.Time
} {
	var out []struct {
		DirPath      string
		FilePath     string
		FileName     string
		DirModified  time.Time
		FileModified time.Time
	}
	roaming := os.Getenv("APPDATA")
	if roaming == "" {
		return out
	}
	fmt.Fprintf(os.Stderr, "[APPDATA] scanning %s...\n", roaming)

	entries, err := os.ReadDir(roaming)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[APPDATA] read dir failed: %v\n", err)
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if !isObfuscatedName(e.Name()) {
			continue
		}
		path := filepath.Join(roaming, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, struct {
			DirPath      string
			FilePath     string
			FileName     string
			DirModified  time.Time
			FileModified time.Time
		}{
			DirPath:      path,
			FilePath:     path,
			FileName:     e.Name(),
			DirModified:  info.ModTime(),
			FileModified: info.ModTime(),
		})
	}

	fmt.Fprintf(os.Stderr, "[APPDATA] found %d obfuscated folders\n", len(out))
	return out
}
