//go:build windows
// +build windows

package winapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

var shellbagRoots = []string{
	`Software\Microsoft\Windows\Shell\BagMRU`,
	`Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`,
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
