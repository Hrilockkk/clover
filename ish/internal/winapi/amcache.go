//go:build windows
// +build windows

package winapi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// AmcacheHit stores a single match found inside Amcache.hve.
type AmcacheHit struct {
	Name      string
	Path      string
	LastRun   time.Time
	FileID    string
	ProgramID string
}

const amcachePath = `C:\Windows\appcompat\Programs\Amcache.hve`

// ScanAmcache searches Amcache.hve InventoryApplicationFile entries for the
// configured executable names. Returns matching hits with path and key
// last-write time.
func ScanAmcache(targetNames []string) []AmcacheHit {
	if len(targetNames) == 0 {
		return nil
	}

	amcache := resolveAmcachePath()
	if _, err := os.Stat(amcache); err != nil {
		fmt.Fprintf(os.Stderr, "[AMCACHE] Amcache.hve not found at %s: %v\n", amcache, err)
		return nil
	}

	var hKey syscall.Handle
	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	regLoadAppKey := advapi32.NewProc("RegLoadAppKeyW")
	ptr, err := windows.UTF16PtrFromString(amcache)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AMCACHE] path conversion failed: %v\n", err)
		return nil
	}

	ret, _, err := regLoadAppKey.Call(
		uintptr(unsafe.Pointer(ptr)),
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS),
		0,
		0,
	)
	if ret != 0 {
		fmt.Fprintf(os.Stderr, "[AMCACHE] RegLoadAppKey failed for %s: %v\n", amcache, err)
		return nil
	}
	defer syscall.RegCloseKey(hKey)

	root := registry.Key(hKey)
	fileKey, err := registry.OpenKey(root, `Root\InventoryApplicationFile`, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AMCACHE] open InventoryApplicationFile failed: %v\n", err)
		return nil
	}
	defer fileKey.Close()

	targets := make([]string, len(targetNames))
	for i, n := range targetNames {
		targets[i] = strings.ToLower(filepath.Base(n))
	}

	subKeys, err := fileKey.ReadSubKeyNames(-1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AMCACHE] enumerate subkeys failed: %v\n", err)
		return nil
	}

	var hits []AmcacheHit
	for _, sub := range subKeys {
		sk, err := registry.OpenKey(fileKey, sub, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		name, _, _ := sk.GetStringValue("Name")
		lowerPath, _, _ := sk.GetStringValue("LowerCaseLongPath")
		fileID, _, _ := sk.GetStringValue("FileId")
		programID, _, _ := sk.GetStringValue("ProgramId")

		if matched := matchAmcacheName(name, lowerPath, targets); matched != "" {
			info, err := sk.Stat()
			if err != nil {
				info = nil
			}
			var lastRun time.Time
			if info != nil {
				lastRun = info.ModTime()
			}

			path := lowerPath
			if path == "" {
				path = name
			}
			hits = append(hits, AmcacheHit{
				Name:      matched,
				Path:      path,
				LastRun:   lastRun,
				FileID:    fileID,
				ProgramID: programID,
			})
		}
		sk.Close()
	}

	if len(hits) > 0 {
		fmt.Fprintf(os.Stderr, "[AMCACHE] %s -> %d hits\n", amcache, len(hits))
	}
	return hits
}

func resolveAmcachePath() string {
	if sysRoot := os.Getenv("SystemRoot"); sysRoot != "" {
		return filepath.Join(sysRoot, `appcompat\Programs\Amcache.hve`)
	}
	return amcachePath
}

func matchAmcacheName(name, lowerPath string, targets []string) string {
	base := strings.ToLower(filepath.Base(name))
	if base == "" {
		base = strings.ToLower(filepath.Base(lowerPath))
	}
	for _, t := range targets {
		if base == t || strings.EqualFold(name, t) || strings.EqualFold(filepath.Base(lowerPath), t) {
			if name != "" {
				return filepath.Base(name)
			}
			return filepath.Base(lowerPath)
		}
	}
	return ""
}
