//go:build windows
// +build windows

package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mmap "github.com/edsrzf/mmap-go"
	"scanner/internal/config"
	"scanner/internal/models"
	"scanner/internal/ntfs"
	"scanner/internal/utils"
	"scanner/internal/winapi"
)

// Engine orchestrates the scanning pipeline.
type Engine struct {
	cfg *config.Cfg

	selfExePath string
	selfExeName string

	mu              sync.Mutex
	results         []models.FileInfo
	dirResults      []models.DirInfo
	namedFiles      []models.NamedFileInfo
	deletedFiles    []models.DeletedFileInfo
	deletedDirs     []models.DeletedDirInfo
	shellbags       []models.ShellbagFinding
	appDataFindings []models.AppDataFinding
	amcacheFindings []models.AmcacheFinding
	cs2Connections  []models.CS2Connection
	cs2RWXRegions   []models.CS2RWXRegion
	hardwareInfo    *models.HardwareInfo
	steamInfo       *models.SteamInfo
	prefetch        []models.PrefetchEntry
	shimcache       []models.ShimcacheEntry
	bamEntries      []models.BamEntry
	processes       []models.ProcessEntry
	drivers         []models.DriverEntry
	shellbagsAll    []models.ShellbagEntry
	services        []models.ServiceEntry
	cleanerDeleted  []models.DeletedIniFinding
	cleanup         *models.CleanupInfo
	usnHistory      []models.UsnEntry
	// resolvers holds the per-drive MFT node maps built during the index
	// phase; the USN history collector reuses them for path resolution.
	resolvers       map[string]*ntfs.PathResolver

	scannedFiles    int64
	processedFiles  int64
	totalCandidates int64
	totalQueued     int64
}

// New creates a new scanning engine.
func New(cfg *config.Cfg, selfExePath, selfExeName string) *Engine {
	return &Engine{
		cfg:         cfg,
		selfExePath: selfExePath,
		selfExeName: selfExeName,
		resolvers:   make(map[string]*ntfs.PathResolver),
	}
}

// setResolver stores the per-drive MFT path resolver for later reuse
// (USN history collection runs after the main pipeline).
func (e *Engine) setResolver(drive string, r *ntfs.PathResolver) {
	if r == nil {
		return
	}
	e.mu.Lock()
	e.resolvers[strings.ToUpper(drive)] = r
	e.mu.Unlock()
}

// AppendResults merges discovered items into the engine state.
func (e *Engine) AppendResults(files []models.FileInfo, dirs []models.DirInfo, named []models.NamedFileInfo, delFiles []models.DeletedFileInfo, delDirs []models.DeletedDirInfo) {
	e.mu.Lock()
	e.results = append(e.results, files...)
	e.dirResults = append(e.dirResults, dirs...)
	e.namedFiles = append(e.namedFiles, named...)
	e.deletedFiles = append(e.deletedFiles, delFiles...)
	e.deletedDirs = append(e.deletedDirs, delDirs...)
	e.mu.Unlock()
}

// Results returns the accumulated results (safe copy).
func (e *Engine) Results() (results []models.FileInfo, dirResults []models.DirInfo, namedFiles []models.NamedFileInfo, deletedFiles []models.DeletedFileInfo, deletedDirs []models.DeletedDirInfo, shellbags []models.ShellbagFinding, appData []models.AppDataFinding, amcache []models.AmcacheFinding, cs2Conns []models.CS2Connection, cs2RWX []models.CS2RWXRegion, hw *models.HardwareInfo, steam *models.SteamInfo, prefetch []models.PrefetchEntry, shimcache []models.ShimcacheEntry, bam []models.BamEntry, processes []models.ProcessEntry, drivers []models.DriverEntry, extra *models.ExtraArtifacts) {
	e.mu.Lock()
	defer e.mu.Unlock()
	results = make([]models.FileInfo, len(e.results))
	copy(results, e.results)
	dirResults = make([]models.DirInfo, len(e.dirResults))
	copy(dirResults, e.dirResults)
	namedFiles = make([]models.NamedFileInfo, len(e.namedFiles))
	copy(namedFiles, e.namedFiles)
	deletedFiles = make([]models.DeletedFileInfo, len(e.deletedFiles))
	copy(deletedFiles, e.deletedFiles)
	deletedDirs = make([]models.DeletedDirInfo, len(e.deletedDirs))
	copy(deletedDirs, e.deletedDirs)
	shellbags = make([]models.ShellbagFinding, len(e.shellbags))
	copy(shellbags, e.shellbags)
	appData = make([]models.AppDataFinding, len(e.appDataFindings))
	copy(appData, e.appDataFindings)
	amcache = make([]models.AmcacheFinding, len(e.amcacheFindings))
	copy(amcache, e.amcacheFindings)
	cs2Conns = make([]models.CS2Connection, len(e.cs2Connections))
	copy(cs2Conns, e.cs2Connections)
	cs2RWX = make([]models.CS2RWXRegion, len(e.cs2RWXRegions))
	copy(cs2RWX, e.cs2RWXRegions)
	// Copy the pointers' targets: callers must not observe later reassignment
	// by ScanHardware/ScanSteam running concurrently.
	if e.hardwareInfo != nil {
		hwCopy := *e.hardwareInfo
		hw = &hwCopy
	}
	if e.steamInfo != nil {
		steamCopy := *e.steamInfo
		steam = &steamCopy
	}
	prefetch = make([]models.PrefetchEntry, len(e.prefetch))
	copy(prefetch, e.prefetch)
	shimcache = make([]models.ShimcacheEntry, len(e.shimcache))
	copy(shimcache, e.shimcache)
	bam = make([]models.BamEntry, len(e.bamEntries))
	copy(bam, e.bamEntries)
	processes = make([]models.ProcessEntry, len(e.processes))
	copy(processes, e.processes)
	drivers = make([]models.DriverEntry, len(e.drivers))
	copy(drivers, e.drivers)

	extra = &models.ExtraArtifacts{}
	if len(e.shellbagsAll) > 0 {
		extra.ShellbagsAll = make([]models.ShellbagEntry, len(e.shellbagsAll))
		copy(extra.ShellbagsAll, e.shellbagsAll)
	}
	if len(e.services) > 0 {
		extra.Services = make([]models.ServiceEntry, len(e.services))
		copy(extra.Services, e.services)
	}
	if e.cleanup != nil {
		cleanupCopy := *e.cleanup
		extra.Cleanup = &cleanupCopy
	}
	if len(e.usnHistory) > 0 {
		extra.USNHistory = make([]models.UsnEntry, len(e.usnHistory))
		copy(extra.USNHistory, e.usnHistory)
	}
	return
}

// Stats returns live counters for the progress UI.
func (e *Engine) TotalCandidates() int64 { return atomic.LoadInt64(&e.totalCandidates) }
func (e *Engine) ProcessedFiles() int64  { return atomic.LoadInt64(&e.processedFiles) }
func (e *Engine) ScannedFiles() int64    { return atomic.LoadInt64(&e.scannedFiles) }
func (e *Engine) TotalQueued() int64     { return atomic.LoadInt64(&e.totalQueued) }

func (e *Engine) HitsCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.results)
}

func (e *Engine) DeletedCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.deletedFiles) + len(e.deletedDirs)
}

func (e *Engine) ShellbagCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.shellbags)
}

func (e *Engine) AppDataCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.appDataFindings)
}

func (e *Engine) AmcacheCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.amcacheFindings)
}

func (e *Engine) CS2ConnectionCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.cs2Connections)
}

func (e *Engine) CS2RWXCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.cs2RWXRegions)
}

const (
	cs2ANSIRed     = "\x1b[31m"
	cs2ANSIBoldRed = "\x1b[1;31m"
	cs2ANSIReset   = "\x1b[0m"
)

// ScanCS2 inspects the running cs2.exe process: enumerates its TCP remote
// endpoints and any RWX (executable+writeable) memory regions. Findings are
// printed in red immediately and stored in engine state for later output.
func (e *Engine) ScanCS2() {
	pid := winapi.FindCS2PID()
	if pid == 0 {
		fmt.Fprintf(os.Stderr, "%s[CS2] cs2.exe is not running%s\n", cs2ANSIRed, cs2ANSIReset)
		return
	}
	fmt.Fprintf(os.Stderr, "%s[CS2] cs2.exe found (PID=%d)%s\n", cs2ANSIBoldRed, pid, cs2ANSIReset)

	conns := winapi.GetCS2Connections(pid)
	for _, c := range conns {
		fmt.Fprintf(os.Stderr, "%s[CS2] Remote Address = %s:%d  (%s <-> %s:%d)%s\n",
			cs2ANSIBoldRed,
			c.RemoteAddress, c.RemotePort,
			c.State, c.LocalAddress, c.LocalPort,
			cs2ANSIReset)
	}
	if len(conns) == 0 {
		fmt.Fprintf(os.Stderr, "%s[CS2] No remote connections%s\n", cs2ANSIRed, cs2ANSIReset)
	}

	regions, err := winapi.GetCS2RWXRegions(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[CS2] RWX scan failed: %v%s\n", cs2ANSIBoldRed, err, cs2ANSIReset)
	} else {
		for _, r := range regions {
			fmt.Fprintf(os.Stderr, "%s[CS2] RWX @ 0x%x  size=%d KB  %s  %s%s\n",
				cs2ANSIBoldRed,
				uint64(r.BaseAddress), uint64(r.RegionSize)/1024,
				r.Protection, r.RegionType,
				cs2ANSIReset)
		}
		if len(regions) == 0 {
			fmt.Fprintf(os.Stderr, "%s[CS2] No RWX executable regions detected%s\n", cs2ANSIRed, cs2ANSIReset)
		}
	}

	e.mu.Lock()
	e.cs2Connections = append(e.cs2Connections, conns...)
	e.cs2RWXRegions = append(e.cs2RWXRegions, regions...)
	e.mu.Unlock()

	fmt.Fprintf(os.Stderr, "%s[CS2] Summary: %d remote connections, %d RWX regions%s\n",
		cs2ANSIBoldRed, len(conns), len(regions), cs2ANSIReset)
}

// ScanHardware collects all hardware identifiers (CPU, board, GPU, RAM, disks,
// MachineGuid, hostname, OS) and computes a composite HWID.
func (e *Engine) ScanHardware() {
	hw, err := winapi.CollectHardware()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[HWID] collection error: %v\n", err)
		return
	}
	e.mu.Lock()
	e.hardwareInfo = hw
	e.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[HWID] Hostname:  %s\n", hw.Hostname)
	fmt.Fprintf(os.Stderr, "[HWID] Username:  %s\n", hw.Username)
	fmt.Fprintf(os.Stderr, "[HWID] OS:        %s\n", hw.OSVersion)
	fmt.Fprintf(os.Stderr, "[HWID] MachineGuid: %s\n", hw.MachineGuid)
	fmt.Fprintf(os.Stderr, "[HWID] CPU:       %s (ID: %s)\n", hw.CPUName, hw.CPUID)
	fmt.Fprintf(os.Stderr, "[HWID] Board:     %s %s (S/N: %s)\n", hw.BoardVendor, hw.BoardProduct, hw.BoardSerial)
	fmt.Fprintf(os.Stderr, "[HWID] GPU:       %s\n", hw.GPUName)
	fmt.Fprintf(os.Stderr, "[HWID] System S/N: %s\n", hw.SystemSerial)
	for i, d := range hw.Disks {
		fmt.Fprintf(os.Stderr, "[HWID] Disk %d:    %s  S/N: %s  %.0fGB\n", i, d.Model, d.SerialNumber, d.SizeGB)
	}
	fmt.Fprintf(os.Stderr, "%s[HWID] HWID:      %s%s\n", cs2ANSIBoldRed, hw.HWID, cs2ANSIReset)
}

// ScanSteam reads the registry and VDF files to extract all Steam accounts
// and library paths.
func (e *Engine) ScanSteam() {
	steam, err := winapi.CollectSteam()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[STEAM] error: %v\n", err)
		return
	}
	e.mu.Lock()
	e.steamInfo = steam
	e.mu.Unlock()

	fmt.Fprintf(os.Stderr, "[STEAM] Path: %s\n", steam.SteamPath)
	for _, a := range steam.Accounts {
		marker := ""
		if a.MostRecent {
			marker = " (most recent)"
		}
		fmt.Fprintf(os.Stderr, "%s[STEAM] %s  %s%s%s\n", cs2ANSIBoldRed, a.SteamID, a.AccountName, marker, cs2ANSIReset)
	}
	for _, p := range steam.LibraryPaths {
		fmt.Fprintf(os.Stderr, "[STEAM] Library: %s\n", p)
	}
}

// ScanAmcache searches Amcache.hve for configured executable names.
func (e *Engine) ScanAmcache() {
	hits := winapi.ScanAmcache(e.cfg.AmcacheExeNames)
	if len(hits) == 0 {
		return
	}
	var findings []models.AmcacheFinding
	for _, h := range hits {
		findings = append(findings, models.AmcacheFinding{
			Name:      h.Name,
			Path:      h.Path,
			LastRun:   h.LastRun,
			FileID:    h.FileID,
			ProgramID: h.ProgramID,
		})
	}
	e.mu.Lock()
	e.amcacheFindings = append(e.amcacheFindings, findings...)
	e.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[AMCACHE] Found %d Amcache hits\n", len(findings))
}

// ScanShellbags scans Explorer shellbags for target directory names and
// additionally stores the full analyzer-style BagMRU listing (all slots,
// existing + deleted) for the «Shellbags» tab of the scan page.
func (e *Engine) ScanShellbags() {
	// Full listing first (independent of hits).
	full := winapi.ScanShellbagsFull(e.cfg.TargetDirNames)
	if len(full) > 0 {
		e.mu.Lock()
		e.shellbagsAll = append(e.shellbagsAll, full...)
		e.mu.Unlock()
		fmt.Fprintf(os.Stderr, "[SHELLBAGS] full listing: %d entries\n", len(full))
	}

	hits := winapi.ScanShellbags(e.cfg.TargetDirNames)
	if len(hits) == 0 {
		return
	}
	var findings []models.ShellbagFinding
	for _, h := range hits {
		findings = append(findings, models.ShellbagFinding{
			Path:       h.Path,
			Name:       h.TargetName,
			LastAccess: h.LastAccess,
		})
	}
	e.mu.Lock()
	e.shellbags = append(e.shellbags, findings...)
	e.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[SHELLBAGS] Found %d shellbag hits\n", len(findings))
}

// ScanServices records the state of forensic-critical services (Services.ps1
// watch list): stopped EventLog/PcaSvc/etc. is a classic anti-artifact move.
func (e *Engine) ScanServices() {
	entries := winapi.CollectServices()
	if len(entries) == 0 {
		return
	}
	stopped := 0
	for _, s := range entries {
		if s.Exists && s.Status != "running" {
			stopped++
		}
	}
	e.mu.Lock()
	e.services = append(e.services, entries...)
	e.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[SERVICES] %d checked, %d not running\n", len(entries), stopped)
}

// ScanCleanup aggregates anti-cleanup evidence for the «Очистка» tab:
// cleaner artefact ini files on disk (shellbag_analyzer_cleaner.ini,
// PrivaZer.ini), their deletion records found in the USN journal during the
// index phase, Prefetch traces of artifact-wiping tools (fsutil/wevtutil)
// and per-drive $UsnJrnl wipe status.
func (e *Engine) ScanCleanup(drives []string) {
	info := &models.CleanupInfo{
		IniOnDisk:     winapi.SearchCleanerINI(),
		PrefetchTools: winapi.CollectCleanupToolPrefetch(),
		Journals:      ntfs.CollectUSNJournalStatus(drives),
	}
	e.mu.Lock()
	info.IniDeleted = append(info.IniDeleted, e.cleanerDeleted...)
	e.cleanup = info
	e.mu.Unlock()

	wiped := 0
	for _, j := range info.Journals {
		if j.Wiped {
			wiped++
		}
	}
	fmt.Fprintf(os.Stderr, "[CLEANUP] ini on disk: %d, ini deleted (USN): %d, prefetch tools: %d, wiped journals: %d/%d\n",
		len(info.IniOnDisk), len(info.IniDeleted), len(info.PrefetchTools), wiped, len(info.Journals))
}

// ScanUSNHistory collects the newest $UsnJrnl records of every drive into a
// JournalTrace-style searchable listing for the «USN» tab. Records matching
// the signature name lists (target dirs/files, amcache names) are flagged.
// The global list is capped at cfg.USNHistoryMax, newest first.
func (e *Engine) ScanUSNHistory(drives []string) {
	maxKeep := e.cfg.USNHistoryMax
	if maxKeep <= 0 {
		maxKeep = 20000
	}
	targetNames := e.collectorTargetNames()
	var all []models.UsnEntry
	for _, drive := range drives {
		drive = strings.ToUpper(drive)
		e.mu.Lock()
		resolver := e.resolvers[drive]
		e.mu.Unlock()
		if resolver == nil {
			fmt.Fprintf(os.Stderr, "[USN] %s history skipped: no MFT resolver (index phase failed)\n", drive)
		}
		entries := ntfs.ScanUSNHistory(drive, resolver, targetNames, maxKeep)
		if len(entries) > 0 {
			all = append(all, entries...)
		}
	}
	if len(all) == 0 {
		return
	}
	// Newest first, global cap across drives.
	sort.Slice(all, func(i, j int) bool { return all[i].TimeMs > all[j].TimeMs })
	if len(all) > maxKeep {
		all = all[:maxKeep]
	}
	matched := 0
	for _, u := range all {
		if u.Matched != "" {
			matched++
		}
	}
	e.mu.Lock()
	e.usnHistory = all
	e.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[USN] history kept: %d records, %d matched\n", len(all), matched)
}

// ScanAppDataRoaming scans %APPDATA%\Roaming for files whose name looks
// obfuscated (long, alphanumeric, mixed letters+digits, high entropy).
func (e *Engine) ScanAppDataRoaming() {
	hits := winapi.ScanAppDataRoaming()
	if len(hits) == 0 {
		return
	}
	var findings []models.AppDataFinding
	for _, h := range hits {
		findings = append(findings, models.AppDataFinding{
			DirPath:      h.DirPath,
			FilePath:     h.FilePath,
			FileName:     h.FileName,
			DirModified:  h.DirModified,
			FileModified: h.FileModified,
		})
	}
	e.mu.Lock()
	e.appDataFindings = append(e.appDataFindings, findings...)
	e.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[APPDATA] Found %d AppData hits\n", len(findings))
}

// collectorTargetNames returns the union of configured name lists used to
// flag matches inside Prefetch/ShimCache/BAM/Processes.
func (e *Engine) collectorTargetNames() []string {
	out := make([]string, 0, len(e.cfg.TargetDirNames)+len(e.cfg.TargetFileNames)+len(e.cfg.AmcacheExeNames))
	out = append(out, e.cfg.TargetDirNames...)
	out = append(out, e.cfg.TargetFileNames...)
	out = append(out, e.cfg.AmcacheExeNames...)
	return out
}

// ScanPrefetch collects Prefetch launch traces.
func (e *Engine) ScanPrefetch() {
	entries := winapi.CollectPrefetch(e.collectorTargetNames())
	if len(entries) == 0 {
		return
	}
	matched := 0
	for _, p := range entries {
		if p.Matched != "" {
			matched++
		}
	}
	e.mu.Lock()
	e.prefetch = append(e.prefetch, entries...)
	e.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[PREFETCH] %d entries, %d matched\n", len(entries), matched)
}

// ScanShimcache collects AppCompatCache entries.
func (e *Engine) ScanShimcache() {
	entries := winapi.CollectShimcache(e.collectorTargetNames())
	if len(entries) == 0 {
		return
	}
	matched := 0
	for _, s := range entries {
		if s.Matched != "" {
			matched++
		}
	}
	e.mu.Lock()
	e.shimcache = append(e.shimcache, entries...)
	e.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[SHIMCACHE] %d entries, %d matched\n", len(entries), matched)
}

// ScanBamDam collects BAM/DAM per-user launch records.
func (e *Engine) ScanBamDam() {
	entries := winapi.CollectBamDam(e.collectorTargetNames())
	if len(entries) == 0 {
		return
	}
	matched := 0
	for _, b := range entries {
		if b.Matched != "" {
			matched++
		}
	}
	e.mu.Lock()
	e.bamEntries = append(e.bamEntries, entries...)
	e.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[BAM] %d entries, %d matched\n", len(entries), matched)
}

// ScanProcesses snapshots running processes.
func (e *Engine) ScanProcesses() {
	entries := winapi.CollectProcesses(e.collectorTargetNames())
	if len(entries) == 0 {
		return
	}
	matched := 0
	for _, p := range entries {
		if p.Matched != "" {
			matched++
		}
	}
	e.mu.Lock()
	e.processes = append(e.processes, entries...)
	e.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[PROCESSES] %d running, %d matched\n", len(entries), matched)
}

// ScanDrivers enumerates installed kernel/fs drivers with blacklist/recent flags.
func (e *Engine) ScanDrivers() {
	entries := winapi.CollectDrivers(e.cfg.DriverBlacklist)
	if len(entries) == 0 {
		return
	}
	flagged := 0
	for _, d := range entries {
		if d.Flag != "" {
			flagged++
		}
	}
	e.mu.Lock()
	e.drivers = append(e.drivers, entries...)
	e.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[DRIVERS] %d drivers, %d flagged\n", len(entries), flagged)
}

// ScanTargetDirs walks the filesystem looking for directories matching target names.
func (e *Engine) ScanTargetDirs(root string) []models.DirInfo {
	found := make([]models.DirInfo, 0, 64)
	seen := make(map[string]bool, 256)
	stack := []string{root}

	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			// Skip junctions/symlinks: they can form cycles.
			if winapi.IsReparsePoint(entry) {
				continue
			}

			name := entry.Name()
			path := filepath.Join(dir, name)

			stack = append(stack, path)

			if !isTargetDirName(name, e.cfg.TargetDirNames) {
				continue
			}

			key := strings.ToLower(path)
			if seen[key] {
				continue
			}
			seen[key] = true

			info, err := os.Stat(path)
			if err != nil {
				continue
			}

			found = append(found, models.DirInfo{
				Path:       path,
				Name:       name,
				Attributes: winapi.WinAttrsToString(path),
				Modified:   info.ModTime(),
			})
		}
	}

	return found
}

// ScanTargetFiles walks the filesystem looking for files with exact target names.
func (e *Engine) ScanTargetFiles(root string) []models.NamedFileInfo {
	found := make([]models.NamedFileInfo, 0, 64)
	seen := make(map[string]bool, 256)
	stack := []string{root}

	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			name := entry.Name()
			path := filepath.Join(dir, name)

			if entry.IsDir() {
				// Skip junctions/symlinks: they can form cycles.
				if winapi.IsReparsePoint(entry) {
					continue
				}
				stack = append(stack, path)
				continue
			}

			if !isTargetFileName(name, e.cfg.TargetFileNames) {
				continue
			}

			key := strings.ToLower(path)
			if seen[key] {
				continue
			}
			seen[key] = true

			info, err := os.Stat(path)
			if err != nil {
				continue
			}

			found = append(found, models.NamedFileInfo{
				Path:       path,
				Name:       name,
				Size:       info.Size(),
				Attributes: winapi.WinAttrsToString(path),
				Modified:   info.ModTime(),
			})
		}
	}

	return found
}

func isTargetDirName(name string, targetDirNames []string) bool {
	for _, n := range targetDirNames {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return false
}

func isTargetFileName(name string, targetFileNames []string) bool {
	for _, n := range targetFileNames {
		if strings.EqualFold(name, n) {
			return true
		}
	}
	return false
}

// ScanTargetsMFT finds target directories and files using the in-memory MFT
// node map (the Everything approach) instead of a filesystem walk. Only the
// handful of matched entries are stat'd, eliminating full-tree os.ReadDir
// scans per drive. A single pass over nodes covers both dirs and files.
func (e *Engine) ScanTargetsMFT(resolver *ntfs.PathResolver) (dirs []models.DirInfo, files []models.NamedFileInfo) {
	dirSet := make(map[string]struct{}, len(e.cfg.TargetDirNames))
	for _, n := range e.cfg.TargetDirNames {
		dirSet[strings.ToLower(n)] = struct{}{}
	}
	fileSet := make(map[string]struct{}, len(e.cfg.TargetFileNames))
	for _, n := range e.cfg.TargetFileNames {
		fileSet[strings.ToLower(n)] = struct{}{}
	}

	dirs = make([]models.DirInfo, 0, 32)
	files = make([]models.NamedFileInfo, 0, 32)
	seenDir := make(map[string]bool, 32)
	seenFile := make(map[string]bool, 32)

	for frn, node := range resolver.Nodes() {
		if node.Name == "" {
			continue
		}
		lower := strings.ToLower(node.Name)
		if node.IsDir {
			if _, ok := dirSet[lower]; !ok {
				continue
			}
			path := resolver.Resolve(frn)
			key := strings.ToLower(path)
			if seenDir[key] {
				continue
			}
			seenDir[key] = true
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			dirs = append(dirs, models.DirInfo{
				Path:       path,
				Name:       node.Name,
				Attributes: winapi.WinAttrsToString(path),
				Modified:   info.ModTime(),
			})
		} else {
			if _, ok := fileSet[lower]; !ok {
				continue
			}
			path := resolver.Resolve(frn)
			key := strings.ToLower(path)
			if seenFile[key] {
				continue
			}
			seenFile[key] = true
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			files = append(files, models.NamedFileInfo{
				Path:       path,
				Name:       node.Name,
				Size:       info.Size(),
				Attributes: winapi.WinAttrsToString(path),
				Modified:   info.ModTime(),
			})
		}
	}
	return dirs, files
}

// EnqueueCandidate validates a path and sends it downstream if it matches a rule.
func (e *Engine) EnqueueCandidate(ctx context.Context, path string, pathChan chan<- models.FileCandidate) {
	atomic.AddInt64(&e.scannedFiles, 1)

	name := filepath.Base(path)
	if !strings.HasSuffix(strings.ToLower(name), ".exe") || strings.HasSuffix(name, "~") {
		return
	}
	if e.selfExePath != "" && (strings.EqualFold(path, e.selfExePath) || strings.EqualFold(name, e.selfExeName)) {
		return
	}

	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return
	}

	size := info.Size()
	fits := false
	for _, r := range e.cfg.Rules {
		if size >= r.Min && size <= r.Max {
			fits = true
			break
		}
	}
	if !fits {
		return
	}

	displayPath := path
	displayName := name
	if iPath, ok := utils.ReadRecycleInfoFromRPath(path); ok {
		if rinfo, err := ntfs.ParseRecycleIFile(iPath); err == nil && rinfo.OriginalPath != "" {
			displayPath = rinfo.OriginalPath
			displayName = filepath.Base(rinfo.OriginalPath)
		}
	}

	select {
	case pathChan <- models.FileCandidate{
		Path: displayPath,
		Name: displayName,
		Size: size,
		Mod:  info.ModTime(),
	}:
		atomic.AddInt64(&e.totalQueued, 1)
	case <-ctx.Done():
	}
}

// Walker discovers candidates and feeds them to pathChan.
func (e *Engine) Walker(ctx context.Context, drives []string, pathChan chan<- models.FileCandidate) {
	defer close(pathChan)

	type driveResult struct {
		drive string
		paths []string
	}

	byDrive := make(map[string][]string, len(drives))
	var idxMu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.cfg.IndexWorkers)

	fmt.Fprintf(os.Stderr, "\n=== Starting index phase for %d drives ===\n", len(drives))

	for _, drive := range drives {
		wg.Add(1)
		go func(d string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			drive := strings.ToUpper(d)
			root := drive + "\\"
			select {
			case <-ctx.Done():
				return
			default:
			}

			var paths []string
			var resolver *ntfs.PathResolver
			var deletedFiles []models.FileInfo
			var dirs []models.DirInfo
			var files []models.NamedFileInfo

			// Primary: single-pass raw MFT scan (Everything approach — one
			// sequential I/O sweep extracts live exe, deleted exe, targets,
			// and the FRN→node map simultaneously).
			fmt.Fprintf(os.Stderr, "[INDEX] %s: Starting raw MFT scan...\n", drive)
			mftOpts := &ntfs.ScanOptions{
				MaxRecords:            e.cfg.MaxMFTRecords,
				BatchSize:             e.cfg.MFTBatchSize,
				MaxDeletedContentSize: e.cfg.MaxDeletedContentSize,
				MaxDeletedSearchSize:  e.cfg.MaxDeletedSearchSize,
			}
			result, rerr := ntfs.ScanRawMFT(drive, e.cfg.Rules, e.cfg.TargetDirNames, e.cfg.TargetFileNames, mftOpts)
			if rerr == nil {
				resolver = result.Resolver
				paths = result.ExePaths
				deletedFiles = result.DeletedFiles
				dirs = result.TargetDirs
				files = result.TargetFiles
				fmt.Fprintf(os.Stderr, "[INDEX] %s: MFT scan found %d .exe, %d deleted, %d dirs, %d targets\n",
					drive, len(paths), len(deletedFiles), len(dirs), len(files))
			} else {
				// Fallback 1: USN enum (FSCTL_ENUM_USN_DATA)
				fmt.Fprintf(os.Stderr, "[INDEX] %s: Raw MFT failed (%v), trying USN enum...\n", drive, rerr)
				var ferr error
				paths, _, resolver, ferr = ntfs.IndexDriveFilesMFT(drive)
				if ferr != nil {
					// Fallback 2: filesystem walk
					fmt.Fprintf(os.Stderr, "[INDEX] %s: USN enum failed (%v), falling back to filesystem walk...\n", drive, ferr)
					paths = ntfs.IndexDriveFiles(root)
					resolver = nil
					dirs = e.ScanTargetDirs(root)
					files = e.ScanTargetFiles(root)
				} else {
					fmt.Fprintf(os.Stderr, "[INDEX] %s: USN enum found %d .exe files\n", drive, len(paths))
					dirs, files = e.ScanTargetsMFT(resolver)
					deletedFiles, _ = ntfs.ScanDeletedViaRawMFT(drive, resolver, e.cfg.Rules, mftOpts)
				}
			}
			e.setResolver(drive, resolver)

			if len(dirs) > 0 {
				e.AppendResults(nil, dirs, nil, nil, nil)
				fmt.Fprintf(os.Stderr, "[INDEX] %s: Found %d target directories\n", drive, len(dirs))
			}
			if len(files) > 0 {
				e.AppendResults(nil, nil, files, nil, nil)
				fmt.Fprintf(os.Stderr, "[INDEX] %s: Found %d target files\n", drive, len(files))
			}

			// USN journal for very recent deletions (complements raw MFT scan).
			// Convert deleted FileInfo results into DeletedFileInfo so they land in the
			// Deleted tab, not the Cheats tab.
			var usnDirs []models.DeletedDirInfo
			if resolver != nil {
				var usnFiles []models.FileInfo
				var cleanerIni []models.DeletedIniFinding
				usnFiles, usnDirs, cleanerIni, _ = ntfs.ScanDeletedViaUSN(drive, resolver, e.cfg.Rules, e.cfg.TargetDirNames, e.cfg.USNWindowHours)
				deletedFiles = append(deletedFiles, usnFiles...)
				if len(cleanerIni) > 0 {
					e.mu.Lock()
					e.cleanerDeleted = append(e.cleanerDeleted, cleanerIni...)
					e.mu.Unlock()
				}
			}
			if len(deletedFiles) > 0 {
				var keptMatches []models.FileInfo
				var delInfos []models.DeletedFileInfo
				for _, f := range deletedFiles {
					if f.Deleted.IsZero() {
						continue
					}
					// Pure deletion records (USN_DELETED, PF_DELETED or no match)
					// belong in the Deleted tab. Real rule matches stay in Cheats.
					m := strings.ToUpper(f.Matched)
					if m == "" || strings.HasPrefix(m, "USN_DELETED") || strings.HasPrefix(m, "PF_DELETED") {
						delInfos = append(delInfos, models.DeletedFileInfo{
							Path:    f.Path,
							Name:    f.Name,
							Size:    f.Size,
							Deleted: f.Deleted,
						})
					} else {
						keptMatches = append(keptMatches, f)
					}
				}
				if len(keptMatches) > 0 {
					e.AppendResults(keptMatches, nil, nil, nil, nil)
				}
				if len(delInfos) > 0 {
					e.AppendResults(nil, nil, nil, delInfos, nil)
					fmt.Fprintf(os.Stderr, "[INDEX] %s: Added %d deleted files to results\n", drive, len(delInfos))
				}
			}
			if len(usnDirs) > 0 {
				e.AppendResults(nil, nil, nil, nil, usnDirs)
			}

			idxMu.Lock()
			byDrive[drive] = paths
			idxMu.Unlock()
		}(drive)
	}
	wg.Wait()

	var cand int64
	for _, drive := range drives {
		drive = strings.ToUpper(drive)
		cand += int64(len(byDrive[drive]))
	}
	atomic.StoreInt64(&e.totalCandidates, cand)
	fmt.Fprintf(os.Stderr, "\n=== Index complete: %d total .exe candidates ===\n", cand)

	for _, drive := range drives {
		drive = strings.ToUpper(drive)
		fmt.Fprintf(os.Stderr, "[SCAN] %s: Enqueuing %d candidates...\n", drive, len(byDrive[drive]))
		for i, path := range byDrive[drive] {
			select {
			case <-ctx.Done():
				return
			default:
			}
			e.EnqueueCandidate(ctx, path, pathChan)
			if e.cfg.EnqueueBatchSize > 0 && e.cfg.EnqueuePauseMs > 0 && (i+1)%e.cfg.EnqueueBatchSize == 0 {
				time.Sleep(time.Duration(e.cfg.EnqueuePauseMs) * time.Millisecond)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "[SCAN] All candidates enqueued\n")
}

// Reader maps files into memory and forwards them to the matcher.
func (e *Engine) Reader(ctx context.Context, pathChan <-chan models.FileCandidate, mappedChan chan<- models.MappedFile) {
	var wg sync.WaitGroup
	workerCount := e.cfg.ReaderWorkers
	if workerCount < 1 {
		workerCount = runtime.NumCPU()
	}
	if workerCount < 1 {
		workerCount = 1
	}
	wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for candidate := range pathChan {
				select {
				case <-ctx.Done():
					return
				default:
				}
				f, err := os.Open(candidate.Path)
				if err != nil {
					atomic.AddInt64(&e.processedFiles, 1)
					if e.cfg.ReaderPauseMs > 0 {
						time.Sleep(time.Duration(e.cfg.ReaderPauseMs) * time.Millisecond)
					}
					continue
				}
				var data mmap.MMap
				if e.cfg.MaxMmapSize > 0 && candidate.Size > e.cfg.MaxMmapSize {
					data, err = mmap.MapRegion(f, int(e.cfg.MaxMmapSize), mmap.RDONLY, 0, 0)
				} else {
					data, err = mmap.Map(f, mmap.RDONLY, 0)
				}
				if err != nil {
					f.Close()
					atomic.AddInt64(&e.processedFiles, 1)
					if e.cfg.ReaderPauseMs > 0 {
						time.Sleep(time.Duration(e.cfg.ReaderPauseMs) * time.Millisecond)
					}
					continue
				}

				mf := models.MappedFile{
					Candidate: candidate,
					Data:      data,
					Close: func() {
						data.Unmap()
						f.Close()
					},
				}
				select {
				case <-ctx.Done():
					mf.Close()
					return
				case mappedChan <- mf:
				}
				if e.cfg.ReaderPauseMs > 0 {
					time.Sleep(time.Duration(e.cfg.ReaderPauseMs) * time.Millisecond)
				}
			}
		}()
	}
	wg.Wait()
	close(mappedChan)
}

// Matcher scans mapped file contents against compiled rules.
func (e *Engine) Matcher(ctx context.Context, mappedChan <-chan models.MappedFile) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "matcher panic recovered: %v\n", r)
		}
	}()
	for mapped := range mappedChan {
		select {
		case <-ctx.Done():
			return
		default:
		}
		matched := ""
		pathLower := strings.ToLower(mapped.Candidate.Path)

		// 1. Path-based check first
		for _, r := range e.cfg.Rules {
			if r.CheckPath && strings.Contains(pathLower, r.PatternLower) {
				matched = r.Pattern
				break
			}
		}

		// 2. Content-based check
		if matched == "" {
			data := mapped.Data
			var dataSHA256 string
			needSHA256 := false
			size := mapped.Candidate.Size
			for _, r := range e.cfg.Rules {
				if !r.CheckPath && r.SHA256 != "" && size >= r.Min && size <= r.Max {
					needSHA256 = true
					break
				}
			}
			if needSHA256 {
				if int64(len(data)) < size {
					// File was mapped truncated (larger than MaxMmapSize): hash
					// the whole file from disk, otherwise the digest is wrong.
					dataSHA256 = streamSHA256(mapped.Candidate.Path)
				} else {
					sum := sha256.Sum256(data)
					dataSHA256 = hex.EncodeToString(sum[:])
				}
			}
			for _, r := range e.cfg.Rules {
				if r.CheckPath {
					continue
				}
				if size < r.Min || size > r.Max {
					continue
				}
				if r.SHA256 != "" {
					if dataSHA256 != "" && strings.EqualFold(dataSHA256, r.SHA256) {
						matched = "sha256:" + r.SHA256
						break
					}
					if len(r.PatternBytes) == 0 {
						// Hash-only rule that did not match: move on, otherwise
						// bytes.Contains(data, nil) would swallow all remaining
						// rules for this file.
						continue
					}
				}
				if len(r.PatternBytes) > 0 && bytes.Contains(data, r.PatternBytes) {
					matched = r.Pattern
					break
				}
				if r.UTF16 {
					if bytes.Contains(data, r.UTF16LE) || bytes.Contains(data, r.UTF16BE) {
						matched = r.Pattern
						break
					}
				}
			}
		}

		if matched != "" {
			e.mu.Lock()
			e.results = append(e.results, models.FileInfo{
				Path:       mapped.Candidate.Path,
				Name:       mapped.Candidate.Name,
				Size:       mapped.Candidate.Size,
				Attributes: winapi.WinAttrsToString(mapped.Candidate.Path),
				Matched:    matched,
				Modified:   mapped.Candidate.Mod,
			})
			fmt.Fprintf(os.Stderr, "\n[FOUND] %s -> %s\n", mapped.Candidate.Name, matched)
			e.mu.Unlock()
		}

		mapped.Close()
		atomic.AddInt64(&e.processedFiles, 1)
	}
}

// streamSHA256 hashes a file by streaming it from disk in fixed-size chunks.
// Used when the mmap'd view was truncated (file larger than MaxMmapSize),
// where hashing the mapped prefix would produce an invalid digest.
func streamSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
