//go:build windows
// +build windows

package output

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"scanner/internal/models"
)

func SaveConsoleResults(results []models.FileInfo, dirs []models.DirInfo, named []models.NamedFileInfo, delFiles []models.DeletedFileInfo, delDirs []models.DeletedDirInfo, shellbags []models.ShellbagFinding, appData []models.AppDataFinding, amcache []models.AmcacheFinding, cs2Conns []models.CS2Connection, cs2RWX []models.CS2RWXRegion, hw *models.HardwareInfo, steam *models.SteamInfo, prefetch []models.PrefetchEntry, shimcache []models.ShimcacheEntry, bam []models.BamEntry, processes []models.ProcessEntry, drivers []models.DriverEntry, extra *models.ExtraArtifacts, elapsed time.Duration, outDir string) error {
	if outDir == "" {
		outDir = "."
	}
	timestamp := time.Now().Format("2006-01-02_150405")
	fileName := filepath.Join(outDir, fmt.Sprintf("scan_results_%s.txt", timestamp))
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "CLOVER SCAN REPORT\n")
	fmt.Fprintf(file, "=================\n")
	fmt.Fprintf(file, "Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(file, "Duration: %.2fs\n", elapsed.Seconds())
	fmt.Fprintf(file, "=================\n\n")

	if hw != nil {
		fmt.Fprintf(file, "--- Hardware Fingerprint ---\n")
		fmt.Fprintf(file, "Hostname:     %s\n", hw.Hostname)
		fmt.Fprintf(file, "Username:     %s\n", hw.Username)
		fmt.Fprintf(file, "OS:           %s\n", hw.OSVersion)
		fmt.Fprintf(file, "MachineGuid:  %s\n", hw.MachineGuid)
		fmt.Fprintf(file, "CPU:          %s\n", hw.CPUName)
		fmt.Fprintf(file, "CPU ID:       %s\n", hw.CPUID)
		fmt.Fprintf(file, "Board:        %s %s\n", hw.BoardVendor, hw.BoardProduct)
		fmt.Fprintf(file, "Board S/N:    %s\n", hw.BoardSerial)
		fmt.Fprintf(file, "GPU:          %s\n", hw.GPUName)
		fmt.Fprintf(file, "System S/N:   %s\n", hw.SystemSerial)
		for i, d := range hw.Disks {
			fmt.Fprintf(file, "Disk %d:        %s  S/N: %s  %.0fGB\n", i, d.Model, d.SerialNumber, d.SizeGB)
		}
		fmt.Fprintf(file, "HWID:         %s\n\n", hw.HWID)
	}

	if steam != nil && len(steam.Accounts) > 0 {
		fmt.Fprintf(file, "--- Steam Accounts ---\n")
		for _, a := range steam.Accounts {
			marker := ""
			if a.MostRecent {
				marker = " (most recent)"
			}
			fmt.Fprintf(file, "SteamID: %s  Account: %s%s\n", a.SteamID, a.AccountName, marker)
		}
		fmt.Fprintf(file, "\n")
	}

	all := len(results) + len(delFiles) + len(delDirs) + len(dirs) + len(named) + len(shellbags) + len(appData) + len(amcache) + len(cs2Conns) + len(cs2RWX) + len(prefetch) + len(shimcache) + len(bam) + len(processes) + len(drivers)
	fmt.Fprintf(file, "Total Items Found: %d\n\n", all)

	if len(amcache) > 0 {
		fmt.Fprintf(file, "--- Amcache ---\n")
		for _, ac := range amcache {
			fmt.Fprintf(file, "[AMCACHE] %s\n  Path: %s\n  LastRun: %s\n\n", ac.Name, ac.Path, ac.LastRun.Format("2006-01-02 15:04:05"))
		}
	}

	if len(results) > 0 {
		fmt.Fprintf(file, "--- Matches (Content) ---\n")
		for _, f := range results {
			fmt.Fprintf(file, "[MATCH] %s\n  Path: %s\n  Size: %.2f MB\n  Matched: %s\n", f.Name, f.Path, float64(f.Size)/1024/1024, f.Matched)
			fmt.Fprintln(file)
		}
	}

	if len(dirs) > 0 {
		fmt.Fprintf(file, "--- Target Directories ---\n")
		for _, d := range dirs {
			fmt.Fprintf(file, "[DIR] %s\n  Path: %s\n  Modified: %s\n\n", d.Name, d.Path, d.Modified.Format("2006-01-02 15:04:05"))
		}
	}

	if len(named) > 0 {
		fmt.Fprintf(file, "--- Target Files ---\n")
		for _, f := range named {
			fmt.Fprintf(file, "[FILE] %s\n  Path: %s\n  Size: %.2f MB\n\n", f.Name, f.Path, float64(f.Size)/1024/1024)
		}
	}

	if len(delFiles) > 0 {
		fmt.Fprintf(file, "--- Deleted Files ---\n")
		for _, f := range delFiles {
			fmt.Fprintf(file, "[DEL] %s\n  Path: %s\n  Deleted: %s\n\n", f.Name, f.Path, f.Deleted.Format("2006-01-02 15:04:05"))
		}
	}

	if len(delDirs) > 0 {
		fmt.Fprintf(file, "--- Deleted Directories ---\n")
		for _, d := range delDirs {
			fmt.Fprintf(file, "[DEL] %s\n  Path: %s\n  Deleted: %s\n\n", d.Name, d.Path, d.Deleted.Format("2006-01-02 15:04:05"))
		}
	}

	if len(shellbags) > 0 {
		fmt.Fprintf(file, "--- Shellbags (Explorer History) ---\n")
		for _, sb := range shellbags {
			fmt.Fprintf(file, "[BAG] %s\n  Path: %s\n  LastAccess: %s\n\n", sb.Name, sb.Path, sb.LastAccess.Format("2006-01-02 15:04:05"))
		}
	}

	if len(appData) > 0 {
		fmt.Fprintf(file, "--- AppData Roaming ---\n")
		for _, ad := range appData {
			fmt.Fprintf(file, "[ROAM] %s\n  Path: %s\n  FileMod: %s | DirMod: %s\n\n", ad.FileName, ad.FilePath, ad.FileModified.Format("2006-01-02 15:04:05"), ad.DirModified.Format("2006-01-02 15:04:05"))
		}
	}

	if len(cs2Conns) > 0 {
		fmt.Fprintf(file, "--- CS2 Remote Connections ---\n")
		for _, c := range cs2Conns {
			fmt.Fprintf(file, "[CS2] Remote Address = %s:%d  (%s <-> %s:%d)\n", c.RemoteAddress, c.RemotePort, c.State, c.LocalAddress, c.LocalPort)
		}
		fmt.Fprintln(file)
	}

	if len(cs2RWX) > 0 {
		fmt.Fprintf(file, "--- CS2 RWX Executable Memory ---\n")
		for _, r := range cs2RWX {
			fmt.Fprintf(file, "[CS2] RWX @ 0x%x  size=%d KB  %s  %s\n", uint64(r.BaseAddress), uint64(r.RegionSize)/1024, r.Protection, r.RegionType)
		}
		fmt.Fprintln(file)
	}

	if len(prefetch) > 0 {
		fmt.Fprintf(file, "--- Prefetch (launched programs, %d) ---\n", len(prefetch))
		for _, p := range prefetch {
			mark := ""
			if p.Matched != "" {
				mark = "  <<< MATCHED: " + p.Matched
			}
			fmt.Fprintf(file, "[PF] %s  last=%s%s\n", p.Name, p.Modified.Format("2006-01-02 15:04:05"), mark)
		}
		fmt.Fprintln(file)
	}

	if len(shimcache) > 0 {
		fmt.Fprintf(file, "--- ShimCache (%d) ---\n", len(shimcache))
		for _, s := range shimcache {
			mark := ""
			if s.Matched != "" {
				mark = "  <<< MATCHED: " + s.Matched
			}
			fmt.Fprintf(file, "[SHIM] %s  mod=%s%s\n", s.Path, s.Modified.Format("2006-01-02 15:04:05"), mark)
		}
		fmt.Fprintln(file)
	}

	if len(bam) > 0 {
		fmt.Fprintf(file, "--- BAM/DAM (%d) ---\n", len(bam))
		for _, b := range bam {
			mark := ""
			if b.Matched != "" {
				mark = "  <<< MATCHED: " + b.Matched
			}
			fmt.Fprintf(file, "[%s] %s  lastRun=%s  sid=%s%s\n", b.Source, b.Path, b.LastRun.Format("2006-01-02 15:04:05"), b.UserSID, mark)
		}
		fmt.Fprintln(file)
	}

	if len(processes) > 0 {
		fmt.Fprintf(file, "--- Processes (%d) ---\n", len(processes))
		for _, p := range processes {
			mark := ""
			if p.Matched != "" {
				mark = "  <<< MATCHED: " + p.Matched
			}
			fmt.Fprintf(file, "[PROC] pid=%d %s  %s%s\n", p.PID, p.Name, p.Path, mark)
		}
		fmt.Fprintln(file)
	}

	if len(drivers) > 0 {
		fmt.Fprintf(file, "--- Drivers (%d) ---\n", len(drivers))
		for _, d := range drivers {
			mark := ""
			if d.Flag != "" {
				mark = "  <<< FLAG: " + d.Flag
			}
			fmt.Fprintf(file, "[DRV] %s (%s)  %s  keyMod=%s%s\n", d.Name, d.Kind, d.ImagePath, d.KeyModified.Format("2006-01-02 15:04:05"), mark)
		}
		fmt.Fprintln(file)
	}

	if all == 0 {
		fmt.Fprintf(file, "No results found. System is clean.\n")
	}

	fmt.Printf("Results saved to: %s\n", fileName)
	return nil
}
