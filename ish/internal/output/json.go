package output

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"scanner/internal/models"
)

type jsonResult struct {
	Type         string `json:"type"`
	Name         string `json:"name"`
	Path         string `json:"path"`
	Size         int64  `json:"size,omitempty"`
	SizeMB       string `json:"sizeMB,omitempty"`
	Matched      string `json:"matched,omitempty"`
	Attributes   string `json:"attributes,omitempty"`
	Modified     string `json:"modified,omitempty"`
	Deleted      string `json:"deleted,omitempty"`
	DirModified  string `json:"dirModified,omitempty"`
	FileModified string `json:"fileModified,omitempty"`
	Details      string `json:"details,omitempty"`
	LastAccess   string `json:"lastAccess,omitempty"`
}

type jsonOutput struct {
	Total       int                  `json:"total"`
	TimeSeconds float64              `json:"timeSeconds"`
	Hardware    *models.HardwareInfo `json:"hardware,omitempty"`
	Steam       *models.SteamInfo    `json:"steam,omitempty"`
	Items       []jsonResult         `json:"items"`
}

func buildJSONOutput(results []models.FileInfo, dirs []models.DirInfo, named []models.NamedFileInfo, delFiles []models.DeletedFileInfo, delDirs []models.DeletedDirInfo, shellbags []models.ShellbagFinding, appData []models.AppDataFinding, amcache []models.AmcacheFinding, cs2Conns []models.CS2Connection, cs2RWX []models.CS2RWXRegion, hw *models.HardwareInfo, steam *models.SteamInfo, prefetch []models.PrefetchEntry, shimcache []models.ShimcacheEntry, bam []models.BamEntry, processes []models.ProcessEntry, drivers []models.DriverEntry, elapsed time.Duration) jsonOutput {
	var out jsonOutput
	out.TimeSeconds = elapsed.Seconds()
	out.Hardware = hw
	out.Steam = steam

	for _, ac := range amcache {
		out.Items = append(out.Items, jsonResult{
			Type:     "amcache",
			Name:     ac.Name,
			Path:     ac.Path,
			Modified: ac.LastRun.Format("2006-01-02 15:04:05"),
		})
	}

	for _, d := range delDirs {
		out.Items = append(out.Items, jsonResult{
			Type:    "deleted_dir",
			Name:    d.Name,
			Path:    d.Path,
			Deleted: d.Deleted.Format("2006-01-02 15:04:05"),
		})
	}
	for _, f := range delFiles {
		out.Items = append(out.Items, jsonResult{
			Type:    "deleted_file",
			Name:    f.Name,
			Path:    f.Path,
			Size:    f.Size,
			SizeMB:  fmt.Sprintf("%.2f", float64(f.Size)/1024/1024),
			Deleted: f.Deleted.Format("2006-01-02 15:04:05"),
		})
	}
	for _, d := range dirs {
		out.Items = append(out.Items, jsonResult{
			Type:       "target_dir",
			Name:       d.Name,
			Path:       d.Path,
			Attributes: d.Attributes,
			Modified:   d.Modified.Format("2006-01-02 15:04:05"),
		})
	}
	for _, f := range named {
		out.Items = append(out.Items, jsonResult{
			Type:       "target_file",
			Name:       f.Name,
			Path:       f.Path,
			Size:       f.Size,
			SizeMB:     fmt.Sprintf("%.2f", float64(f.Size)/1024/1024),
			Attributes: f.Attributes,
			Modified:   f.Modified.Format("2006-01-02 15:04:05"),
		})
	}
	for _, sb := range shellbags {
		out.Items = append(out.Items, jsonResult{
			Type:       "shellbag",
			Name:       sb.Name,
			Path:       sb.Path,
			LastAccess: sb.LastAccess.Format("2006-01-02 15:04:05"),
		})
	}
	for _, ad := range appData {
		out.Items = append(out.Items, jsonResult{
			Type:         "appdata",
			Name:         ad.FileName,
			Path:         ad.FilePath,
			DirModified:  ad.DirModified.Format("2006-01-02 15:04:05"),
			FileModified: ad.FileModified.Format("2006-01-02 15:04:05"),
		})
	}
	for _, f := range results {
		jr := jsonResult{
			Type:       "match",
			Name:       f.Name,
			Path:       f.Path,
			Size:       f.Size,
			SizeMB:     fmt.Sprintf("%.2f", float64(f.Size)/1024/1024),
			Matched:    f.Matched,
			Attributes: f.Attributes,
			Modified:   f.Modified.Format("2006-01-02 15:04:05"),
		}
		if !f.Deleted.IsZero() {
			jr.Type = "deleted_match"
			jr.Deleted = f.Deleted.Format("2006-01-02 15:04:05")
		}
		out.Items = append(out.Items, jr)
	}
	for _, c := range cs2Conns {
		out.Items = append(out.Items, jsonResult{
			Type:    "cs2_connection",
			Name:    "Remote",
			Path:    fmt.Sprintf("cs2.exe -> %s:%d", c.RemoteAddress, c.RemotePort),
			Details: fmt.Sprintf("%s:%d (%s)", c.RemoteAddress, c.RemotePort, c.State),
		})
	}
	for _, r := range cs2RWX {
		out.Items = append(out.Items, jsonResult{
			Type:    "cs2_rwx_region",
			Name:    "RWX",
			Path:    fmt.Sprintf("0x%x %s", uint64(r.BaseAddress), r.RegionType),
			Size:    int64(r.RegionSize),
			SizeMB:  fmt.Sprintf("%.2f", float64(r.RegionSize)/1024/1024),
			Details: r.Protection,
		})
	}
	for _, p := range prefetch {
		out.Items = append(out.Items, jsonResult{
			Type:     "prefetch",
			Name:     p.Name,
			Path:     p.Path,
			Matched:  p.Matched,
			Modified: p.Modified.Format("2006-01-02 15:04:05"),
		})
	}
	for _, s := range shimcache {
		out.Items = append(out.Items, jsonResult{
			Type:     "shimcache",
			Name:     s.Path,
			Path:     s.Path,
			Matched:  s.Matched,
			Modified: s.Modified.Format("2006-01-02 15:04:05"),
		})
	}
	for _, b := range bam {
		out.Items = append(out.Items, jsonResult{
			Type:     "bam_" + b.Source,
			Name:     b.Path,
			Path:     b.Path,
			Matched:  b.Matched,
			Details:  b.UserSID,
			Modified: b.LastRun.Format("2006-01-02 15:04:05"),
		})
	}
	for _, p := range processes {
		out.Items = append(out.Items, jsonResult{
			Type:    "process",
			Name:    p.Name,
			Path:    p.Path,
			Matched: p.Matched,
			Details: fmt.Sprintf("pid=%d", p.PID),
		})
	}
	for _, d := range drivers {
		out.Items = append(out.Items, jsonResult{
			Type:     "driver_" + d.Kind,
			Name:     d.Name,
			Path:     d.ImagePath,
			Matched:  d.Flag,
			Modified: d.KeyModified.Format("2006-01-02 15:04:05"),
		})
	}
	out.Total = len(out.Items)
	return out
}

// PrintJSON emits all accumulated results as JSON.
func PrintJSON(results []models.FileInfo, dirs []models.DirInfo, named []models.NamedFileInfo, delFiles []models.DeletedFileInfo, delDirs []models.DeletedDirInfo, shellbags []models.ShellbagFinding, appData []models.AppDataFinding, amcache []models.AmcacheFinding, cs2Conns []models.CS2Connection, cs2RWX []models.CS2RWXRegion, hw *models.HardwareInfo, steam *models.SteamInfo, prefetch []models.PrefetchEntry, shimcache []models.ShimcacheEntry, bam []models.BamEntry, processes []models.ProcessEntry, drivers []models.DriverEntry, elapsed time.Duration) {
	out := buildJSONOutput(results, dirs, named, delFiles, delDirs, shellbags, appData, amcache, cs2Conns, cs2RWX, hw, steam, prefetch, shimcache, bam, processes, drivers, elapsed)
	b, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "json marshal error: %v\n", err)
		return
	}
	fmt.Println(string(b))
}

// SaveJSONFile writes scan results as a pretty-printed JSON file.
func SaveJSONFile(results []models.FileInfo, dirs []models.DirInfo, named []models.NamedFileInfo, delFiles []models.DeletedFileInfo, delDirs []models.DeletedDirInfo, shellbags []models.ShellbagFinding, appData []models.AppDataFinding, amcache []models.AmcacheFinding, cs2Conns []models.CS2Connection, cs2RWX []models.CS2RWXRegion, hw *models.HardwareInfo, steam *models.SteamInfo, prefetch []models.PrefetchEntry, shimcache []models.ShimcacheEntry, bam []models.BamEntry, processes []models.ProcessEntry, drivers []models.DriverEntry, elapsed time.Duration, filePath string) error {
	out := buildJSONOutput(results, dirs, named, delFiles, delDirs, shellbags, appData, amcache, cs2Conns, cs2RWX, hw, steam, prefetch, shimcache, bam, processes, drivers, elapsed)
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, b, 0644)
}
