package output

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"scanner/internal/models"
	"scanner/internal/obfuscate"
	"scanner/internal/scan"
)

const (
	ANSIReset       = "\x1b[0m"
	ANSIBoldRed     = "\x1b[1;31m"
	ANSIRed         = "\x1b[31m"
	ANSIGreen       = "\x1b[32m"
	ANSIYellow      = "\x1b[33m"
	ANSIBlue        = "\x1b[34m"
	ANSIMagenta     = "\x1b[35m"
	ANSICyan        = "\x1b[36m"
	ANSIWhite       = "\x1b[37m"
	ANSIBoldGreen   = "\x1b[1;32m"
	ANSIBoldYellow  = "\x1b[1;33m"
	ANSIBoldCyan    = "\x1b[1;36m"
	ANSIBoldWhite   = "\x1b[1;37m"
	ANSIBoldMagenta = "\x1b[1;35m"
	ANSIBoldBlue    = "\x1b[1;34m"
	ANSIGray        = "\x1b[90m"
	ANSIClearScreen = "\x1b[2J\x1b[H"
)

// Kept for backward compatibility within this package
const (
	ansiReset       = ANSIReset
	ansiBoldRed     = ANSIBoldRed
	ansiRed         = ANSIRed
	ansiGreen       = ANSIGreen
	ansiYellow      = ANSIYellow
	ansiBlue        = ANSIBlue
	ansiMagenta     = ANSIMagenta
	ansiCyan        = ANSICyan
	ansiWhite       = ANSIWhite
	ansiBoldGreen   = ANSIBoldGreen
	ansiBoldYellow  = ANSIBoldYellow
	ansiBoldCyan    = ANSIBoldCyan
	ansiBoldWhite   = ANSIBoldWhite
	ansiBoldMagenta = ANSIBoldMagenta
	ansiBoldBlue    = ANSIBoldBlue
	ansiGray        = ANSIGray
	ansiClearScreen = ANSIClearScreen
)

func ClearScreen() {
	fmt.Print(ansiClearScreen)
}

func PrintBanner() {
	ClearScreen()

	gradient := []string{ansiBoldCyan, ansiCyan, ansiBlue, ansiBoldBlue, ansiMagenta, ansiBoldMagenta, ansiRed, ansiBoldRed, ansiYellow, ansiBoldYellow}

	bannerLines := []string{
		"",
		"           ██████",
		"         ██░░░░░░██",
		"       ██░░░░████░░██",
		"      █░░░░██    ██░░█",
		"      █░░░░██    ██░░█",
		"       ██░░░░████░░██",
		"         ██░░░░░░██",
		"           ██████",
		"             ██",
		"           ██████",
		"         ██░░░░░░██",
		"        █░░░░░░░░░░█",
		"        █░░░░░░░░░░█",
		"         ██░░░░░░██",
		"           ██████",
		"",
	}

	for i, line := range bannerLines {
		col := gradient[i%len(gradient)]
		fmt.Print(col)
		fmt.Print(line)
		fmt.Println(ansiReset)
	}

	fmt.Println()
	tagline := "Clover"
	tagColors := []string{ansiBoldCyan, ansiCyan, ansiBlue, ansiBoldBlue, ansiMagenta, ansiBoldMagenta, ansiRed, ansiBoldRed, ansiYellow, ansiBoldYellow, ansiGreen, ansiBoldGreen, ansiCyan, ansiBoldCyan}
	for i, ch := range tagline {
		col := tagColors[i%len(tagColors)]
		fmt.Printf("%s%c%s", col, ch, ansiReset)
	}
	fmt.Println()

	fmt.Print(ansiGray)
	fmt.Print(strings.Repeat("─", 40))
	fmt.Println(ansiReset)

	fmt.Println()
	steps := []string{
		"[ * ] Initializing engine...",
		"[ * ] Loading cheat signatures...",
		"[ * ] Hooking NTFS parser...",
		"[ * ] Ready.",
	}
	for _, s := range steps {
		fmt.Printf("%s%s%s\n", ansiBoldCyan, s, ansiReset)
	}
	fmt.Println()
}

// ─── Live Progress ──────────────────────────────────────────────────────────

// Progress renders a live single-line status bar during scanning.
type Progress struct {
	engine *scan.Engine
	done   chan struct{}
	mu     sync.Mutex
	active bool
	// Quiet mode (player-facing auto runs): instead of the detailed bar with
	// hit/deleted counters, render only "Scanning... N%" to quietOut.
	quiet    bool
	quietOut *os.File
}

// NewProgress creates a progress monitor bound to an engine.
func NewProgress(e *scan.Engine) *Progress {
	return &Progress{engine: e}
}

// SetQuiet switches the progress display to the minimal player-facing
// percentage line written to out (the real console captured before stdout
// was silenced).
func (p *Progress) SetQuiet(out *os.File) {
	p.mu.Lock()
	p.quiet = true
	p.quietOut = out
	p.mu.Unlock()
}

// EnterQuietMode redirects os.Stdout/os.Stderr to the null device so verbose
// collector/engine output never reaches the player's console. It returns the
// original stdout handle, which remains usable for the minimal progress UI.
// All internal prints use fmt.Fprintf(os.Stderr/os.Stdout, ...) evaluated at
// call time, so the reassignment silences every package.
func EnterQuietMode() *os.File {
	real := os.Stdout
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		// Better verbose than broken: keep the original console.
		return real
	}
	os.Stdout = devNull
	os.Stderr = devNull
	return real
}

// Start launches a background ticker that redraws the status line.
func (p *Progress) Start(ctx context.Context) {
	p.mu.Lock()
	if p.active {
		p.mu.Unlock()
		return
	}
	p.active = true
	p.done = make(chan struct{})
	p.mu.Unlock()

	go func() {
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-p.done:
				return
			case <-ticker.C:
				p.draw()
			}
		}
	}()
}

// Stop halts the ticker and leaves the cursor on a fresh line.
func (p *Progress) Stop() {
	p.mu.Lock()
	if !p.active {
		p.mu.Unlock()
		return
	}
	p.active = false
	close(p.done)
	p.mu.Unlock()

	time.Sleep(60 * time.Millisecond) // let ticker goroutine drain
	if p.quiet {
		out := p.quietOut
		if out == nil {
			out = os.Stdout
		}
		fmt.Fprintf(out, "\r%-44s\r%s: 100%%\n", "", obfuscate.MSG_SCANNING())
		return
	}
	p.clear()
	fmt.Fprintln(os.Stdout)
}

func (p *Progress) clear() {
	p.mu.Lock()
	fmt.Fprint(os.Stdout, "\033[2K\r")
	p.mu.Unlock()
}

func (p *Progress) draw() {
	p.mu.Lock()
	if !p.active {
		p.mu.Unlock()
		return
	}
	if p.quiet {
		p.drawQuiet()
		p.mu.Unlock()
		return
	}
	total := p.engine.TotalCandidates()
	processed := p.engine.ProcessedFiles()
	hits := p.engine.HitsCount()
	del := p.engine.DeletedCount()

	pct := 0.0
	if total > 0 {
		pct = float64(processed) * 100.0 / float64(total)
	}

	line := fmt.Sprintf(
		"\033[2K\r%s▸%s %s%5d/%d%s %s%s%s | %sH%s%2d %sD%s%2d | %5.1f%%",
		ansiCyan, ansiReset,
		ansiWhite, processed, total, ansiReset,
		ansiGray, "exe", ansiReset,
		ansiBoldGreen, ansiReset, hits,
		ansiBoldRed, ansiReset, del,
		pct,
	)

	runes := []rune(line)
	if len(runes) > 80 {
		line = string(runes[:80])
	}
	fmt.Fprint(os.Stdout, line)
	p.mu.Unlock()
}

// drawQuiet renders the player-facing minimal line: just a percentage, no
// counters, paths or findings. Call with p.mu held.
func (p *Progress) drawQuiet() {
	out := p.quietOut
	if out == nil {
		out = os.Stdout
	}
	total := p.engine.TotalQueued()
	if total <= 0 {
		total = p.engine.TotalCandidates()
	}
	processed := p.engine.ProcessedFiles()

	var line string
	if total > 0 {
		pct := int(float64(processed) * 100.0 / float64(total))
		if pct > 99 {
			pct = 99 // 100% is printed only when everything is truly done
		}
		line = fmt.Sprintf("%s: %d%%", obfuscate.MSG_SCANNING(), pct)
	} else {
		line = obfuscate.MSG_SCANNING() + "..."
	}
	// Pad to erase remnants of the previous, possibly longer, line.
	fmt.Fprintf(out, "\r%-44s\r%s", "", line)
}

// ─── Compact Results Table ──────────────────────────────────────────────────

type compactRow struct {
	tag     string
	color   string
	name    string
	size    string
	details string
	path    string
}

func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	if n > 3 {
		return string(runes[:n-3]) + "..."
	}
	return string(runes[:n])
}

// PrintConsole renders a compact 80-column table with tags. For the bulk
// collectors (prefetch/shimcache/bam/processes/drivers) only the entries
// that matched a target name (or were flagged) are shown.
func PrintConsole(results []models.FileInfo, dirs []models.DirInfo, named []models.NamedFileInfo, delFiles []models.DeletedFileInfo, delDirs []models.DeletedDirInfo, shellbags []models.ShellbagFinding, appData []models.AppDataFinding, amcache []models.AmcacheFinding, cs2Conns []models.CS2Connection, cs2RWX []models.CS2RWXRegion, hw *models.HardwareInfo, steam *models.SteamInfo, prefetch []models.PrefetchEntry, shimcache []models.ShimcacheEntry, bam []models.BamEntry, processes []models.ProcessEntry, drivers []models.DriverEntry, extra *models.ExtraArtifacts, elapsed time.Duration) {
	fmt.Println()

	// Cleanup evidence (cleaner ini files, artifact-wiping tools in Prefetch,
	// wiped USN journals) is high-signal — surface it at the very top in
	// standalone mode.
	if extra != nil && extra.Cleanup != nil {
		for _, f := range extra.Cleanup.IniOnDisk {
			fmt.Printf("%s[CLEANUP]%s %s on disk: %s\n", ANSIBoldRed, ANSIReset, f.Name, f.Path)
		}
		for _, f := range extra.Cleanup.IniDeleted {
			fmt.Printf("%s[CLEANUP]%s %s DELETED (USN): %s at %s\n", ANSIBoldRed, ANSIReset, f.Name, f.Path, f.Deleted.Format("2006-01-02 15:04:05"))
		}
		for _, t := range extra.Cleanup.PrefetchTools {
			fmt.Printf("%s[CLEANUP]%s %s launched (Prefetch): last run %s (pf created %s)\n", ANSIBoldRed, ANSIReset, t.Name, t.Modified.Format("2006-01-02 15:04:05"), t.Created.Format("2006-01-02 15:04:05"))
		}
		for _, j := range extra.Cleanup.Journals {
			if j.Wiped {
				fmt.Printf("%s[CLEANUP]%s USN journal on %s re-created AFTER boot (boot=%s, journal=%s)\n", ANSIBoldRed, ANSIReset, j.Drive, j.BootTime.Format("15:04:05"), j.CreatedAt.Format("2006-01-02 15:04:05"))
			}
		}
	}
	if extra != nil && len(extra.Services) > 0 {
		stopped := 0
		for _, s := range extra.Services {
			if s.Exists && s.Status != "running" {
				stopped++
				fmt.Printf("%s[SVC]%s %s (%s): %s\n", ANSIBoldYellow, ANSIReset, s.Name, s.DisplayName, s.Status)
			}
		}
		if stopped == 0 {
			fmt.Printf("%s[SVC] all critical services running%s\n", ANSIGreen, ANSIReset)
		}
	}

	// Hardware fingerprint
	if hw != nil {
		fmt.Printf("%s╔══ HWID ═════════════════════════════════════════════════════════╗%s\n", ANSIBoldRed, ANSIReset)
		fmt.Printf("%s║ Hostname:     %-54s%s\n", ANSIBoldRed, hw.Hostname, ANSIReset)
		fmt.Printf("%s║ Username:     %-54s%s\n", ANSIBoldRed, hw.Username, ANSIReset)
		fmt.Printf("%s║ OS:           %-54s%s\n", ANSIBoldRed, hw.OSVersion, ANSIReset)
		fmt.Printf("%s║ MachineGuid:  %-54s%s\n", ANSIBoldRed, hw.MachineGuid, ANSIReset)
		fmt.Printf("%s║ CPU:          %-54s%s\n", ANSIBoldRed, hw.CPUName, ANSIReset)
		fmt.Printf("%s║ CPU ID:       %-54s%s\n", ANSIBoldRed, hw.CPUID, ANSIReset)
		fmt.Printf("%s║ Board:        %-54s%s\n", ANSIBoldRed, fmt.Sprintf("%s %s", hw.BoardVendor, hw.BoardProduct), ANSIReset)
		fmt.Printf("%s║ Board S/N:    %-54s%s\n", ANSIBoldRed, hw.BoardSerial, ANSIReset)
		fmt.Printf("%s║ GPU:          %-54s%s\n", ANSIBoldRed, hw.GPUName, ANSIReset)
		fmt.Printf("%s║ System S/N:   %-54s%s\n", ANSIBoldRed, hw.SystemSerial, ANSIReset)
		for i, d := range hw.Disks {
			fmt.Printf("%s║ Disk %d:        %-54s%s\n", ANSIBoldRed, i, fmt.Sprintf("%s S/N:%s %.0fGB", d.Model, d.SerialNumber, d.SizeGB), ANSIReset)
		}
		fmt.Printf("%s║ HWID:         %-54s%s\n", ANSIBoldRed, hw.HWID, ANSIReset)
		fmt.Printf("%s╚══════════════════════════════════════════════════════════════════╝%s\n", ANSIBoldRed, ANSIReset)
		fmt.Println()
	}

	// Steam accounts
	if steam != nil && len(steam.Accounts) > 0 {
		fmt.Printf("%s╔══ STEAM ACCOUNTS ════════════════════════════════════════════════╗%s\n", ANSIBoldRed, ANSIReset)
		for _, a := range steam.Accounts {
			marker := ""
			if a.MostRecent {
				marker = " *"
			}
			fmt.Printf("%s║ %-66s%s\n", ANSIBoldRed, fmt.Sprintf("%s  %s%s", a.SteamID, a.AccountName, marker), ANSIReset)
		}
		fmt.Printf("%s╚══════════════════════════════════════════════════════════════════╝%s\n", ANSIBoldRed, ANSIReset)
		fmt.Println()
	}

	// Header
	fmt.Printf("%s  #  TAG   NAME                 SIZE     DETAILS%s\n", ansiBoldWhite, ansiReset)
	fmt.Println(ansiGray + strings.Repeat("─", 78) + ansiReset)

	idx := 1
	var rows []compactRow

	// 1. Amcache
	for _, ac := range amcache {
		details := ac.LastRun.Format("2006-01-02")
		if details == "0001-01-01" {
			details = "unknown date"
		}
		rows = append(rows, compactRow{
			tag:     "[AMC]",
			color:   ansiBoldMagenta,
			name:    ac.Name,
			size:    "-",
			details: details,
			path:    ac.Path,
		})
	}
	// 2. Deleted dirs
	for _, d := range delDirs {
		rows = append(rows, compactRow{
			tag:     "[MFT]",
			color:   ansiBoldRed,
			name:    d.Name,
			size:    "-",
			details: d.Deleted.Format("2006-01-02"),
			path:    d.Path,
		})
	}
	// 3. Deleted files
	for _, f := range delFiles {
		rows = append(rows, compactRow{
			tag:     "[MFT]",
			color:   ansiBoldRed,
			name:    f.Name,
			size:    fmt.Sprintf("%.1fMB", float64(f.Size)/1024/1024),
			details: f.Deleted.Format("2006-01-02"),
			path:    f.Path,
		})
	}
	// 4. Target dirs
	for _, d := range dirs {
		rows = append(rows, compactRow{
			tag:     "[DIR]",
			color:   ansiBoldYellow,
			name:    d.Name,
			size:    "-",
			details: d.Modified.Format("2006-01-02"),
			path:    d.Path,
		})
	}
	// 5. Target files
	for _, f := range named {
		rows = append(rows, compactRow{
			tag:     "[FILE]",
			color:   ansiMagenta,
			name:    f.Name,
			size:    fmt.Sprintf("%.1fMB", float64(f.Size)/1024/1024),
			details: f.Modified.Format("2006-01-02"),
			path:    f.Path,
		})
	}
	// 6. Shellbags
	for _, sb := range shellbags {
		details := sb.LastAccess.Format("2006-01-02")
		if details == "0001-01-01" {
			details = "unknown date"
		}
		rows = append(rows, compactRow{
			tag:     "[BAG]",
			color:   ansiBoldCyan,
			name:    sb.Name,
			size:    "-",
			details: details,
			path:    sb.Path,
		})
	}
	// 7. AppData Roaming
	for _, ad := range appData {
		rows = append(rows, compactRow{
			tag:     "[ROAM]",
			color:   ansiBoldBlue,
			name:    ad.FileName,
			size:    "-",
			details: ad.FileModified.Format("2006-01-02"),
			path:    ad.FilePath,
		})
	}
	// 8. Content matches
	for _, f := range results {
		tag := "[SIG]"
		if !f.Deleted.IsZero() {
			tag = "[MFT]"
		}
		color := ansiBoldGreen
		if tag == "[MFT]" {
			color = ansiBoldRed
		}

		size := fmt.Sprintf("%.1fMB", float64(f.Size)/1024/1024)
		details := f.Matched
		rows = append(rows, compactRow{
			tag:     tag,
			color:   color,
			name:    f.Name,
			size:    size,
			details: details,
			path:    f.Path,
		})
	}

	// 9. CS2 remote connections
	for _, c := range cs2Conns {
		rows = append(rows, compactRow{
			tag:     "[CS2]",
			color:   ansiBoldRed,
			name:    "Remote",
			size:    "-",
			details: fmt.Sprintf("%s:%d (%s)", c.RemoteAddress, c.RemotePort, c.State),
			path:    fmt.Sprintf("cs2.exe -> %s:%d", c.RemoteAddress, c.RemotePort),
		})
	}
	// 10. CS2 RWX memory regions
	for _, r := range cs2RWX {
		rows = append(rows, compactRow{
			tag:     "[CS2]",
			color:   ansiBoldRed,
			name:    "RWX",
			size:    fmt.Sprintf("%dKB", uint64(r.RegionSize)/1024),
			details: r.Protection,
			path:    fmt.Sprintf("0x%x %s", uint64(r.BaseAddress), r.RegionType),
		})
	}

	// 11-14. Launch traces (matched only)
	for _, p := range prefetch {
		if p.Matched == "" {
			continue
		}
		rows = append(rows, compactRow{
			tag:     "[PF]",
			color:   ansiBoldYellow,
			name:    p.Name,
			size:    "-",
			details: p.Modified.Format("2006-01-02"),
			path:    p.Path,
		})
	}
	for _, s := range shimcache {
		if s.Matched == "" {
			continue
		}
		rows = append(rows, compactRow{
			tag:     "[SHIM]",
			color:   ansiBoldYellow,
			name:    s.Matched,
			size:    "-",
			details: s.Modified.Format("2006-01-02"),
			path:    s.Path,
		})
	}
	for _, b := range bam {
		if b.Matched == "" {
			continue
		}
		rows = append(rows, compactRow{
			tag:     "[BAM]",
			color:   ansiBoldYellow,
			name:    b.Matched,
			size:    "-",
			details: b.LastRun.Format("2006-01-02"),
			path:    b.Path,
		})
	}
	for _, p := range processes {
		if p.Matched == "" {
			continue
		}
		rows = append(rows, compactRow{
			tag:     "[PROC]",
			color:   ansiBoldRed,
			name:    p.Name,
			size:    "-",
			details: fmt.Sprintf("pid=%d", p.PID),
			path:    p.Path,
		})
	}
	for _, d := range drivers {
		if d.Flag == "" {
			continue
		}
		rows = append(rows, compactRow{
			tag:     "[DRV]",
			color:   ansiBoldRed,
			name:    d.Name,
			size:    "-",
			details: d.Flag,
			path:    d.ImagePath,
		})
	}

	for _, r := range rows {
		name := truncateRunes(r.name, 18)
		details := truncateRunes(r.details, 26)
		fmt.Printf("%s%3d%s %s%-6s%s %-18s %7s  %s%s%s\n",
			ansiGray, idx, ansiReset,
			r.color, r.tag, ansiReset,
			name,
			r.size,
			ansiWhite, details, ansiReset,
		)
		path := truncateRunes("  → "+r.path, 76)
		fmt.Printf("%s%s%s\n", ansiGray, path, ansiReset)
		idx++
	}

	if len(rows) == 0 {
		fmt.Printf("%s  Clean. No matches found.%s\n", ansiGreen, ansiReset)
	}

	fmt.Println(ansiGray + strings.Repeat("─", 78) + ansiReset)
	fmt.Printf("  %sTime: %.1fs  |  Total: %d%s\n\n", ansiWhite, elapsed.Seconds(), len(rows), ansiReset)
}

func WaitForExit() {
	fmt.Println("\n\n=== Press ENTER to exit ===")
	reader := bufio.NewReader(os.Stdin)
	for {
		if _, err := reader.ReadString('\n'); err != nil {
			// Either the user pressed ENTER, or stdin is closed/redirected
			// (no TTY) — exit in both cases instead of spinning forever.
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}
