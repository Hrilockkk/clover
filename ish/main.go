//go:build windows
// +build windows

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"scanner/internal/anti"
	"scanner/internal/config"
	"scanner/internal/embedded"
	"scanner/internal/logger"
	"scanner/internal/models"
	"scanner/internal/obfuscate"
	"scanner/internal/output"
	"scanner/internal/scan"
	"scanner/internal/selfdestruct"
	"scanner/internal/ui"
	"scanner/internal/winapi"
)

func main() {
	anti.RunHardening()

	if exe, err := os.Executable(); err == nil {
		if real, realErr := filepath.EvalSymlinks(exe); realErr == nil {
			exe = real
		}
		_ = anti.StripZoneIdentifier(exe)
	}

	runCLI()
}

func runCLI() {
	jsonFlag := flag.Bool("json", false, "Output results as JSON")
	noPauseFlag := flag.Bool("no-pause", false, "Skip 'Press ENTER to exit'")
	configPath := flag.String("config", obfuscate.CONFIG_FILE(), "Путь к файлу конфигурации JSON (config.clover)")
	uploadURL := flag.String("upload-url", "", "Server URL to upload scan results (e.g. http://server:8080)")
	scanID := flag.String("scan-id", "", "Scan link ID from the server")
	flag.Parse()

	// Read embedded config (appended by server per-link). When present, the
	// scanner runs in auto-mode: no menu, no pause, uploads automatically,
	// and self-destructs after the scan completes.
	emb := embedded.ReadConfig()
	autoMode := false
	if emb != nil {
		autoMode = true
		if *uploadURL == "" {
			*uploadURL = emb.UploadURL
		}
		if *scanID == "" {
			*scanID = emb.ScanID
		}
		*jsonFlag = true
		*noPauseFlag = true
		logger.Info("embedded config loaded", "tag", obfuscate.CLOVER_TAG(), "summary", emb.Summary())
	}

	winapi.EnableConsoleVT()
	output.PrintBanner()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	drives := winapi.GetDrives()
	start := time.Now()

	var cfg *config.Cfg
	if _, err := os.Stat(*configPath); err == nil {
		cfg, err = config.Load(*configPath)
		if err != nil {
			logger.Error("config error", "error", err)
			os.Exit(1)
		}
	} else {
		cfg = config.Get()
	}

	var selfExePath, selfExeName string
	if exe, err := os.Executable(); err == nil {
		if real, realErr := filepath.EvalSymlinks(exe); realErr == nil {
			exe = real
		}
		selfExePath = strings.ToLower(exe)
		selfExeName = filepath.Base(exe)
	}

	engine := scan.New(cfg, selfExePath, selfExeName)

	pathChan := make(chan models.FileCandidate, 10000)
	mappedChan := make(chan models.MappedFile, runtime.NumCPU()*4)

	progress := output.NewProgress(engine)
	progress.Start(ctx)

	go func() {
		engine.Walker(ctx, drives, pathChan)
	}()
	go engine.Reader(ctx, pathChan, mappedChan)

	engine.Matcher(ctx, mappedChan)
	progress.Stop()

	// Auxiliary scans (shellbags + AppData roaming + Amcache + CS2 runtime + HWID + Steam) after main pipeline.
	engine.ScanShellbags()
	engine.ScanAppDataRoaming()
	engine.ScanAmcache()
	engine.ScanCS2()
	engine.ScanHardware()
	engine.ScanSteam()

	results, dirResults, namedFiles, deletedFiles, deletedDirs, shellbags, appData, amcache, cs2Conns, cs2RWX, hw, steam := engine.Results()
	results = dedup(results)
	dirResults = dedupDirs(dirResults)
	namedFiles = dedupNamed(namedFiles)
	deletedFiles = dedupDeleted(deletedFiles)
	deletedDirs = dedupDeletedDirs(deletedDirs)
	elapsed := time.Since(start)

	if *jsonFlag {
		output.PrintJSON(results, dirResults, namedFiles, deletedFiles, deletedDirs, shellbags, appData, amcache, cs2Conns, cs2RWX, hw, steam, elapsed)
	} else {
		output.PrintConsole(results, dirResults, namedFiles, deletedFiles, deletedDirs, shellbags, appData, amcache, cs2Conns, cs2RWX, hw, steam, elapsed)
	}

	// Upload to server if configured
	if *uploadURL != "" {
		uploadScan(*uploadURL, *scanID, results, dirResults, namedFiles, deletedFiles, deletedDirs, shellbags, appData, amcache, cs2Conns, cs2RWX, hw, steam, elapsed)
	}

	// Auto-mode: self-destruct immediately after scan + upload, no menu.
	if autoMode {
		logger.Info(obfuscate.SELF_DESTRUCT_MSG(), "tag", obfuscate.CLOVER_TAG())
		if err := selfdestruct.DeleteExecutable(selfExePath); err != nil {
			logger.Error("self-destruct failed", "tag", obfuscate.CLOVER_TAG(), "error", err)
		}
		return
	}

	if *jsonFlag {
		if !*noPauseFlag {
			output.WaitForExit()
		}
		return
	}

	// Interactive menu for saving / self-destruct (standalone mode only).
	choice := ui.ShowMenu()
	var saveErr error
	switch choice {
	case 1:
		jsonPath := fmt.Sprintf("%s%s%s", obfuscate.JSON_PREFIX(), time.Now().Format("20060102_150405"), obfuscate.JSON_SUFFIX())
		if err := output.SaveJSONFile(results, dirResults, namedFiles, deletedFiles, deletedDirs, shellbags, appData, amcache, cs2Conns, cs2RWX, hw, steam, elapsed, jsonPath); err != nil {
			saveErr = err
		} else {
			fmt.Printf("JSON saved: %s\n", jsonPath)
		}
		if err := selfdestruct.DeleteExecutable(selfExePath); err != nil {
			fmt.Fprintf(os.Stderr, "self-destruct failed: %v\n", err)
		} else {
			fmt.Println("Self-destruct scheduled.")
		}
	case 2:
		if err := output.SaveConsoleResults(results, dirResults, namedFiles, deletedFiles, deletedDirs, shellbags, appData, amcache, cs2Conns, cs2RWX, hw, steam, elapsed, ""); err != nil {
			saveErr = err
		} else {
			fmt.Println("Console results saved.")
		}
	}
	if saveErr != nil {
		logger.Error("save error", "error", saveErr)
	}

	if !*noPauseFlag {
		output.WaitForExit()
	}
}

func dedup(slice []models.FileInfo) []models.FileInfo {
	seen := make(map[string]bool)
	unique := make([]models.FileInfo, 0, len(slice))
	for _, f := range slice {
		if !seen[f.Path] {
			seen[f.Path] = true
			unique = append(unique, f)
		}
	}
	return unique
}

func dedupDirs(slice []models.DirInfo) []models.DirInfo {
	seen := make(map[string]bool)
	unique := make([]models.DirInfo, 0, len(slice))
	for _, d := range slice {
		key := strings.ToLower(d.Path)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, d)
		}
	}
	return unique
}

func dedupNamed(slice []models.NamedFileInfo) []models.NamedFileInfo {
	seen := make(map[string]bool)
	unique := make([]models.NamedFileInfo, 0, len(slice))
	for _, f := range slice {
		key := strings.ToLower(f.Path)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}
	return unique
}

func dedupDeleted(slice []models.DeletedFileInfo) []models.DeletedFileInfo {
	seen := make(map[string]bool)
	unique := make([]models.DeletedFileInfo, 0, len(slice))
	for _, f := range slice {
		key := strings.ToLower(f.Path)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, f)
		}
	}
	return unique
}

func dedupDeletedDirs(slice []models.DeletedDirInfo) []models.DeletedDirInfo {
	seen := make(map[string]bool)
	unique := make([]models.DeletedDirInfo, 0, len(slice))
	for _, d := range slice {
		key := strings.ToLower(d.Path)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, d)
		}
	}
	return unique
}

// uploadScan sends all scan results to the server as JSON.
func uploadScan(baseURL, id string,
	results []models.FileInfo, dirs []models.DirInfo, named []models.NamedFileInfo,
	delFiles []models.DeletedFileInfo, delDirs []models.DeletedDirInfo,
	shellbags []models.ShellbagFinding, appData []models.AppDataFinding, amcache []models.AmcacheFinding,
	cs2Conns []models.CS2Connection, cs2RWX []models.CS2RWXRegion,
	hw *models.HardwareInfo, steam *models.SteamInfo, elapsed time.Duration) {

	payload := struct {
		ScanID      string                  `json:"scanId"`
		Timestamp   int64                   `json:"timestamp"`
		Hardware    *models.HardwareInfo    `json:"hardware"`
		Steam       *models.SteamInfo       `json:"steam"`
		Results     []models.FileInfo       `json:"results"`
		Dirs        []models.DirInfo        `json:"dirs"`
		NamedFiles  []models.NamedFileInfo  `json:"namedFiles"`
		DeletedFiles []models.DeletedFileInfo `json:"deletedFiles"`
		DeletedDirs  []models.DeletedDirInfo  `json:"deletedDirs"`
		Shellbags   []models.ShellbagFinding `json:"shellbags"`
		AppData     []models.AppDataFinding  `json:"appData"`
		Amcache     []models.AmcacheFinding  `json:"amcache"`
		CS2Conns    []models.CS2Connection   `json:"cs2Conns"`
		CS2RWX      []models.CS2RWXRegion    `json:"cs2Rwx"`
		Elapsed     float64                  `json:"elapsedSeconds"`
	}{
		ScanID:      id,
		Timestamp:   time.Now().UnixMilli(),
		Hardware:    hw,
		Steam:       steam,
		Results:     results,
		Dirs:        dirs,
		NamedFiles:  named,
		DeletedFiles: delFiles,
		DeletedDirs:  delDirs,
		Shellbags:   shellbags,
		AppData:     appData,
		Amcache:     amcache,
		CS2Conns:    cs2Conns,
		CS2RWX:      cs2RWX,
		Elapsed:     elapsed.Seconds(),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s marshal error: %v\n", obfuscate.UPLOAD_TAG(), err)
		return
	}

	// Encrypt the payload so the scan results cannot be intercepted in transit.
	enc, err := embedded.EncryptPayloadBase64(body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s encrypt error: %v\n", obfuscate.UPLOAD_TAG(), err)
		return
	}
	uploadBody, err := json.Marshal(map[string]string{"encrypted": enc})
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s marshal encrypted error: %v\n", obfuscate.UPLOAD_TAG(), err)
		return
	}

	url := baseURL
	// The embedded config provides the full upload URL. If a bare server URL is
	// passed via the command-line flag, append the public scan-upload path.
	if id != "" && !strings.Contains(url, "/api/scans/upload/") {
		url = strings.TrimSuffix(url, "/") + "/api/scans/upload/" + id
	}

	resp, err := postJSON(url, uploadBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s failed: %v\n", obfuscate.UPLOAD_TAG(), err)
		// Save the encrypted envelope locally so it can be uploaded manually
		// later via the dashboard. The file contains the same JSON body that
		// would have been sent over the network.
		scanId := id
		if scanId == "" {
			scanId = generateScanID()
		}
		if savePath := saveEncryptedUpload(scanId, uploadBody); savePath != "" {
			fmt.Fprintf(os.Stderr, "%s saved encrypted scan to %s — upload manually if needed\n", obfuscate.UPLOAD_TAG(), savePath)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "%s results sent to %s -> %s\n", obfuscate.UPLOAD_TAG(), url, resp)
}

// generateScanID creates a random hex ID for local saves in standalone mode.
func generateScanID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// saveEncryptedUpload writes the encrypted upload envelope to a file next to
// the running executable. Returns the full path or empty string on failure.
func saveEncryptedUpload(scanId string, body []byte) string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	name := fmt.Sprintf("scan_%s.enc", scanId)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, body, 0644); err != nil {
		return ""
	}
	return path
}

func postJSON(url string, body []byte) (string, error) {
	req, err := http.NewRequest(obfuscate.POST(), url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set(obfuscate.CONTENT_TYPE(), obfuscate.APP_JSON())
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody := make([]byte, 512)
	n, _ := resp.Body.Read(respBody)
	return fmt.Sprintf("%d %s", resp.StatusCode, string(respBody[:n])), nil
}
