package config

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"scanner/internal/models"
	"scanner/internal/utils"
)

// DefaultRules are baked-in signatures.
var DefaultRules = []models.SearchRule{
	{Min: 9 * 1024 * 1024, Max: 15 * 1024 * 1024, Pattern: "Gentee Launcher"},
	{Min: 9 * 1024 * 1024, Max: 16 * 1024 * 1024, Pattern: "X PROGRAMM LTD1"},
	{Min: 16 * 1024 * 1024, Max: 24 * 1024 * 1024, Pattern: "7+InZ[^0"},
	{Min: 10 * 1024 * 1024, Max: 24 * 1024 * 1024, Pattern: "t$PfD)t$PL"},
	{Min: 4 * 1024 * 1024, Max: 10 * 1024 * 1024, Pattern: "KDMapper"},
	{Min: 300 * 1024, Max: 3 * 1024 * 1024, Pattern: "DragonBurn"},
	{Min: 2 * 1024 * 1024, Max: 8 * 1024 * 1024, Pattern: "D:/Projects/touchskins"},
	{Min: 43 * 1024 * 1024, Max: 60 * 1024 * 1024, Pattern: "vac_module_ok"},
	{Min: 600 * 1024 * 1024, Max: 700 * 1024 * 1024, Pattern: "SharkHack"},
	{Min: 25 * 1024 * 1024, Max: 31 * 1024 * 1024, SHA256: "a842a8dd5bfa9ea792dbdce210d53ec29e85c9c30115c4046d9b26c73dcdac66"},
	{Min: 10 * 1024 * 1024, Max: 16 * 1024 * 1024, Pattern: "&Lp6U&XM}3ZQ*^[Hp)"},
	{Min: 2 * 1024 * 1024, Max: 8 * 1024 * 1024, Pattern: "j_M6:F"},
	{Min: 100 * 1024, Max: 400 * 1024, Pattern: "swiftsoft", UTF16: true},
	{Min: 20 * 1024 * 1024, Max: 24 * 1024 * 1024, Pattern: "exloader"},
	{Min: 13 * 1024 * 1024, Max: 23 * 1024 * 1024, Pattern: "ZI>vZ@y#O%~"},
	{Min: 200 * 1024, Max: 400 * 1024, Pattern: "com.mvploader", UTF16: true},
	{Min: 3 * 1024 * 1024, Max: 7 * 1024 * 1024, Pattern: "Wzo8f9:GPd_C["},
	{Min: 1 * 1024 * 1024, Max: 4 * 1024 * 1024, Pattern: "lua54.dll not loaded!"},
}

// TargetDirNames are directory names that trigger a match.
var TargetDirNames = []string{
	"XONE",
	"Memesense",
	"com.swiftsoft",
	"Interium",
	"com.mvploader",
	"GPA",
	"DragonBurn",
	"DragonBurn-tmp",
	"en1gma-tech",
	"osiriscs2",
	"fatality",
	"nix",
}

// TargetFileNames are file names that trigger a match.
var TargetFileNames = []string{
	"token.ms",
	"schinese.bin",
	"russian.bin",
	"esp-icons.ttf",
	"message-bus.bin",
	"nl.log",
	"nl_cs2.log",
}

// AmcacheExeNames are executable names searched inside Amcache.hve.
// Edit this slice directly in config.go.
var AmcacheExeNames = []string{
	"exloader.exe",
	"mvploader.exe",
	"catalyst.exe",
	"exloader_installer.exe",

	// example: "badsoft.exe"
}

// DefaultDriverBlacklist is the built-in list of known-abused (BYOVD)
// driver file names; the site can override it via the embedded config.
var DefaultDriverBlacklist = []string{
	"iqvw64e.sys", "iqvw64.sys", "dbutil_2_3.sys", "capcom.sys",
	"rtcore64.sys", "rtcore32.sys", "winring0.sys", "winring0x64.sys",
	"gdrv.sys", "inpoutx64.sys", "inpout32.sys", "ntiolib.sys", "ntiolib_x64.sys",
	"msio64.sys", "msio32.sys", "physmem.sys", "kprocesshacker.sys",
	"mhyprot2.sys", "mhyprot.sys", "kdstinker.sys", "amifldrv64.sys",
	"asio64.sys", "gmer64.sys", "hw.sys", "kguard.sys", "knpcdev.sys",
	"my.sys", "pcdrv64.sys", "pfc64.sys", "rambpf64.sys", "smepcap.sys",
	"speedfan.sys", "tbs.sys", "vmdrv.sys", "wsprvt.sys", "xhunter1.sys",
	"zam64.sys", "zamguard64.sys",
}

// Cfg holds runtime configuration.
type Cfg struct {
	Rules                 []models.SearchRule `json:"rules"`
	TargetDirNames        []string            `json:"targetDirNames"`
	TargetFileNames       []string            `json:"targetFileNames"`
	AmcacheExeNames       []string            `json:"amcacheExeNames"`
	DriverBlacklist       []string            `json:"driverBlacklist"`
	IndexWorkers          int
	ReaderWorkers         int
	EnqueueBatchSize      int
	EnqueuePauseMs        int
	ReaderPauseMs         int
	MaxMmapSize           int64 `json:"maxMmapSize"`
	MaxMFTRecords         int64 `json:"maxMFTRecords"`
	MFTBatchSize          int   `json:"mftBatchSize"`
	MaxDeletedContentSize int64 `json:"maxDeletedContentSize"`
	MaxDeletedSearchSize  int64 `json:"maxDeletedSearchSize"`
	USNWindowHours        int   `json:"usnWindowHours"`
	// USNHistoryMax caps how many newest $UsnJrnl records are kept for the
	// «USN» tab (per drive window and global report size).
	USNHistoryMax int `json:"usnHistoryMax"`
}

var (
	cfgOnce  sync.Once
	cfgValue *Cfg
)

// Get returns the singleton config (loaded once).
func Get() *Cfg {
	cfgOnce.Do(func() {
		cfgValue = newDefault()
	})
	return cfgValue
}

// Load reads configuration from a JSON file or falls back to defaults.
func Load(path string) (*Cfg, error) {
	if path == "" {
		return Get(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := newDefault()
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	compileRules(c.Rules)
	return c, nil
}

func newDefault() *Cfg {
	c := &Cfg{
		Rules:                 append([]models.SearchRule(nil), DefaultRules...),
		TargetDirNames:        append([]string(nil), TargetDirNames...),
		TargetFileNames:       append([]string(nil), TargetFileNames...),
		AmcacheExeNames:       append([]string(nil), AmcacheExeNames...),
		DriverBlacklist:       append([]string(nil), DefaultDriverBlacklist...),
		IndexWorkers:          envInt("SCANNER_INDEX_WORKERS", runtime.NumCPU()*2),
		ReaderWorkers:         envInt("SCANNER_READER_WORKERS", runtime.NumCPU()*2),
		EnqueueBatchSize:      envInt("SCANNER_ENQUEUE_BATCH", 512),
		EnqueuePauseMs:        envInt("SCANNER_ENQUEUE_PAUSE_MS", 0),
		ReaderPauseMs:         envInt("SCANNER_READER_PAUSE_MS", 0),
		MaxMmapSize:           envInt64("SCANNER_MAX_MMAP_SIZE", 128*1024*1024),
		MaxMFTRecords:         envInt64("SCANNER_MAX_MFT_RECORDS", 8_000_000),
		MFTBatchSize:          envInt("SCANNER_MFT_BATCH_SIZE", 4*1024*1024),
		MaxDeletedContentSize: envInt64("SCANNER_MAX_DELETED_CONTENT_SIZE", 64*1024*1024),
		MaxDeletedSearchSize:  envInt64("SCANNER_MAX_DELETED_SEARCH_SIZE", 100*1024*1024),
		USNWindowHours:        envInt("SCANNER_USN_WINDOW_HOURS", 72),
		USNHistoryMax:         envInt("SCANNER_USN_HISTORY_MAX", 20000),
	}
	compileRules(c.Rules)
	return c
}

// ApplyEmbedded overrides the search-related configuration with the values
// embedded by the server (the site's «Сигнатуры» panel). Only non-nil fields
// are applied, so an absent field keeps the current value.
func ApplyEmbedded(c *Cfg, rules []models.SearchRule, dirNames, fileNames, amcacheNames, driverBlacklist []string) {
	if rules != nil {
		c.Rules = rules
		compileRules(c.Rules)
	}
	if dirNames != nil {
		c.TargetDirNames = dirNames
	}
	if fileNames != nil {
		c.TargetFileNames = fileNames
	}
	if amcacheNames != nil {
		c.AmcacheExeNames = amcacheNames
	}
	if driverBlacklist != nil {
		c.DriverBlacklist = driverBlacklist
	}
}

func compileRules(rules []models.SearchRule) {
	for i := range rules {
		if rules[i].Pattern != "" {
			rules[i].PatternBytes = []byte(rules[i].Pattern)
			rules[i].PatternLower = strings.ToLower(rules[i].Pattern)
			rules[i].UTF16LE = utils.ToUTF16LE(rules[i].Pattern)
			rules[i].UTF16BE = utils.ToUTF16BE(rules[i].Pattern)
		}
	}
}

func envInt(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func envInt64(name string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}
