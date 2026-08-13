package models

import (
	"time"

	mmap "github.com/edsrzf/mmap-go"
)

// SearchRule defines a pattern-based search with optional size range.
type SearchRule struct {
	Min       int64  `json:"min"`
	Max       int64  `json:"max"`
	Pattern   string `json:"pattern,omitempty"`
	UTF16     bool   `json:"utf16,omitempty"`
	CheckPath bool   `json:"checkPath,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	// Compiled caches for performance (ignored in JSON).
	PatternBytes []byte `json:"-"`
	PatternLower string `json:"-"`
	UTF16LE      []byte `json:"-"`
	UTF16BE      []byte `json:"-"`
}

// FileInfo is the primary match result.
type FileInfo struct {
	Path       string
	Name       string
	Size       int64
	Attributes string
	Matched    string
	Modified   time.Time
	Deleted    time.Time
}

// DirInfo describes a matched directory.
type DirInfo struct {
	Path       string
	Name       string
	Original   string
	Attributes string
	Modified   time.Time
}

// NamedFileInfo is a target file found by exact name.
type NamedFileInfo struct {
	Path       string
	Name       string
	Size       int64
	Attributes string
	Modified   time.Time
}

// DeletedFileInfo describes a deleted file recovered via NTFS.
type DeletedFileInfo struct {
	Path    string
	Name    string
	Size    int64
	Deleted time.Time
}

// DeletedDirInfo describes a deleted directory recovered via NTFS.
type DeletedDirInfo struct {
	Path    string
	Name    string
	Deleted time.Time
}

// RecycleInfo stores metadata from a $I recycle-bin file.
type RecycleInfo struct {
	OriginalPath string
	DeletedAt    time.Time
}

// FileCandidate is an executable queued for content scanning.
type FileCandidate struct {
	Path string
	Name string
	Size int64
	Mod  time.Time
}

// MappedFile holds an mmap'd file with its cleanup callback.
type MappedFile struct {
	Candidate FileCandidate
	Data      mmap.MMap
	Close     func()
}

// MFTNode stores a single NTFS MFT entry for path resolution.
type MFTNode struct {
	Name   string
	Parent uint64
	IsDir  bool
}

// MFTParsedRecord is a decoded MFT FILE record.
type MFTParsedRecord struct {
	IsInUse        bool
	IsDir          bool
	Name           string
	Size           int64
	ParentFRN      uint64
	CreationTime   time.Time
	ModifiedTime   time.Time
	ResidentData   []byte
	HasNonResident bool
	Runlist        []byte
	MFTRecordNum   uint64
}

// NTFSBootSector is the parsed BPB from an NTFS volume.
type NTFSBootSector struct {
	BytesPerSector       uint16
	SectorsPerCluster    uint8
	MFTStartLCN          int64
	ClustersPerMFTRecord int8
}

// ShellbagFinding is a directory seen in Explorer shellbags.
type ShellbagFinding struct {
	Path       string
	Name       string    // matched target dir name
	LastAccess time.Time // extracted from shellbag FILETIME if available
}

// AppDataFinding is a suspicious file found under AppData\Roaming.
type AppDataFinding struct {
	DirPath      string
	FilePath     string
	FileName     string
	DirModified  time.Time
	FileModified time.Time
}

// AmcacheFinding is a matching executable found in Amcache.hve.
type AmcacheFinding struct {
	Name      string
	Path      string
	LastRun   time.Time
	FileID    string
	ProgramID string
}

// CS2Connection is an established TCP connection owned by cs2.exe.
type CS2Connection struct {
	LocalAddress  string
	LocalPort     int
	RemoteAddress string
	RemotePort    int
	State         string
}

// CS2RWXRegion describes a committed memory region inside cs2.exe with
// executable+write protection (PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY).
type CS2RWXRegion struct {
	BaseAddress uintptr
	RegionSize  uintptr
	Protection  string
	RegionType  string
}

// RAMModule describes a single physical memory stick.
type RAMModule struct {
	CapacityMB   uint64
	Speed        uint32
	Manufacturer string
}

// USBDevice holds a single USB device seen in the registry history.
type USBDevice struct {
	VID          string    `json:"vid"`
	PID          string    `json:"pid"`
	SerialNumber string    `json:"serialNumber"`
	FriendlyName string    `json:"friendlyName"`
	Manufacturer string    `json:"manufacturer"`
	Class        string    `json:"class"`
	Driver       string    `json:"driver"`
	HardwareID   string    `json:"hardwareId"`
	FirstSeen    time.Time `json:"firstSeen,omitempty"`
	LastSeen     time.Time `json:"lastSeen,omitempty"`
	IsRemovable  bool      `json:"isRemovable"`
}

// DiskHardwareInfo describes a single physical disk.
type DiskHardwareInfo struct {
	Model        string
	SerialNumber string
	SizeGB       float64
}

// HardwareInfo holds all collected hardware identifiers for fingerprinting.
type HardwareInfo struct {
	Hostname    string `json:"hostname"`
	Username    string `json:"username"`
	OSVersion   string `json:"osVersion"`
	MachineGuid string `json:"machineGuid"`

	CPUName string `json:"cpuName"`
	CPUID   string `json:"cpuId"`

	BoardVendor  string `json:"boardVendor"`
	BoardProduct string `json:"boardProduct"`
	BoardSerial  string `json:"boardSerial"`

	GPUName string `json:"gpuName"`
	GPUUID  string `json:"gpuUid"`

	RAM   []RAMModule        `json:"ram"`
	Disks []DiskHardwareInfo `json:"disks"`

	SystemSerial string `json:"systemSerial"`
	BIOSVersion  string `json:"biosVersion"`

	USB []USBDevice `json:"usb,omitempty"`

	HWID string `json:"hwid"`
}

// SteamAccount holds a single Steam account found in loginusers.vdf.
type SteamAccount struct {
	SteamID     string `json:"steamId"`
	AccountName string `json:"accountName"`
	MostRecent  bool   `json:"mostRecent"`
	Timestamp   string `json:"timestamp"`
}

// SteamInfo holds Steam installation and account information.
type SteamInfo struct {
	SteamPath    string         `json:"steamPath"`
	Accounts     []SteamAccount `json:"accounts"`
	LibraryPaths []string       `json:"libraryPaths"`
}

// PrefetchEntry describes one Prefetch .pf file (program launch trace).
// Modified ≈ last launch time of the program.
type PrefetchEntry struct {
	Name     string    `json:"name"` // program name, e.g. "EXLOADER.EXE"
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Created  time.Time `json:"created,omitempty"`
	Modified time.Time `json:"modified,omitempty"`
	Matched  string    `json:"matched,omitempty"`
}

// ShimcacheEntry is one AppCompatCache (ShimCache) record: a program path
// that was seen by the Windows process-creation shim.
type ShimcacheEntry struct {
	Path     string    `json:"path"`
	Modified time.Time `json:"modified,omitempty"`
	Executed bool      `json:"executed,omitempty"`
	Matched  string    `json:"matched,omitempty"`
}

// BamEntry is one BAM/DAM record: per-user program launch with timestamp.
type BamEntry struct {
	Source  string    `json:"source"` // "bam" | "dam"
	UserSID string    `json:"userSid"`
	Path    string    `json:"path"`
	LastRun time.Time `json:"lastRun"`
	Matched string    `json:"matched,omitempty"`
}

// ProcessEntry is one running process from the Toolhelp32 snapshot.
type ProcessEntry struct {
	PID     uint32 `json:"pid"`
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Matched string `json:"matched,omitempty"`
}

// DriverEntry is one installed kernel driver / service from the registry.
type DriverEntry struct {
	Name        string    `json:"name"`
	ImagePath   string    `json:"imagePath"`
	Kind        string    `json:"kind"` // "kernel" | "fs" | "service"
	KeyModified time.Time `json:"keyModified,omitempty"`
	Flag        string    `json:"flag,omitempty"` // "blacklist" | "recent"
}
