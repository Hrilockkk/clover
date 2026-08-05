package models

import (
	"os"
	"time"

	mmap "github.com/edsrzf/mmap-go"
)

// SearchRule defines a pattern-based search with optional size range.
type SearchRule struct {
	Min       int64
	Max       int64
	Pattern   string
	UTF16     bool
	CheckPath bool
	SHA256    string
	// Compiled caches for performance (ignored in JSON).
	PatternBytes []byte `json:"-"`
	PatternLower string `json:"-"`
	UTF16LE      []byte `json:"-"`
	UTF16BE      []byte `json:"-"`
}

// ADSStream holds a single NTFS Alternate Data Stream.
type ADSStream struct {
	Name string
	Data []byte `json:"-"`
}

// FileInfo is the primary match result.
type FileInfo struct {
	Path         string
	Name         string
	Size         int64
	Attributes   string
	Matched      string
	Modified     time.Time
	Deleted      time.Time
	ADS          []ADSStream
	ADSMatched   string
	ADSHostURL   string
	ADSReferrerURL string
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
	Mode os.FileMode
	Mod  time.Time
}

// MappedFile holds an mmap'd file with its cleanup callback.
type MappedFile struct {
	Candidate      FileCandidate
	Data           mmap.MMap
	ADS            []ADSStream
	ADSMatched     string
	ADSHostURL     string
	ADSReferrerURL string
	Close          func()
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
	ADS            []ADSStream
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
	Name       string
	Path       string
	LastRun    time.Time
	FileID     string
	ProgramID  string
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
	CapacityMB  uint64
	Speed       uint32
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
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	OSVersion    string `json:"osVersion"`
	MachineGuid  string `json:"machineGuid"`

	CPUName      string `json:"cpuName"`
	CPUID        string `json:"cpuId"`

	BoardVendor  string `json:"boardVendor"`
	BoardProduct string `json:"boardProduct"`
	BoardSerial  string `json:"boardSerial"`

	GPUName      string `json:"gpuName"`
	GPUUID       string `json:"gpuUid"`

	RAM          []RAMModule       `json:"ram"`
	Disks        []DiskHardwareInfo `json:"disks"`

	SystemSerial string `json:"systemSerial"`
	BIOSVersion  string `json:"biosVersion"`

	USB []USBDevice `json:"usb,omitempty"`

	HWID string `json:"hwid"`
}

// SteamAccount holds a single Steam account found in loginusers.vdf.
type SteamAccount struct {
	SteamID    string `json:"steamId"`
	AccountName string `json:"accountName"`
	MostRecent bool   `json:"mostRecent"`
	Timestamp  string `json:"timestamp"`
}

// SteamInfo holds Steam installation and account information.
type SteamInfo struct {
	SteamPath    string        `json:"steamPath"`
	Accounts     []SteamAccount `json:"accounts"`
	LibraryPaths []string      `json:"libraryPaths"`
}
